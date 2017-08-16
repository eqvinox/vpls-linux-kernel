/*
 *  net/mpls/vpls.c
 *
 *  Copyright (C) 2016 David Lamparter
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/mpls.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/mpls.h>
#include <linux/module.h>
#include <net/dst_metadata.h>
#include <net/ip_tunnels.h>

#include "internal.h"

#define DRV_NAME	"vpls"

#define MIN_MTU 68		/* Min L3 MTU */
#define MAX_MTU 65535		/* Max L3 MTU (arbitrary) */

struct vpls_cw {
	u8 type_flags;
#define VPLS_CWTYPE(cw) ((cw)->type_flags & 0x0f)

	u8 len;
	u16 seqno;
};

struct vpls_wirelist {
	struct rcu_head rcu;
	size_t count;
	unsigned wires[0];
};

struct vpls_priv {
	struct net *encap_net;
	struct vpls_wirelist __rcu *wires;
};

static int vpls_xmit_wire(struct sk_buff *skb, struct net_device *dev,
			  struct vpls_priv *vpls, u32 wire)
{
	struct mpls_route *rt;
	struct mpls_entry_decoded dec;

	dec.bos = 1;
	dec.ttl = 255;

	rt = mpls_route_input_rcu(vpls->encap_net, wire);
	if (!rt)
		return -ENOENT;
	if (rt->rt_vpls_dev != dev)
		return -EINVAL;

	if (rt->rt_vpls_flags & RTA_VPLS_F_CW_TX) {
		struct vpls_cw *cw;
		if (skb_cow(skb, sizeof(*cw)))
			return -ENOMEM;
		cw = skb_push(skb, sizeof(*cw));
		memset(cw, 0, sizeof(*cw));
	}

	return mpls_rt_xmit(skb, rt, dec);
}

static netdev_tx_t vpls_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int err = -EINVAL, ok_count = 0;
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_info *vi;
	struct pcpu_sw_netstats *stats;
	size_t len = skb->len;

	rcu_read_lock();
	vi = skb_vpls_info(skb);

	skb_orphan(skb);
	skb_forward_csum(skb);

	if (vi) {
		err = vpls_xmit_wire(skb, dev, priv, vi->pw_label);
		if (err)
			goto out_err;
	} else {
		struct sk_buff *cloned;
		struct vpls_wirelist *wl;
		size_t i;

		wl = rcu_dereference(priv->wires);
		if (wl->count == 0) {
			dev->stats.tx_carrier_errors++;
			goto out_err;
		}

		for (i = 0; i < wl->count; i++) {
			cloned = skb_clone(skb, GFP_KERNEL);
			if (vpls_xmit_wire(cloned, dev, priv, wl->wires[i]))
				consume_skb(cloned);
			else
				ok_count++;
		}
		if (!ok_count)
			goto out_err;

		consume_skb(skb);
	}

	stats = this_cpu_ptr(dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->tx_packets++;
	stats->tx_bytes += len;
	u64_stats_update_end(&stats->syncp);

	rcu_read_unlock();
	return 0;

out_err:
	dev->stats.tx_errors++;

	consume_skb(skb);
	rcu_read_unlock();
	return err;
}

int vpls_rcv(struct sk_buff *skb, struct net_device *in_dev,
	     struct packet_type *pt, struct mpls_route *rt,
	     struct mpls_shim_hdr *hdr, struct net_device *orig_dev)
{
	struct net_device *dev = rt->rt_vpls_dev;
	struct mpls_entry_decoded dec;
	struct metadata_dst *md_dst;
	struct pcpu_sw_netstats *stats;
	void *next;

	if (!dev)
		goto drop_nodev;

	dec = mpls_entry_decode(hdr);
	if (!dec.bos) {
		dev->stats.rx_frame_errors++;
		goto drop;
	}

	/* bottom label is still in the skb */
	next = skb_pull(skb, sizeof(*hdr));

	if (rt->rt_vpls_flags & RTA_VPLS_F_CW_RX) {
		struct vpls_cw *cw = next;
		if (unlikely(!pskb_may_pull(skb, sizeof(*cw)))) {
			dev->stats.rx_length_errors++;
			goto drop;
		}
		next = skb_pull(skb, sizeof(*cw));

		if (VPLS_CWTYPE(cw) != 0) {
			/* insert MPLS OAM implementation here */
			goto drop_nodev;
		}
	}

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN))) {
		dev->stats.rx_length_errors++;
		goto drop;
	}

	md_dst = vpls_rx_dst();
	if (unlikely(!md_dst)) {
		netdev_err(dev, "failed to allocate dst metadata\n");
		goto drop;
	}
	md_dst->u.vpls_info.pw_label = dec.label;

	skb->dev = dev;

	skb_reset_mac_header(skb);
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_HOST;

	skb_clear_hash(skb);
	skb->vlan_tci = 0;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, !net_eq(dev_net(in_dev), dev_net(dev)));

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);

	skb_dst_drop(skb);
	skb_dst_set(skb, &md_dst->dst);

	stats = this_cpu_ptr(dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);
	return 0;

drop:
	dev->stats.rx_errors++;
drop_nodev:
	kfree_skb(skb);
	return NET_RX_DROP;
}

void vpls_label_update(unsigned label, struct mpls_route *rt_old,
		       struct mpls_route *rt_new)
{
	struct vpls_priv *priv;
	struct vpls_wirelist *wl, *wl_new;
	size_t i;

	ASSERT_RTNL();

	if (rt_old && rt_new && rt_old->rt_vpls_dev == rt_new->rt_vpls_dev)
		return;

	if (rt_old && rt_old->rt_vpls_dev) {
		priv = netdev_priv(rt_old->rt_vpls_dev);
		wl = rcu_dereference(priv->wires);

		for (i = 0; i < wl->count; i++)
			if (wl->wires[i] == label)
				break;

		if (i == wl->count) {
			netdev_err(rt_old->rt_vpls_dev,
				   "can't find pseudowire to remove!\n");
			goto update_new;
		}

		wl_new = kmalloc(sizeof(*wl) +
				 (wl->count - 1) * sizeof(wl->wires[0]),
				 GFP_ATOMIC);
		if (!wl_new) {
			netdev_err(rt_old->rt_vpls_dev,
				   "out of memory for pseudowire delete!\n");
			goto update_new;
		}

		wl_new->count = wl->count - 1;
		memcpy(wl_new->wires, wl->wires, i * sizeof(wl->wires[0]));
		memcpy(wl_new->wires + i, wl->wires + i + 1,
			(wl->count - i - 1) * sizeof(wl->wires[0]));

		rcu_assign_pointer(priv->wires, wl_new);
		kfree_rcu(wl, rcu);

		if (wl_new->count == 0)
			netif_carrier_off(rt_old->rt_vpls_dev);
	}

update_new:
	if (rt_new && rt_new->rt_vpls_dev) {
		priv = netdev_priv(rt_new->rt_vpls_dev);
		wl = rcu_dereference(priv->wires);

		wl_new = kmalloc(sizeof(*wl) +
				 (wl->count + 1) * sizeof(wl->wires[0]),
				 GFP_ATOMIC);
		if (!wl_new) {
			netdev_err(rt_new->rt_vpls_dev,
				   "out of memory for pseudowire add!\n");
			return;
		}
		wl_new->count = wl->count + 1;
		memcpy(wl_new->wires, wl->wires,
			wl->count * sizeof(wl->wires[0]));
		wl_new->wires[wl->count] = label;

		rcu_assign_pointer(priv->wires, wl_new);
		kfree_rcu(wl, rcu);

		if (wl_new->count == 1)
			netif_carrier_on(rt_new->rt_vpls_dev);
	}
}

/* fake multicast ability */
static void vpls_set_multicast_list(struct net_device *dev)
{
}

static int vpls_open(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_wirelist *wl;

	wl = rcu_dereference(priv->wires);
	if (wl->count > 0)
		netif_carrier_on(dev);

	return 0;
}

static int vpls_close(struct net_device *dev)
{
	netif_carrier_off(dev);
	return 0;
}

static int is_valid_vpls_mtu(int new_mtu)
{
	return new_mtu >= MIN_MTU && new_mtu <= MAX_MTU;
}

static int vpls_change_mtu(struct net_device *dev, int new_mtu)
{
	if (!is_valid_vpls_mtu(new_mtu))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static int vpls_dev_init(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	priv->wires = kzalloc(sizeof(struct vpls_wirelist), GFP_KERNEL);
	if (!priv->wires)
		return -ENOMEM;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats) {
		kfree(priv->wires);
		return -ENOMEM;
	}

	return 0;
}

static void vpls_dev_free(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);

	free_percpu(dev->tstats);

	if (priv->wires)
		kfree(priv->wires);

	if (priv->encap_net)
		put_net(priv->encap_net);

	free_netdev(dev);
}

static const struct net_device_ops vpls_netdev_ops = {
	.ndo_init		= vpls_dev_init,
	.ndo_open		= vpls_open,
	.ndo_stop		= vpls_close,
	.ndo_start_xmit		= vpls_xmit,
	.ndo_change_mtu		= vpls_change_mtu,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_set_rx_mode	= vpls_set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_features_check	= passthru_features_check,
};

int is_vpls_dev(struct net_device *dev)
{
	return dev->netdev_ops == &vpls_netdev_ops;
}

#define VPLS_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | \
		       NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_HIGHDMA)

static void vpls_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->netdev_ops = &vpls_netdev_ops;
	dev->features |= NETIF_F_LLTX;
	dev->features |= VPLS_FEATURES;
	dev->vlan_features = dev->features;
	dev->priv_destructor = vpls_dev_free;

	dev->hw_features = VPLS_FEATURES;
	dev->hw_enc_features = VPLS_FEATURES;

	netif_keep_dst(dev);
}

/*
 * netlink interface
 */

static int vpls_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
				    "Invalid Ethernet address length");
			return -EINVAL;
		}
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
				    "Invalid Ethernet address");
			return -EADDRNOTAVAIL;
		}
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_vpls_mtu(nla_get_u32(tb[IFLA_MTU]))) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
				    "Invalid MTU");
			return -EINVAL;
		}
	}
	return 0;
}

static struct rtnl_link_ops vpls_link_ops;

static int vpls_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	int err;
	struct vpls_priv *priv = netdev_priv(dev);

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strlcpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err;
	priv->encap_net = get_net(src_net);

	netif_carrier_off(dev);
	return 0;

err:
	return err;
}

static void vpls_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}


static struct rtnl_link_ops vpls_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct vpls_priv),
	.setup		= vpls_setup,
	.validate	= vpls_validate,
	.newlink	= vpls_newlink,
	.dellink	= vpls_dellink,
};

/*
 * init/fini
 */

__init int vpls_init(void)
{
	int ret;

	ret = rtnl_link_register(&vpls_link_ops);
	if (ret)
		goto out;

	return 0;

out:
	return ret;
}

__exit void vpls_exit(void)
{
	rtnl_link_unregister(&vpls_link_ops);
}

#if 0
/* not currently available as a separate module... */

module_init(vpls_init);
module_exit(vpls_exit);

MODULE_DESCRIPTION("Virtual Private LAN Service");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
#endif
