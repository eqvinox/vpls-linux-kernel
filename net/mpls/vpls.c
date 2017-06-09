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

#include <net/genetlink.h>

#include "internal.h"
#include "vpls.h"

#define DRV_NAME	"vpls"

#define MIN_MTU 68		/* Min L3 MTU */
#define MAX_MTU 65535		/* Max L3 MTU (arbitrary) */

#define MAXWIRES 256

union vpls_nh {
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

struct vpls_dst {
	struct net_device *dev;
	unsigned label_in, label_out;
	union vpls_nh	addr;
	u16 vlan_id;
	u8 via_table;
	u8 flags;
	u8 ttl;
};

struct vpls_dst_list {
	size_t count;
	struct vpls_dst *items;
};

struct vpls_priv {
	struct net *encap_net;
	struct vpls_dst_list *dsts;
};

static int vpls_xmit_dst(struct sk_buff *skb, struct vpls_priv *vpls,
			 struct vpls_dst *dst)
{
	unsigned int hh_len;
	unsigned int new_header_size;
	struct mpls_shim_hdr *hdr;
	struct net_device *out_dev = dst->dev;
	int err;

	if (!mpls_output_possible(dst->dev) || skb_warn_if_lro(skb))
		return -1;

	new_header_size = 1 * sizeof(struct mpls_shim_hdr);

	hh_len = LL_RESERVED_SPACE(out_dev);
	if (!out_dev->header_ops)
		hh_len = 0;

	if (skb_cow(skb, hh_len + new_header_size))
		return -1;

	skb_push(skb, new_header_size);
	skb_reset_network_header(skb);

	skb->dev = out_dev;
	skb->protocol = htons(ETH_P_MPLS_UC);

	hdr = mpls_hdr(skb);
	hdr[0] = mpls_entry_encode(dst->label_out, dst->ttl, 0, true);

	if (dst->flags & VPLS_F_VLAN)
		skb_vlan_push(skb, htons(ETH_P_8021Q), dst->vlan_id);

	err = neigh_xmit(dst->via_table, out_dev, &dst->addr, skb);
	if (err)
		net_dbg_ratelimited("%s: packet transmission failed: %d\n",
				    __func__, err);

	return err;
}

static netdev_tx_t vpls_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int ret = -EINVAL;
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_dst_list *dsts;
	struct sk_buff *cloned;
	size_t i;

	skb_orphan(skb);
	skb_forward_csum(skb);

	rcu_read_lock();

	dsts = rcu_dereference(priv->dsts);
	if (!dsts->count)
		goto drop;

	if (skb->subport_cnt == 1 && skb->subport < dsts->count
		&& dsts->items[skb->subport].dev) {

		i = skb->subport;

		cloned = skb_clone(skb, GFP_KERNEL);
		if (vpls_xmit_dst(cloned, priv, &dsts->items[i]))
			consume_skb(cloned);

	} else {
		for (i = 0; i < dsts->count; i++)
			if (dsts->items[i].dev) {
				cloned = skb_clone(skb, GFP_KERNEL);
				if (vpls_xmit_dst(cloned, priv, &dsts->items[i]))
					consume_skb(cloned);
			}
	}

	ret = 0;
drop:
	rcu_read_unlock();
	consume_skb(skb);
	return ret;
}

static int vpls_rcv(void *arg, struct sk_buff *skb, struct net_device *in_dev,
		     struct packet_type *pt, struct mpls_shim_hdr *hdr,
		     struct net_device *orig_dev)
{
	struct net_device *dev = arg;
	struct vpls_priv *priv = netdev_priv(dev);
	struct mpls_entry_decoded dec;
	struct vpls_dst_list *dsts;
	size_t i;

	dec = mpls_entry_decode(hdr);
	if (!dec.bos) {
		pr_info("%s: incoming BoS mismatch\n", dev->name);
		goto drop;
	}

	rcu_read_lock();
	dsts = rcu_dereference(priv->dsts);
	for (i = 0; i < dsts->count; i++)
		if (dsts->items[i].dev && dec.label == dsts->items[i].label_in)
			break;

	if (i == dsts->count) {
		pr_info("%s: incoming label %u not found\n", dev->name,
			dec.label);
		rcu_read_unlock();
		goto drop;
	}
	rcu_read_unlock();

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
		goto drop;

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

	skb->subport_cnt = 1;
	skb->subport = i;

	netif_rx(skb);
	return 0;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/* fake multicast ability */
static void vpls_set_multicast_list(struct net_device *dev)
{
}

static int vpls_open(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_dst_list *dsts;
	int rc;
	size_t i;

	rcu_read_lock();
	dsts = rcu_dereference(priv->dsts);
	for (i = 0; i < dsts->count; i++)
		if (dsts->items[i].dev) {
			struct vpls_dst *dst = &dsts->items[i];
			rc = mpls_handler_add(priv->encap_net, dst->label_in,
					      vpls_rcv, dev);
		}
	rcu_read_unlock();

	netif_carrier_on(dev);
	return 0;
}

static int vpls_close(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_dst_list *dsts;
	size_t i;

	netif_carrier_off(dev);

	rcu_read_lock();
	dsts = rcu_dereference(priv->dsts);
	for (i = 0; i < dsts->count; i++)
		if (dsts->items[i].dev) {
			struct vpls_dst *dst = &dsts->items[i];
			mpls_handler_del(priv->encap_net, dst->label_in);
		}
	rcu_read_unlock();
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
	priv->dsts = kzalloc(sizeof(struct vpls_dst_list), GFP_KERNEL);

	return 0;
}

static void vpls_dev_free(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_dst_list *dsts;
	size_t i;

	dsts = priv->dsts;
	for (i = 0; i < dsts->count; i++)
		if (dsts->items[i].dev)
			dev_put(dsts->items[i].dev);
	if (priv->dsts->items)
		kfree(priv->dsts->items);
	kfree(priv->dsts);

	if (priv->encap_net)
		put_net(priv->encap_net);

	free_netdev(dev);
}

static const struct net_device_ops vpls_netdev_ops = {
	.ndo_init            = vpls_dev_init,
	.ndo_open            = vpls_open,
	.ndo_stop            = vpls_close,
	.ndo_start_xmit      = vpls_xmit,
	.ndo_change_mtu      = vpls_change_mtu,
	.ndo_set_rx_mode     = vpls_set_multicast_list,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_features_check	= passthru_features_check,
};

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
	dev->destructor = vpls_dev_free;

	dev->hw_features = VPLS_FEATURES;
	dev->hw_enc_features = VPLS_FEATURES;
}

/*
 * netlink interface
 */

static int vpls_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_vpls_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

static struct rtnl_link_ops vpls_link_ops;

static int vpls_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
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
 * GENL wire-control interface
 */

static struct nla_policy vpls_genl_policy[VPLS_ATTR_MAX + 1] = {
	[VPLS_ATTR_IFINDEX]	= { .type = NLA_U32 },
	[VPLS_ATTR_WIREID]	= { .type = NLA_U32 },
	[VPLS_ATTR_LABEL_IN]	= { .type = NLA_U32 },
	[VPLS_ATTR_LABEL_OUT]	= { .type = NLA_U32 },
	[VPLS_ATTR_NH_DEV]	= { .type = NLA_U32 },
	[VPLS_ATTR_NH_IP]	= { .type = NLA_U32 },
	[VPLS_ATTR_NH_IPV6]	= { .len = sizeof(struct in6_addr) },
	[VPLS_ATTR_TTL]		= { .type = NLA_U8  },
	[VPLS_ATTR_VLANID]	= { .type = NLA_U16 },
};

static int vpls_genl_newwire(struct sk_buff *skb, struct genl_info *info);
static int vpls_genl_getwire(struct sk_buff *skb, struct genl_info *info);
static int vpls_genl_dumpwire(struct sk_buff *skb, struct netlink_callback *cb);
static int vpls_genl_delwire(struct sk_buff *skb, struct genl_info *info);

static struct genl_ops vpls_genl_ops[] = {
	{
		.cmd = VPLS_CMD_NEWWIRE,
		.flags = GENL_ADMIN_PERM,
		.policy = vpls_genl_policy,
		.doit = vpls_genl_newwire,
		.dumpit = NULL,
	},
	{
		.cmd = VPLS_CMD_GETWIRE,
		.flags = GENL_ADMIN_PERM,
		.policy = vpls_genl_policy,
		.doit = vpls_genl_getwire,
		.dumpit = vpls_genl_dumpwire,
	},
	{
		.cmd = VPLS_CMD_DELWIRE,
		.flags = GENL_ADMIN_PERM,
		.policy = vpls_genl_policy,
		.doit = vpls_genl_delwire,
		.dumpit = NULL,
	},
};

struct genl_multicast_group vpls_genl_groups[] = {
	{
		.name = "newwire",
	},
};

static struct genl_family vpls_genl_family = {
	.hdrsize = 0,
	.name = "vpls",
	.version = 1,
	.maxattr = VPLS_ATTR_MAX,

	.ops = vpls_genl_ops,
	.n_ops = ARRAY_SIZE(vpls_genl_ops),
	.mcgrps = vpls_genl_groups,
	.n_mcgrps = ARRAY_SIZE(vpls_genl_groups),
};


static int vpls_genl_newwire(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **data = info->attrs;
	struct net *net = sock_net(skb->sk);
	int ret = -EINVAL;
	struct net_device *vplsdev, *outdev;
	struct vpls_priv *priv;
	struct vpls_dst_list *dsts, *newdsts;
	u32 wireid;
	size_t count;
	unsigned remove_lbl = 0;

	if (!data[VPLS_ATTR_WIREID] || !data[VPLS_ATTR_IFINDEX])
		return -EINVAL;
	if (!data[VPLS_ATTR_NH_DEV] || !data[VPLS_ATTR_NH_IP] ||
	    !data[VPLS_ATTR_NH_IP])
		return -EINVAL;
	if (!data[VPLS_ATTR_LABEL_OUT] || !data[VPLS_ATTR_LABEL_IN])
		return -EINVAL;

	wireid = nla_get_u32(data[VPLS_ATTR_WIREID]);
	if (wireid >= MAXWIRES)
		return -EINVAL;

	rtnl_lock();

	vplsdev = __dev_get_by_index(net, nla_get_u32(data[VPLS_ATTR_IFINDEX]));
	if (!vplsdev || vplsdev->netdev_ops != &vpls_netdev_ops)
		goto out_unlock;

	outdev = dev_get_by_index(net, nla_get_u32(data[VPLS_ATTR_NH_DEV]));
	if (!outdev)
		goto out_unlock;

	priv = netdev_priv(vplsdev);
	dsts = priv->dsts;
	count = dsts->count;
	if (wireid < count && dsts->items[wireid].dev) {
		if ((info->nlhdr->nlmsg_flags & (NLM_F_EXCL
				| NLM_F_REPLACE)) != NLM_F_REPLACE) {
			ret = -EEXIST;
			goto out_drop_outdev;
		}
		remove_lbl = dsts->items[wireid].label_in;
	} else {
		if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
			ret = -ENOENT;
			goto out_drop_outdev;
		}
		if (wireid >= count)
			count = wireid + 1;
	}
	newdsts = kzalloc(sizeof(struct vpls_dst_list), GFP_KERNEL);
	if (!newdsts) {
		ret = -ENOMEM;
		goto out_drop_outdev;
	}
	newdsts->count = count;
	newdsts->items = kzalloc(sizeof(newdsts->items[0]) * newdsts->count, GFP_KERNEL);
	memcpy(newdsts->items, dsts->items, sizeof(dsts->items[0]) * dsts->count);

	if (newdsts->items[wireid].dev)
		dev_put(newdsts->items[wireid].dev);
	newdsts->items[wireid].label_in = nla_get_u32(data[VPLS_ATTR_LABEL_IN]);
	newdsts->items[wireid].label_out = nla_get_u32(data[VPLS_ATTR_LABEL_OUT]);
	newdsts->items[wireid].dev = outdev;
	newdsts->items[wireid].ttl = nla_get_u8(data[VPLS_ATTR_TTL]);
	if (data[VPLS_ATTR_NH_IP]) {
		newdsts->items[wireid].addr.sin.sin_addr.s_addr = nla_get_in_addr(data[VPLS_ATTR_NH_IP]);
		newdsts->items[wireid].flags |= VPLS_F_INET;
		newdsts->items[wireid].via_table = NEIGH_ARP_TABLE;
	} else if (data[VPLS_ATTR_NH_IPV6]) {
		if (!IS_ENABLED(CONFIG_IPV6))
			return -EPFNOSUPPORT;
		newdsts->items[wireid].addr.sin6.sin6_addr = nla_get_in6_addr(data[VPLS_ATTR_NH_IPV6]);
		newdsts->items[wireid].flags |= VPLS_F_INET6;
		newdsts->items[wireid].via_table = NEIGH_ND_TABLE;
	}
	if (data[VPLS_ATTR_VLANID]) {
		newdsts->items[wireid].vlan_id = nla_get_u16(data[VPLS_ATTR_VLANID]);
		newdsts->items[wireid].flags |= VPLS_F_VLAN;
	}

	if (remove_lbl && remove_lbl != newdsts->items[wireid].label_in)
		mpls_handler_del(priv->encap_net, remove_lbl);

	if (remove_lbl != newdsts->items[wireid].label_in)
		ret = mpls_handler_add(priv->encap_net,
					newdsts->items[wireid].label_in,
					vpls_rcv, vplsdev);

	rcu_assign_pointer(priv->dsts, newdsts);
	rtnl_unlock();

	synchronize_rcu();

	kfree(dsts->items);
	kfree(dsts);

	return 0;

out_drop_outdev:
	dev_put(outdev);
out_unlock:
	rtnl_unlock();
	return ret;
}

static int vpls_genl_delwire(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **data = info->attrs;
	struct net *net = sock_net(skb->sk);
	int ret = -EINVAL;
	struct net_device *vplsdev;
	struct vpls_priv *priv;
	struct vpls_dst_list *dsts, *newdsts;
	u32 wireid;
	size_t count;

	if (!data[VPLS_ATTR_WIREID] || !data[VPLS_ATTR_IFINDEX])
		return -EINVAL;

	wireid = nla_get_u32(data[VPLS_ATTR_WIREID]);
	if (wireid >= MAXWIRES)
		return -EINVAL;

	rtnl_lock();

	vplsdev = __dev_get_by_index(net, nla_get_u32(data[VPLS_ATTR_IFINDEX]));
	if (!vplsdev || vplsdev->netdev_ops != &vpls_netdev_ops)
		goto out_unlock;
	priv = netdev_priv(vplsdev);

	dsts = priv->dsts;
	count = dsts->count;
	if (wireid >= count || !dsts->items[wireid].dev) {
		ret = -ENOENT;
		goto out_unlock;
	}

	mpls_handler_del(priv->encap_net, dsts->items[wireid].label_in);

	if (wireid + 1 == count)
		for (count--; count && !dsts->items[count - 1].dev; count--)
			;

	newdsts->count = count;
	newdsts->items = kzalloc(sizeof(newdsts->items[0]) * count, GFP_KERNEL);
	memcpy(newdsts->items, dsts->items, sizeof(dsts->items[0]) * count);
	if (wireid < count)
		memset(&newdsts->items[wireid], 0, sizeof(newdsts->items[0]));

	rcu_assign_pointer(priv->dsts, newdsts);
	rtnl_unlock();

	synchronize_rcu();

	kfree(dsts->items);
	kfree(dsts);

	return 0;

out_unlock:
	rtnl_unlock();
	return ret;
}

static int vpls_nl_wire_msg(struct sk_buff *msg, struct net_device *dev,
			    int cmd, unsigned wireid, struct vpls_dst *dst,
			    u32 portid, u32 seq, int flags)
{
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &vpls_genl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(msg, VPLS_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;
	if (nla_put_u32(msg, VPLS_ATTR_WIREID, wireid))
		goto nla_put_failure;
	if (nla_put_u32(msg, VPLS_ATTR_NH_DEV, dst->dev->ifindex))
		goto nla_put_failure;
	if (dst->flags & VPLS_F_INET) {
		if (nla_put_in_addr(msg, VPLS_ATTR_NH_IP,
				    dst->addr.sin.sin_addr.s_addr))
			goto nla_put_failure;
	} else if (dst->flags & VPLS_F_INET6) {
		if (nla_put_in6_addr(msg, VPLS_ATTR_NH_IPV6,
				     &dst->addr.sin6.sin6_addr))
			goto nla_put_failure;
	}
	if (nla_put_u32(msg, VPLS_ATTR_LABEL_IN, dst->label_in))
		goto nla_put_failure;
	if (nla_put_u32(msg, VPLS_ATTR_LABEL_OUT, dst->label_out))
		goto nla_put_failure;
	if (nla_put_u8(msg, VPLS_ATTR_TTL, dst->ttl))
		goto nla_put_failure;
	if (dst->flags & VPLS_F_VLAN)
		if (nla_put_u16(msg, VPLS_ATTR_VLANID, dst->vlan_id))
			goto nla_put_failure;
	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int vpls_genl_getwire(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **data = info->attrs;
	struct net *net = sock_net(skb->sk);
	int ret = -EINVAL;
	struct net_device *vplsdev;
	struct vpls_priv *priv;
	struct vpls_dst_list *dsts;
	u32 wireid;
	struct sk_buff *msg;

	if (!data[VPLS_ATTR_WIREID] || !data[VPLS_ATTR_IFINDEX])
		return -EINVAL;

	wireid = nla_get_u32(data[VPLS_ATTR_WIREID]);
	if (wireid >= MAXWIRES)
		return -EINVAL;

	rtnl_lock();

	vplsdev = __dev_get_by_index(net, nla_get_u32(data[VPLS_ATTR_IFINDEX]));
	if (!vplsdev || vplsdev->netdev_ops != &vpls_netdev_ops)
		goto out_unlock;

	priv = netdev_priv(vplsdev);
	dsts = priv->dsts;

	if (wireid >= dsts->count || !dsts->items[wireid].dev) {
		ret = -ENOENT;
		goto out_unlock;
	} else {
		ret = -ENOMEM;
		msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg)
			goto out_unlock;
		ret = vpls_nl_wire_msg(msg, vplsdev, VPLS_CMD_NEWWIRE, wireid,
			&dsts->items[wireid], info->snd_portid, info->snd_seq,
			0);
		if (ret)
			goto out_unlock;

		ret = genlmsg_reply(msg, info);
	}

	rtnl_unlock();
	return 0;

out_unlock:
	rtnl_unlock();
	return ret;
}

static int vpls_genl_dumpwire(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret;
	struct nlattr *attrs[VPLS_ATTR_MAX+1];
	unsigned ifindex;
	struct net *net = sock_net(skb->sk);
	struct net_device *vplsdev;
	struct vpls_priv *priv;
	struct vpls_dst_list *dsts;
	u32 wireid;

	if (!cb->args[0]) {
		ret = nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs,
				  ARRAY_SIZE(attrs), vpls_genl_policy, NULL);
		if (ret)
			return ret;
		if (!attrs[VPLS_ATTR_IFINDEX])
			return -EINVAL;
		ifindex = cb->args[0] = nla_get_u32(attrs[VPLS_ATTR_IFINDEX]);
	} else {
		ifindex = cb->args[0];
	}

	rtnl_lock();

	ret = -ENODEV;
	vplsdev = __dev_get_by_index(net, ifindex);
	if (!vplsdev || vplsdev->netdev_ops != &vpls_netdev_ops)
		goto out_unlock;

	priv = netdev_priv(vplsdev);
	dsts = priv->dsts;

	wireid = cb->args[1];
	for (wireid = cb->args[1]; wireid < dsts->count; wireid++)
		if (dsts->items[wireid].dev)
			break;
	ret = 0;
	if (wireid == dsts->count)
		goto out_unlock;
	cb->args[1] = wireid + 1;

	ret = vpls_nl_wire_msg(skb, vplsdev, VPLS_CMD_NEWWIRE, wireid,
			       &dsts->items[wireid],
			       NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			       NLM_F_MULTI);
	if (ret == 0)
		ret = skb->len;

out_unlock:
	rtnl_unlock();
	return ret;
}

/*
 * init/fini
 */

static __init int vpls_init(void)
{
	int ret;

	ret = genl_register_family(&vpls_genl_family);
	if (ret)
		return ret;

	ret = rtnl_link_register(&vpls_link_ops);
	if (ret)
		goto out_unreg_family;

	return 0;

out_unreg_family:
	genl_unregister_family(&vpls_genl_family);
	return ret;
}

static __exit void vpls_exit(void)
{
	genl_unregister_family(&vpls_genl_family);
	rtnl_link_unregister(&vpls_link_ops);
}

module_init(vpls_init);
module_exit(vpls_exit);

MODULE_DESCRIPTION("Virtual Private LAN Service");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
