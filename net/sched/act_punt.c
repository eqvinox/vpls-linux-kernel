// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/act_punt.c		Throw packet onto skb_punt()
 *
 * Authors:	David Lamparter (2021-02)
 * Derived from act_simple.c by Jamal Hadi Salim (2005-8)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/skbpunt.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#include <linux/tc_act/tc_punt.h>
#include <net/tc_act/tc_punt.h>

static unsigned int act_punt_net_id;
static struct tc_action_ops act_punt_ops;

static struct skbpunt_location tc_punt_loc __read_mostly = {
	.owner = THIS_MODULE,
	.name = "tca_punt",
	.infocuts = { sizeof(struct tcf_punt_info), 0 },
};

static int tcf_punt_act(struct sk_buff *skb, const struct tc_action *a,
			struct tcf_result *res)
{
	struct tcf_punt *d = to_punt_act(a);
	struct tcf_punt_info info;
	unsigned consumers;
	bool allow_steal;

	spin_lock(&d->tcf_lock);
	tcf_lastuse_update(&d->tcf_tm);
	bstats_update(&d->tcf_bstats, skb);

	allow_steal = d->allow_steal;
	info.index = d->common.tcfa_index;
	spin_unlock(&d->tcf_lock);

	consumers = skb_punt(&tc_punt_loc, skb, (u8 *)&info, sizeof(info));
	if (allow_steal && consumers)
		return TC_ACT_STOLEN;

	return d->tcf_action;
}

static void tcf_punt_release(struct tc_action *a)
{
	struct tcf_punt *d = to_punt_act(a);

	/* nothing to do here right now */
	(void)d;
}

static const struct nla_policy punt_policy[TCA_PUNT_MAX + 1] = {
	[TCA_PUNT_PARMS]	= { .len = sizeof(struct tc_punt) },
};

static int tcf_punt_init(struct net *net, struct nlattr *nla,
			 struct nlattr *est, struct tc_action **a,
			 int ovr, int bind, bool rtnl_held,
			 struct tcf_proto *tp, u32 flags,
			 struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, act_punt_net_id);
	struct nlattr *tb[TCA_PUNT_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tc_punt *parm;
	struct tcf_punt *d;
	bool exists = false;
	int ret = 0, err;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "Punt requires attributes to be passed");
		return -EINVAL;
	}

	err = nla_parse_nested_deprecated(tb, TCA_PUNT_MAX, nla, punt_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[TCA_PUNT_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "Missing required punt parameters");
		return -EINVAL;
	}

	parm = nla_data(tb[TCA_PUNT_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;
	exists = err;
	if (exists && bind)
		return 0;

	if (!exists) {
		ret = tcf_idr_create_from_flags(tn, index, est, a,
						&act_punt_ops, bind, flags);
		if (ret) {
			tcf_idr_cleanup(tn, index);
			return ret;
		}
		ret = ACT_P_CREATED;
	} else if (!ovr) {
		tcf_idr_release(*a, bind);
		return -EEXIST;
	}

	d = to_punt_act(*a);

	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto release_idr;

	spin_lock_bh(&d->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	d->tcf_action = parm->action;
	d->allow_steal = parm->allow_steal;
	spin_unlock_bh(&d->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);

	return ret;

release_idr:
	tcf_idr_release(*a, bind);
	return err;
}

static int tcf_punt_dump(struct sk_buff *skb, struct tc_action *a,
			 int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_punt *d = to_punt_act(a);
	struct tc_punt opt = {
		.index       = d->tcf_index,
		.refcnt      = refcount_read(&d->tcf_refcnt) - ref,
		.bindcnt     = atomic_read(&d->tcf_bindcnt) - bind,
		.allow_steal = d->allow_steal,
	};
	struct tcf_t t;

	spin_lock_bh(&d->tcf_lock);
	opt.action = d->tcf_action;
	if (nla_put(skb, TCA_PUNT_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &d->tcf_tm);
	if (nla_put_64bit(skb, TCA_PUNT_TM, sizeof(t), &t, TCA_PUNT_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&d->tcf_lock);

	return skb->len;

nla_put_failure:
	spin_unlock_bh(&d->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_punt_walker(struct net *net, struct sk_buff *skb,
			   struct netlink_callback *cb, int type,
			   const struct tc_action_ops *ops,
			   struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, act_punt_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_punt_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, act_punt_net_id);

	return tcf_idr_search(tn, a, index);
}

static struct tc_action_ops act_punt_ops = {
	.kind		=	"punt",
	.id		=	TCA_ID_PUNT,
	.owner		=	THIS_MODULE,
	.act		=	tcf_punt_act,
	.dump		=	tcf_punt_dump,
	.cleanup	=	tcf_punt_release,
	.init		=	tcf_punt_init,
	.walk		=	tcf_punt_walker,
	.lookup		=	tcf_punt_search,
	.size		=	sizeof(struct tcf_punt),
};

static __net_init int punt_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, act_punt_net_id);

	return tc_action_net_init(net, tn, &act_punt_ops);
}

static void __net_exit punt_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, act_punt_net_id);
}

static struct pernet_operations punt_net_ops = {
	.init = punt_init_net,
	.exit_batch = punt_exit_net,
	.id   = &act_punt_net_id,
	.size = sizeof(struct tc_action_net),
};

MODULE_AUTHOR("David Lamparter");
MODULE_DESCRIPTION("punt action");
MODULE_LICENSE("GPL");

static int __init punt_init_module(void)
{
	int ret;

	ret = skbpunt_register(&tc_punt_loc);
	if (ret)
		goto out;

	ret = tcf_register_action(&act_punt_ops, &punt_net_ops);
	if (ret)
		goto out_unreg;

	pr_info("Punt TC action Loaded\n");
	return 0;

out_unreg:
	skbpunt_unregister(&tc_punt_loc);
out:
	return ret;
}

static void __exit punt_cleanup_module(void)
{
	skbpunt_unregister(&tc_punt_loc);
	tcf_unregister_action(&act_punt_ops, &punt_net_ops);
}

module_init(punt_init_module);
module_exit(punt_cleanup_module);
