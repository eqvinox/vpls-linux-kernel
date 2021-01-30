/* SPDX-License-Identifier: GPL-2.0 */

/*
 * minimal core aspects of SKB punting;  the remainder is in net/packet and
 * might be loaded as a module (which will set skb_punt_fn)
 *
 * refer to include/linux/skbpunt.h for details
 */

#include <linux/skbpunt.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/jhash.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>

static u32 punt_id_seed;

static u32 punt_hkey(const u8 *info, size_t info_len, struct net *net)
{
	return jhash(info, info_len, punt_id_seed)
		^ info_len ^ hash32_ptr(net);
}

static unsigned __skb_punt(struct skbpunt_location *loc, struct sk_buff *skb,
			   const u8 *info, size_t info_len)
{
	struct skbpunt_state state = {
		.info = info,
		.info_len = info_len,
	};
	unsigned counter = 0;
	size_t i, len;
	struct skbpunt_listener *lis;
	struct net *net = dev_net(skb->dev);

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
			 "__skb_punt() without RCU held?");

	for (i = 0; i < SKBPUNT_MAXINFOCUTS; i++) {
		len = loc->infocuts[i];
		if (info_len < len)
			continue;

		hash_for_each_possible_rcu(loc->listeners, lis, head[i],
					   punt_hkey(info, len, net)) {
			if (lis->dev && lis->dev != skb->dev)
				continue;
			if (lis->net != net)
				continue;
			if (lis->protocol != htons(ETH_P_ALL) &&
			    lis->protocol != skb->protocol)
				continue;
			if (lis->info_len != len)
				continue;
			if (memcmp(lis->info, info, len))
				continue;

			counter += lis->func(skb, lis, &state);
		}

		if (!len)
			break;
	}

	if (state.af_packet_skb)
		consume_skb(state.af_packet_skb);

	return counter;
}

unsigned skb_punt(struct skbpunt_location *loc, struct sk_buff *skb,
		  const u8 *info, size_t info_len)
{
	unsigned ret;

	rcu_read_lock();
	ret = __skb_punt(loc, skb, info, info_len);
	rcu_read_unlock();
	return ret;

}
EXPORT_SYMBOL_GPL(skb_punt);

void skbpunt_add(struct skbpunt_listener *lis)
{
	struct skbpunt_location *loc;
	size_t i;

	BUG_ON(!lis->func);
	BUG_ON(!lis->net);
	BUG_ON(!lis->loc);
	loc = lis->loc;

	spin_lock(&loc->listeners_lock);
	for (i = 0; i < SKBPUNT_MAXINFOCUTS; i++) {
		if (lis->info_len < loc->infocuts[i])
			continue;

		hash_add_rcu(loc->listeners, &lis->head[i],
			     punt_hkey(lis->info, loc->infocuts[i], lis->net));

		if (!loc->infocuts[i])
			break;
	}
	spin_unlock(&loc->listeners_lock);
}

void skbpunt_remove(struct skbpunt_listener *lis)
{
	struct skbpunt_location *loc;
	size_t i;

	BUG_ON(!lis->loc);
	loc = lis->loc;

	spin_lock(&loc->listeners_lock);
	for (i = 0; i < SKBPUNT_MAXINFOCUTS; i++) {
		if (lis->info_len < loc->infocuts[i])
			continue;

		hash_del_rcu(&lis->head[i]);

		if (!loc->infocuts[i])
			break;
	}
	spin_unlock(&loc->listeners_lock);
}
EXPORT_SYMBOL_GPL(skbpunt_add);
EXPORT_SYMBOL_GPL(skbpunt_remove);

/* the names are only relevant for binding since skb_punt directly takes
 * a pointer to the loc.
 */
static DEFINE_HASHTABLE(locations, 4);
static DEFINE_MUTEX(locations_mutex);

static inline u32 location_hkey(const char name[8])
{
	u64 *namep = (u64 *)name;
	return hash_64_generic(*namep, HASH_BITS(locations));
}

struct skbpunt_location *skbpunt_get(const char name[8])
{
	u32 key = location_hkey(name);
	struct skbpunt_location *iter;

	mutex_lock(&locations_mutex);
	hash_for_each_possible(locations, iter, node, key) {
		if (!memcmp(iter->name, name, 8))
			break;
	}
	if (iter) {
		unsigned rc = refcount_read(&iter->refs);
		if (rc == 0) {
			if (!try_module_get(iter->owner)) {
				iter = NULL;
				goto out;
			}
		}
		refcount_set(&iter->refs, rc + 1);
	}
out:
	mutex_unlock(&locations_mutex);

	return iter;
}

void skbpunt_put(struct skbpunt_location *loc)
{
	if (!loc)
		return;

	mutex_lock(&locations_mutex);
	if (refcount_dec_and_test(&loc->refs))
		module_put(loc->owner);
	mutex_unlock(&locations_mutex);
}

int skbpunt_check_info(struct skbpunt_location *loc,
		       const u8 *info, size_t info_len)
{
	size_t i;

	for (i = 0; i < SKBPUNT_MAXINFOCUTS; i++)
		if (loc->infocuts[i] == info_len)
			break;
	if (i == SKBPUNT_MAXINFOCUTS)
		return -EINVAL;

	if (loc->bind_validate)
		return loc->bind_validate(info, info_len);

	return 0;
}

EXPORT_SYMBOL_GPL(skbpunt_get);
EXPORT_SYMBOL_GPL(skbpunt_put);
EXPORT_SYMBOL_GPL(skbpunt_check_info);

int skbpunt_register(struct skbpunt_location *loc)
{
	u32 key = location_hkey(loc->name);
	struct skbpunt_location *iter;
	int err = 0;
	size_t i, prev_len = SKBPUNT_MAXINFOLEN;

	for (i = 0; i < SKBPUNT_MAXINFOCUTS; i++) {
		if (loc->infocuts[i] > prev_len) {
			pr_err("kernel bug: SKB punt location \"%.*s\" has invalid infocuts\n",
			       (int)sizeof(loc->name), loc->name);
			/* the location just won't work; let's not BUG() out */
			return -EINVAL;
		}
		prev_len = loc->infocuts[i];
	}

	spin_lock_init(&loc->listeners_lock);

	mutex_lock(&locations_mutex);
	refcount_set(&loc->refs, 0);

	hash_for_each_possible(locations, iter, node, key) {
		if (!memcmp(iter->name, loc->name, 8)) {
			err = -EEXIST;
			goto out_unlock;
		}
	}

	hash_add(locations, &loc->node, key);

out_unlock:
	mutex_unlock(&locations_mutex);
	return err;
}

void skbpunt_unregister(struct skbpunt_location *loc)
{
	mutex_lock(&locations_mutex);
	BUG_ON(refcount_read(&loc->refs));
	hash_del(&loc->node);
	mutex_unlock(&locations_mutex);
}

EXPORT_SYMBOL_GPL(skbpunt_register);
EXPORT_SYMBOL_GPL(skbpunt_unregister);

/* must be before other net initcalls, which use fs_initcall() */
static int __init skbpunt_init(void)
{
	get_random_bytes(&punt_id_seed, sizeof(punt_id_seed));
	return 0;
}
subsys_initcall(skbpunt_init);
