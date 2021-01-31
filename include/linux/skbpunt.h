/* SPDX-License-Identifier: GPL-2.0 */
/*
 * "punting points" for the network stack that userspace can bind to with a
 * packet socket.  This is intended for router/bridge control plane functions
 * where the kernel could have built-in handling, but userspace could implement
 * something different.
 *
 * Some of these functions might be performance sensitive, e.g. storm controls
 * implemented on slow CPU switches;  hence the reuse of AF_PACKET sockets
 * with all their performance optimizations going into them.
 *
 * To create a punting location, pick a sensible 8-character name, for example
 *   "ipv4ttl0" "ipv6ttl0" "mplsttl0" "mpls-gal" "tcmirred"
 * These shold also give you a sense of the "greater idea" here.
 */
#ifndef __LINUX_SKBPUNT_H
#define __LINUX_SKBPUNT_H

#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct module;
struct sk_buff;
struct skbpunt_location;
struct skbpunt_state;

#define SKBPUNT_MAXINFOCUTS	4
#define SKBPUNT_MAXINFOLEN	24

/**
 * skb_punt() - Throw a SKB at a punting location and see if it sticks.
 *
 * @loc: punting location, cf. skbpunt_register()
 * @skb: packet, not consumed in any case (cloned if necessary)
 * @info: additional punting location specific extra data, may be NULL
 * @info_len: length for consistency checking with &struct skbpunt_location
 *	should always match an entry in &skbpunt_location.infolens
 *
 * Returns: nonzero if any receiver "felt responsible" for the SKB and
 *	kernel built-in processing (e.g. ICMP error messages) should be
 *	suppressed since the receiver is generating them.
 */
extern unsigned skb_punt(struct skbpunt_location *loc, struct sk_buff *skb,
			 const u8 *info, size_t info_len);

/**
 * setup for a punting location
 *
 * @node: hash item for lookup by name
 * @owner: holds module (e.g. mpls_router) as long as refs > 0
 * @refs: number of currently attached listeners
 * @name: unique identifier for this location, e.g. "mplsttl0".  Visible to
 *	userspace, use something reasonably descriptive.
 * @infocuts: "less specific" lengths of the extra info, see below. Pad with 0.
 *	Make sure to include the full length and must sort descending.
 * @bind_validate: check whether the extra data makes sense.  May be
 *	NULL if the location has no extra info or any info is valid.
 *	infolens is checked before, so not needed if it's only that.
 * @listeners: lookup by extra info (cut iteratively at infolens steps)
 *
 * these are static variables placed in the core code
 * e.g. mpls_forward() uses struct skbpunt_location mpls_ttl0_punt
 *
 * infolens lists "cut-off" points for the info on skb_punt() to allow some
 * granular steps for userspace to be interested in.  For example, a punting
 * location in tc's mirred action might supply the tc index as extra info, and
 * set infolens to { sizeof(unsigned), 0 }.  skb_punt() will check for
 * listeners on each listed length, so listeners can subscribe to a specific
 * tc index or all tc mirred actions.
 *
 * netdevice is handled separately and should not be included in the info.
 *
 * The info data should go into a UAPI struct.  Size is capped by %MAX_ADDR_LEN
 * to 24 bytes (%SKBPUNT_MAXINFOLEN).
 */
struct skbpunt_location {
	struct hlist_node	node;
	struct list_head	listnode;

	struct module		*owner;
	refcount_t		refs;

	char			name[8];
	u8			infocuts[SKBPUNT_MAXINFOCUTS];

	int (*bind_validate)(const u8 *info, size_t info_len);

	spinlock_t		listeners_lock;
	DECLARE_HASHTABLE(listeners, 6) ____cacheline_aligned_in_smp;
};

/**
 * listener bound to a skb_punt() / &struct skbpunt_location
 *
 * @head: each listener is added to the hash for its info_len but also
 *	the less specific lengths defined by &skbpunt_location.infocuts
 *	Not all heads are necessarily used, a listener with info_len = 0
 *	is only in the hash table once.
 *
 * This struct is a functional/semantic sibling to &struct packet_type.
 */
struct skbpunt_listener {
	struct hlist_node	head[SKBPUNT_MAXINFOCUTS];

	struct net		*net; /* NOT wildcarded! */
	struct net_device	*dev; /* NULL = wildcard */
	__be16			protocol; /* htons(ETH_P_ALL) = wildcard */

	/* return >0 if the packet should be stolen; semantics depend on
	 * the specific skb_punt location
	 */
	unsigned (*func)(struct sk_buff *skb, struct skbpunt_listener *self,
			 struct skbpunt_state *state);

	void			*af_packet_priv;

	size_t			info_len;
	u8			info[SKBPUNT_MAXINFOLEN];

	/* rarely accessed */
	struct skbpunt_location	*loc;
};

/* extra bits to carry around skbpunt_listener->func
 *
 * the af_packet code makes a clone that we can reuse across multiple packet
 * sockets, so let the first listener do that it.
 */
struct skbpunt_state {
	const u8		*info;
	size_t			info_len;

	struct sk_buff		*af_packet_skb;
};

extern int __must_check skbpunt_register(struct skbpunt_location *loc);
extern void skbpunt_unregister(struct skbpunt_location *loc);

extern struct skbpunt_location *skbpunt_get(const char name[8]);
extern void skbpunt_put(struct skbpunt_location *loc);

extern int skbpunt_check_info(struct skbpunt_location *loc,
			      const u8 *info, size_t info_len);

/* set up listener->loc before calling this */
extern void skbpunt_add(struct skbpunt_listener *listener);
extern void skbpunt_remove(struct skbpunt_listener *listener);

#endif
