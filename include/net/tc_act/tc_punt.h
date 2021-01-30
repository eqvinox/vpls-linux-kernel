/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_PUNT_H
#define __NET_TC_PUNT_H

#include <net/act_api.h>
#include <linux/tc_act/tc_punt.h>

struct tcf_punt {
	struct tc_action	common;

	bool			allow_steal;
};
#define to_punt_act(a) ((struct tcf_punt *)a)

#endif
