/* SCTP kernel reference Implementation
 * (C) Copyright IBM Corp. 2001, 2003
 * Copyright (c) 1999 Cisco
 * Copyright (c) 1999-2001 Motorola
 * Copyright (c) 2001 Nokia, Inc.
 * Copyright (c) 2001 La Monte H.P. Yarroll
 *
 * This file is part of the SCTP kernel reference Implementation
 *
 * These functions populate the sctp protocol structure for sockets.
 *
 * The SCTP reference implementation  is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * the SCTP reference implementation  is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Please send any bug reports or fixes you make to one of the
 * following email addresses:
 *
 * La Monte H.P. Yarroll <piggy@acm.org>
 * Narasimha Budihal <narsi@refcode.org>
 * Karl Knutson <karl@athena.chicago.il.us>
 * Jon "Taz" Mischo <taz@refcode.org>
 * Daisy Chang <daisyc@us.ibm.com>
 * Sridhar Samudrala <samudrala@us.ibm.com>
 * Hui Huang <hui.huang@nokia.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorperated into the next SCTP release.
 */

#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/poll.h>
#include <linux/in6.h>
#include <linux/crypto.h>
#include <net/if_inet6.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
/* undefs were here */
#include <net/protocol.h>
#include <net/sock.h>
#include <net/ip.h>
#ifndef CONFIG_INET_ECN
#define CONFIG_INET_ECN
#endif /* CONFIG_INET_ECN */
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/icmp.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <net/dsfield.h>
#include <net/sctp/sctp.h>
#undef read_lock_bh
#undef read_unlock_bh
#include <net/sctp/sm.h>
#include <funtest.h>
#undef __NFDBITS
#undef __FDMASK
#include <stdio.h>
#include <stdarg.h>
#include <test_kernel.h>

extern int slaughter;
extern int num_slaughter;
extern int congest;
extern void *replacement;
extern int replacement_len;
extern sctp_cid_t scapegoat;
extern int ip_mtu;
extern struct list_head test_timers;

int ft_sctp_lock_bug = 0;
int ft_sctp_lock_assert = 0;
unsigned long volatile jiffies = 0;

cpumask_t cpu_callout_map;

#ifdef CONFIG_SMP
struct cpuinfo_x86 cpu_data[NR_CPUS];
DEFINE_PER_CPU(int, cpu_number);
#endif

/* This array holds the first and last local port number. It is defined
 * by net/ipv4/tcp_ipv4.c in Linux kernel. We define it here for the
 * test frame kernel.
 */
int sysctl_local_port_range[2] = { 1024, 4999 };

/* We define interfaces for the devices, 1 loopback, 3 ethernet. */

/* local addresses */
struct in_ifaddr eth2_ifa = {
        ifa_next: NULL, ifa_dev: NULL,
        ifa_local: 0, ifa_address: 0, ifa_mask: 0,
};
struct in_ifaddr eth1_ifa = {
        ifa_next: NULL, ifa_dev: NULL,
        ifa_local: 0, ifa_address: 0, ifa_mask: 0,
};
struct in_ifaddr eth0_ifa = {
        ifa_next: NULL, ifa_dev: NULL,
        ifa_local: 0, ifa_address: 0, ifa_mask: 0,
};
struct in_ifaddr lo_ifa = {
        ifa_next: NULL, ifa_dev: NULL,
        ifa_local: 0, ifa_address: 0, ifa_mask: 0,
};

/* eth2 IPv6 addresses*/
struct inet6_ifaddr eth2_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr eth2_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth2_inet6_linklocal_ifa,
};

struct inet6_ifaddr eth2_inet6_global_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth2_inet6_sitelocal_ifa,
};

/* eth1 IPv6 addresses*/

struct inet6_ifaddr eth1_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr eth1_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth1_inet6_linklocal_ifa,
};

struct inet6_ifaddr eth1_inet6_global_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth1_inet6_sitelocal_ifa,
};

/* eth0 IPv6 addresses*/
struct inet6_ifaddr eth0_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr eth0_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth0_inet6_linklocal_ifa,
};

struct inet6_ifaddr eth0_inet6_global_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &eth0_inet6_sitelocal_ifa,
};

/* LOOPBACK IPv6 address */
struct inet6_ifaddr lo_inet6_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

/* An ipv6 address for our eth0 peer. */
struct inet6_ifaddr peer_eth0_inet6_global_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr peer_eth0_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &peer_eth0_inet6_global_ifa,
};

struct inet6_ifaddr peer_eth0_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
        prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &peer_eth0_inet6_linklocal_ifa,
};

/* An ipv6 address for a 2nd eth0 peer. */

struct inet6_ifaddr peer2_eth0_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr peer2_eth0_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &peer2_eth0_inet6_linklocal_ifa,
};

/* An ipv6 address for a 3rd eth0 peer. */

struct inet6_ifaddr peer3_eth0_inet6_linklocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: NULL,
};

struct inet6_ifaddr peer3_eth0_inet6_sitelocal_ifa = {
        addr: { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } },
         prefix_len: 0, idev: NULL,
        lst_next: NULL, if_next: &peer3_eth0_inet6_linklocal_ifa,
};

/* These are stubs for setting up the ip_ptr field in the
 * corresponding net_device.
 */
struct in_device eth2_ip_ptr = {
        dev: NULL, refcnt: {0}, dead: 0,
        ifa_list: &eth2_ifa, mc_list: NULL,
};
struct in_device eth1_ip_ptr = {
        dev: NULL, refcnt: {0}, dead: 0,
        ifa_list: &eth1_ifa, mc_list: NULL,
};
struct in_device eth0_ip_ptr = {
        dev: NULL, refcnt: {0}, dead: 0,
        ifa_list: &eth0_ifa, mc_list: NULL,
};
struct in_device lo_ip_ptr = {
        dev: NULL, refcnt: {0}, dead: 0,
        ifa_list: &lo_ifa, mc_list: NULL,
};

struct inet6_dev eth2_ip6_ptr = {
        dev: NULL, addr_list: &eth2_inet6_global_ifa,
        mc_list: NULL, refcnt: {0}, lock: RW_LOCK_UNLOCKED, dead: 0,
        next: NULL,
        };

struct inet6_dev eth1_ip6_ptr = {
        dev: NULL, addr_list: &eth1_inet6_global_ifa,
        mc_list: NULL, refcnt: {0}, lock: RW_LOCK_UNLOCKED, dead: 0,
        next: &eth2_ip6_ptr,
};

struct inet6_dev eth0_ip6_ptr = {
        dev: NULL, addr_list: &eth0_inet6_global_ifa,
        mc_list: NULL, refcnt: {0}, lock: RW_LOCK_UNLOCKED, dead: 0,
        next: &eth1_ip6_ptr,
};

struct inet6_dev lo_ip6_ptr = {
        dev: NULL, addr_list: &lo_inet6_ifa,
        mc_list: NULL, refcnt: {0}, lock: RW_LOCK_UNLOCKED, dead: 0,
        next: &eth0_ip6_ptr,
};

/* These are net_device definitions for the test frame. */
struct net_device eth2_dev =
	{"eth2", {NULL, NULL}, 0, 0, 0, 0, 0, 0, 0, {NULL, NULL}, NULL, 0, NULL, 4};
struct net_device eth1_dev =
	{"eth1", {NULL, NULL}, 0, 0, 0, 0, 0, 0, 0, {NULL, NULL}, NULL, 0, NULL, 3};
struct net_device eth0_dev =
	{"eth0", {NULL, NULL}, 0, 0, 0, 0, 0, 0, 0, {NULL, NULL}, NULL, 0, NULL, 2};
struct net_device loopback_dev =
	{"lo", {NULL, NULL}, 0, 0, 0, 0, 0, 0, 0, {NULL, NULL},  NULL, 0, NULL, 1};
LIST_HEAD(dev_base_head);
rwlock_t inetdev_lock = RW_LOCK_UNLOCKED;
rwlock_t dev_base_lock = RW_LOCK_UNLOCKED;
rwlock_t addrconf_lock = RW_LOCK_UNLOCKED;
struct notifier_block *inetaddr_notifier_on = NULL;

struct rtable *rt_list = NULL;
struct rt6_info *rt6_list = NULL;

int ip_rt_mtu_expires  = 10 * 60 * HZ;

//__u32 sysctl_rmem_default = SK_RMEM_MAX;
/* Some of the tests assume that the rwnd is initialized to 32768 bytes. */
__u32 sysctl_rmem_default = 32768;
__u32 sysctl_wmem_default = 65536;
int sysctl_ip_default_ttl = IPDEFTTL;
int sysctl_ip_nonlocal_bind = 0;

struct icmp_err icmp_err_convert[] = {
	{
		.errno =ENETUNREACH,	/* ICMP_NET_UNREACH */
		.fatal =0,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_HOST_UNREACH */
		.fatal =0,
	},
	{
		.errno =ENOPROTOOPT	/* ICMP_PROT_UNREACH */,
		.fatal =1,
	},
	{
		.errno =ECONNREFUSED,	/* ICMP_PORT_UNREACH */
		.fatal =1,
	},
	{
		.errno =EMSGSIZE,	/* ICMP_FRAG_NEEDED */
		.fatal =0,
	},
	{
		.errno =EOPNOTSUPP,	/* ICMP_SR_FAILED */
		.fatal =0,
	},
	{
		.errno =ENETUNREACH,	/* ICMP_NET_UNKNOWN */
		.fatal =1,
	},
	{
		.errno =EHOSTDOWN,	/* ICMP_HOST_UNKNOWN */
		.fatal =1,
	},
	{
		.errno =ENONET,		/* ICMP_HOST_ISOLATED */
		.fatal =1,
	},
	{
		.errno =ENETUNREACH,	/* ICMP_NET_ANO	*/
		.fatal =1,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_HOST_ANO */
		.fatal =1,
	},
	{
		.errno =ENETUNREACH,	/* ICMP_NET_UNR_TOS */
		.fatal =0,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_HOST_UNR_TOS */
		.fatal =0,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_PKT_FILTERED */
		.fatal =1,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_PREC_VIOLATION */
		.fatal =1,
	},
	{
		.errno =EHOSTUNREACH,	/* ICMP_PREC_CUTOFF */
		.fatal =1,
	},
};

static void ip_rt_update_pmtu(struct dst_entry *, u32);

static struct dst_ops ipv4_dst_ops = {
	.family = AF_INET,
	.protocol = __constant_htons(ETH_P_IP),
	.update_pmtu = ip_rt_update_pmtu,
	.entry_size = sizeof(struct rtable),
};

struct ipv4_config ipv4_config;

const char dst_underflow_bug_msg[] = KERN_DEBUG "BUG: dstunderflow %d: %p at %p\n";

/* These are kernel functions we need to emulate for testing.  */
void *__kmalloc(size_t s, unsigned int flags) { return((void *)malloc(s)); }
void kfree(const void *m)
{
	free((void *)m);
}

void get_random_bytes(void *s, int count)
{
	int i;
	uint8_t *t;

	t = s;

	for (i = 0; i < count; ++i) {
		*t++ = (uint8_t)rand();
	}
} /* get_random_bytes() */

/* Get the current time (GMT).  We use this for all our time stamps.  */
void do_gettimeofday(struct timeval *retval)
{
	struct timezone tz;
	tz.tz_minuteswest = 0;
	tz.tz_dsttime = 0;
	gettimeofday(retval, &tz);
} /* void get_time(struct timeval *retval) */

/* Create an new skb.  */
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask, int fclone,
				int node)
{
	struct sk_buff *skb;
	int sctp_ip_overhead;
	u8 *data;

	/* Get the HEAD */
	skb = t_new(struct sk_buff, GFP_KERNEL);
	if (skb == NULL) {
		goto nohead;
        }
	memset(skb, 0, sizeof(struct sk_buff));

        /* This is a complete hack for the test frame.
	 * Some of the tests would like to use an sctp_chunk as a packet
	 * and consequently require room in the skb for sctp/ip headers.
	 * Rather than carrying this burden in the core code, I'm moving
	 * this to the test frame.
	 */
	sctp_ip_overhead = (sizeof(struct ipv6hdr) + sizeof(struct sctphdr));
	size += sctp_ip_overhead;

	/* Get the DATA. Size must match skb_add_mtu(). */
	size = ((size + 15) & ~15);
	data = kmalloc(size + sizeof(struct skb_shared_info), GFP_KERNEL);
	if (data == NULL) {
		goto nodata;
        }

	/* XXX: does not include slab overhead */
	skb->truesize = size + sizeof(struct sk_buff);

	/* Load the data pointers. */
	skb->head = data;
	skb->data = data;
	skb->tail = data;
	skb->end = data + size;

	/* Set up other state */
	skb->len = 0;
	skb->cloned = 0;
	skb->data_len = 0;

        atomic_set(&skb->users, 1);
        atomic_set(&(skb_shinfo(skb)->dataref), 1);
        skb_shinfo(skb)->nr_frags = 0;
        skb_shinfo(skb)->frag_list = NULL;

	/* Reserve room for headers if running in the test frame.  */
	skb_reserve(skb, sctp_ip_overhead);

	return skb;

nodata:
	kfree(skb);
nohead:
	return NULL;
} /* alloc_skb() */

static void skb_drop_fraglist(struct sk_buff *skb)
{
	struct sk_buff *list = skb_shinfo(skb)->frag_list;

	skb_shinfo(skb)->frag_list = NULL;

	do {
		struct sk_buff *this = list;
		list = list->next;
		kfree_skb(this);
	} while (list);
}

void skb_release_data(struct sk_buff *skb)
{
	if (!skb->cloned ||
	    atomic_dec_and_test(&(skb_shinfo(skb)->dataref))) {

		if (skb_shinfo(skb)->frag_list)
			skb_drop_fraglist(skb);

		kfree(skb->head);
	}
}

/*
 *      Free an skbuff by memory without cleaning the state.
 */
void kfree_skbmem(struct sk_buff *skb)
{
	skb_release_data(skb);
}

/**
 *      kfree_skb - free an sk_buff
 *      @skb: buffer to free
 *
 *      Drop a reference to the buffer and free it if the usage count has
 *      hit zero.
 */
void kfree_skb(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return;
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users)))
		return;
	__kfree_skb(skb);
}

/* Free an skb.  */
void
__kfree_skb(struct sk_buff *skb)
{
        /* The test kernel just plain leaks.  */
        /* TNABTAF */

       /* Continue leaking but at least call the destructor cause I got
	* stuff to do - JAG
	*/

	if (skb->destructor) {
		skb->destructor(skb);
	}

	kfree_skbmem(skb);

} /* __kfree_skb() */

/* Create an skb from a raw packet.  */
struct sk_buff *
make_skb(const void *raw, int datalen)
{
        struct sk_buff *nskb;

        /* Get memory for the skb part.  */
        nskb = t_new(struct sk_buff, GFP_KERNEL);

        /* Get memory for the data part.  */
        nskb->head = kmalloc(datalen + sizeof(struct skb_shared_info), GFP_KERNEL);

        /* Fix up the header pointers.  */
        nskb->end	= nskb->head + datalen;
        nskb->data	= nskb->head;
        nskb->tail	= nskb->head + datalen;
	nskb->len	= datalen;

	skb_reset_network_header(nskb);

        /* Copy the actual packet... */
        memcpy(nskb->head, raw, datalen);

        /* Make sure we are NOT on a list.  */
        nskb->next = NULL;
        nskb->prev = NULL;

        nskb->sk = NULL;

        atomic_set(&nskb->users, 1);
        atomic_set(&(skb_shinfo(nskb)->dataref), 1);
        skb_shinfo(nskb)->nr_frags = 0;
        skb_shinfo(nskb)->frag_list = NULL;

        /* Error checking?  What error checking?  */
        return(nskb);
} /* make_skb() */

static void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	/*
	 *	Shift between the two data areas in bytes
	 */
	unsigned long offset = new->data - old->data;

	new->sk=NULL;
	new->dev=old->dev;
	new->priority=old->priority;
	new->protocol=old->protocol;
	new->dst=dst_clone(old->dst);
	new->transport_header=old->transport_header+offset;
	new->network_header=old->network_header+offset;
	new->mac_header=old->mac_header+offset;
	memcpy(new->cb, old->cb, sizeof(old->cb));
	atomic_set(&new->users, 1);
	new->pkt_type=old->pkt_type;
	new->destructor = NULL;
	new->mark=old->mark;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	new->nfct=old->nfct;
	nf_conntrack_get(new->nfct);
#endif
#ifdef CONFIG_NET_SCHED
	new->tc_index = old->tc_index;
#endif
}

/* Copy an skb.  */
struct sk_buff *
skb_copy(const struct sk_buff *skb, unsigned int priority)
{
        struct sk_buff *nskb;
        int datalen;

        /* Get memory for the skb part.  */
        nskb = t_new(struct sk_buff, priority);

        /* Copy the header stuff.  */
        *nskb = *skb;

        /* Get memory for the data part.  */
        datalen = skb->end - skb->head;
        nskb->head = kmalloc(datalen + sizeof(struct skb_shared_info), priority);

        /* Fix up the header pointers.  */
        nskb->end	= nskb->head + datalen;
        nskb->data	= nskb->head + (skb->data - skb->head);
        nskb->tail	= nskb->head + (skb->tail - skb->head);
	copy_skb_header(nskb, skb);

        /* Copy the actual packet... */
        memcpy(nskb->head, skb->head, datalen + sizeof(struct skb_shared_info));

        /* Make sure we are NOT on a list.  */
        nskb->next = NULL;
        nskb->prev = NULL;

        nskb->sk = NULL;

        /* Error checking?  What error checking?  */
        return(nskb);
} /* skb_copy() */

/**
 *	skb_clone	-	duplicate an sk_buff
 *	@skb: buffer to clone
 *	@gfp_mask: allocation priority
 *
 *	Duplicate an &sk_buff. The new one is not owned by a socket. Both
 *	copies share the same packet data but not structure. The new
 *	buffer has a reference count of 1. If the allocation fails the
 *	function returns %NULL otherwise the new buffer is returned.
 *
 *	If this function is called from an interrupt gfp_mask() must be
 *	%GFP_ATOMIC.
 */

struct sk_buff *skb_clone(struct sk_buff *skb, unsigned int gfp_mask)
{
	struct sk_buff *n;

	n = kmalloc(sizeof(struct sk_buff), gfp_mask);
	if (!n) {
                return NULL;
	}

	memcpy(n, skb, sizeof(*n));
	atomic_inc(&(skb_shinfo(skb)->dataref));
	skb->cloned = 1;

	n->cloned = 1;
	n->next = n->prev = NULL;
	n->sk = NULL;
	atomic_set(&n->users, 1);
	n->destructor = NULL;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_conntrack_get(skb->nfct);
#endif
	return n;
}

/**
 *	skb_copy_expand	-	copy and expand sk_buff
 *	@skb: buffer to copy
 *	@newheadroom: new free bytes at head
 *	@newtailroom: new free bytes at tail
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data and while doing so
 *	allocate additional space.
 *
 *	This is used when the caller wishes to modify the data and needs a
 *	private copy of the data to alter as well as more space for new fields.
 *	Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	You must pass %GFP_ATOMIC as the allocation priority if this function
 *	is called from an interrupt.
 */


struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				int newheadroom,
				int newtailroom,
				unsigned int gfp_mask)
{
	struct sk_buff *n;

	/*
	 *	Allocate the copy buffer
	 */

	n=alloc_skb(newheadroom + (skb->tail - skb->data) + newtailroom,
		    gfp_mask);
	if (n==NULL)
		return NULL;

	skb_reserve(n,newheadroom);

	/* Set the tail pointer and length */
	skb_put(n,skb->len);

	/* Copy the data only. */
	memcpy(n->data, skb->data, skb->len);

	copy_skb_header(n, skb);
	return n;
}


void
skb_over_panic(struct sk_buff *skb, int len, void *here)
{
        debug_halt();
} /* skb_over_panic() */

void
skb_under_panic(struct sk_buff *skb, int len, void *here)
{
        debug_halt();
} /* skb_over_panic() */

void
read_lock_bh(rwlock_t *rw)
{
        /* DO NOTHING.  */
} /* read_lock_bh() */

void
read_unlock_bh(rwlock_t *rw)
{
        /* DO NOTHING.  */
} /* read_unlock_bh() */

void __lockfunc
_read_lock_bh(rwlock_t *rw)
{
        /* DO NOTHING.  */
} /* _read_lock_bh() */

void __lockfunc
_read_unlock_bh(rwlock_t *rw)
{
        /* DO NOTHING.  */
} /* _read_unlock_bh() */

/* Halt the system because it has a bug.  */
void
debug_halt()
{
	printf("\nhalting\n");
	DUMP_CORE;
} /* debug_halt() */

/* Yes, I know this is not quite historically accurate, but
 * Unix ~= Internet.
 */
static int epoch_started = 0;

static struct sk_buff_head Internet[NUM_NETWORKS];
int network_up[NUM_NETWORKS];
int network_mask[NUM_NETWORKS];
static struct net_device *devices[NUM_NETWORKS];
static struct sk_buff_head sidelist;


/* Fetch the Internet for debugging assistance.  */
struct sk_buff_head *
get_Internet(int n)
{
        return(&Internet[n]);
}

/* Is there anything pending for delivery?  */
int
is_empty_Internet()
{
        int i;
        int retval = 1;
        for(i = 0; i < NUM_NETWORKS; ++i) {
                retval = retval && skb_queue_empty(&Internet[i]);
        }
        return(retval);
}

/* Is there anything pending for delivery on a specific network?  */
int
is_empty_network(int i)
{
        return(skb_queue_empty(&Internet[i]));
}

void
init_Internet(void)
{
        int i;

        epoch_started = 1;
        for (i = 0; i < NUM_NETWORKS; ++i) {
                skb_queue_head_init(&Internet[i]);
                network_up[i] = 1;
        }
        skb_queue_head_init(&sidelist);

	/* Initialize multiple devices and the interfaces list.  */
	list_add_tail(&loopback_dev.dev_list, &dev_base_head);
	list_add_tail(&eth0_dev.dev_list, &dev_base_head);
	list_add_tail(&eth1_dev.dev_list, &dev_base_head);
	list_add_tail(&eth2_dev.dev_list, &dev_base_head);

	loopback_dev.ip_ptr = &lo_ip_ptr;
	network_mask[TEST_NETWORK0] = SCTP_IP_LOOPBACK & SCTP_MASK_LO;
	devices[TEST_NETWORK0] = &loopback_dev;

	eth0_dev.ip_ptr = &eth0_ip_ptr;
	eth1_dev.ip_ptr = &eth1_ip_ptr;
	lo_ifa.ifa_local = SCTP_ADDR_LO;
	lo_ifa.ifa_mask = SCTP_MASK_LO;
	eth0_ifa.ifa_local = SCTP_ADDR_ETH0;
	eth0_ifa.ifa_mask = SCTP_MASK_ETH0;
	eth1_ifa.ifa_local = SCTP_ADDR_ETH1;
	eth1_ifa.ifa_mask = SCTP_MASK_ETH1;
	devices[TEST_NETWORK_ETH0] = &eth0_dev;
	devices[TEST_NETWORK_ETH1] = &eth1_dev;
	network_mask[TEST_NETWORK_ETH0] = SCTP_ADDR_ETH0 & SCTP_MASK_LO;
	network_mask[TEST_NETWORK_ETH1] = SCTP_ADDR_ETH1 & SCTP_MASK_LO;

	/* Initialize IPv6 interfaces */
	loopback_dev.ip6_ptr = &lo_ip6_ptr;
        eth0_dev.ip6_ptr = &eth0_ip6_ptr;
        eth1_dev.ip6_ptr = &eth1_ip6_ptr;

        lo_inet6_ifa.addr = (struct in6_addr) SCTP_IN6ADDR_LOOPBACK_INIT;

        eth0_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH0;
        eth0_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH0;
        eth0_inet6_global_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH0;
        eth1_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH1;
        eth1_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH1;
        eth1_inet6_global_ifa.addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH1;

	/* This is just an extra entry to represent an ETH0 non-local global
	 * peer for the testframe.
	 */
	peer_eth0_inet6_global_ifa.addr
		= (struct in6_addr) SCTP_B_ADDR6_GLOBAL_ETH0;

	peer_eth0_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_B_ADDR6_LINKLOCAL_ETH0;

	peer_eth0_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_B_ADDR6_SITELOCAL_ETH0;

	peer2_eth0_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_C_ADDR6_LINKLOCAL_ETH0;

	peer2_eth0_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_C_ADDR6_SITELOCAL_ETH0;

	peer3_eth0_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_D_ADDR6_LINKLOCAL_ETH0;

	peer3_eth0_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_D_ADDR6_SITELOCAL_ETH0;

	/* This device is an extra, not in the initial device list. */
	eth2_dev.ip_ptr = &eth2_ip_ptr;
	eth2_ifa.ifa_local = SCTP_ADDR_ETH2;
	eth2_ifa.ifa_mask = SCTP_MASK_ETH2;
	devices[TEST_NETWORK_ETH2] = &eth2_dev;
	network_mask[TEST_NETWORK_ETH2] = SCTP_ADDR_ETH2 & SCTP_MASK_LO;

	eth2_dev.ip6_ptr = &eth2_ip6_ptr;
	eth2_inet6_linklocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_LINKLOCAL_ETH2;
        eth2_inet6_sitelocal_ifa.addr
		= (struct in6_addr) SCTP_ADDR6_SITELOCAL_ETH2;
        eth2_inet6_global_ifa.addr = (struct in6_addr) SCTP_ADDR6_GLOBAL_ETH2;


} /* init_Internet() */

/* Get the network for a given v4 or v6 address. */
int test_get_network_ip_addr(void *addr, unsigned short family)
{
	int net = TEST_NETWORK0;
	int i;

	switch (family) {
	case AF_INET:
	{
		uint32_t v4addr = *(uint32_t *)addr;
        	for (i = 0; i < NUM_NETWORKS; ++i) {
			if ((v4addr & SCTP_MASK_LO) == network_mask[i]) {
				net = i;
				goto done;
			}
		}
		break;
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	case AF_INET6:
	{
		struct in6_addr *v6addr = (struct in6_addr *)addr;

		if (!ipv6_addr_cmp(v6addr, &lo_inet6_ifa.addr)) {
			net = TEST_NETWORK0;
			goto done;
		}
		if (!ipv6_addr_cmp(v6addr, &eth0_inet6_global_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &eth0_inet6_sitelocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &eth0_inet6_linklocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer_eth0_inet6_global_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer_eth0_inet6_linklocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer_eth0_inet6_sitelocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer2_eth0_inet6_linklocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer2_eth0_inet6_sitelocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer3_eth0_inet6_linklocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &peer3_eth0_inet6_sitelocal_ifa.addr)) {
			net = TEST_NETWORK_ETH0;
			goto done;
		}
		if (!ipv6_addr_cmp(v6addr, &eth1_inet6_global_ifa.addr) ||
	    	    !ipv6_addr_cmp(v6addr, &eth1_inet6_sitelocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &eth1_inet6_linklocal_ifa.addr)) {
			net = TEST_NETWORK_ETH1;
			goto done;
		}

		if (!ipv6_addr_cmp(v6addr, &eth2_inet6_global_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &eth2_inet6_sitelocal_ifa.addr) ||
		    !ipv6_addr_cmp(v6addr, &eth2_inet6_linklocal_ifa.addr)) {
			net = TEST_NETWORK_ETH2;
			goto done;
		}
		break;
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	}

done:
	return net;
}

/* Get the network for a given sctp address. */
int test_get_network_sctp_addr(union sctp_addr *addr)
{
	switch (addr->sa.sa_family) {
	case AF_INET:
		return test_get_network_ip_addr(&addr->v4.sin_addr.s_addr,
						AF_INET);
		break;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	case AF_INET6:
		return test_get_network_ip_addr(&addr->v6.sin6_addr,
						AF_INET6);
		break;
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	default:
		DUMP_CORE;
		return 0;
	}
}

/* Put a packet "on the wire".  */
int
ip_queue_xmit(struct sk_buff *skb, int ipfragok)
{
        struct iphdr *ih;
        int error = 0;
        static struct sk_buff_head *network;
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);

        /* If it is the beginning of time, initialize the Internet.  */
        if (!epoch_started) {
                init_Internet();
        }


        /* Futz with the headers.  */

        /* Build the IP header.  */
        /* The real ip_queue_xmit() gets most of this stuff from the
         * struct sock association with the skb.
         */
        ih = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
        ih->version	= 4;
	ih->ihl 	= 5;
        ih->tos		= inet->tos;
        ih->tot_len	= skb->len;
        ih->id		= 0;
	if (ipfragok)
		ih->frag_off	= 0;
	else
		ih->frag_off	= htons(IP_DF);
	ih->ttl		= 255;
	ih->protocol	= skb->sk->sk_protocol;
	ih->check	= 0x1234; /* CHEAT! */

        /* Route that packet!  */
	/* FIX ME.  We probably want to do "real" routing.
	 */
	if (skb->dst) {
		struct rtable *rt = (struct rtable *)skb->dst;

		ih->daddr = rt->rt_dst;
		ih->saddr = rt->rt_src;
	} else {
        	ih->daddr	= inet->daddr;

 		if (INADDR_ANY == inet->saddr) {
 			ih->saddr = test_get_source_from_route(inet->daddr);
 		} else {
 			ih->saddr       = inet->saddr;
 		}
	}

	/* Find the right link/network to go outbound with.
	 * send the packet through the corresponding link/network.
	 */
	network = &Internet[test_get_network_ip_addr(&ih->daddr, AF_INET)];

        /* "Transmit" it on the Internet.  */
        skb_queue_tail(network, (struct sk_buff *)skb);

        return(error);
} /* ip_queue_xmit() */


#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)

int ip6_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl, struct ipv6_txoptions *opt, int ipfragok)
{
        struct ipv6hdr *ip6h;
        int error = 0;
        static struct sk_buff_head *network;

        /* If it is the beginning of time, initialize the Internet.  */
        if (!epoch_started) {
                init_Internet();
        }

        /* Futz with the headers.  */

        /* Build the IPv6 header.  */
        /* The real ip6_queue_xmit() gets most of this stuff from the
         * struct sock association with the skb.
         */
        ip6h = (struct ipv6hdr *)skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	*(u32 *)ip6h = htonl(0x60000000) | fl->fl6_flowlabel;
        ip6h->payload_len = skb->len - sizeof(struct ipv6hdr);
        ip6h->hop_limit   = 255;
        ip6h->nexthdr    = skb->sk->sk_protocol;
	ip6h->daddr       = inet6_sk(skb->sk)->daddr;

	if (skb->dst) {
		ipv6_addr_copy(&ip6h->daddr, &fl->fl6_dst);
		ipv6_addr_copy(&ip6h->saddr, &fl->fl6_src);
	} else {
		return -EHOSTUNREACH;
	}

        /* Route that packet!  */
	network = &Internet[test_get_network_ip_addr(&ip6h->daddr, AF_INET6)];

        /* "Transmit" it on the Internet.  */
        skb_queue_tail(network, (struct sk_buff *)skb);

        return error;

} /* ip6_xmit() */

int ipv6_get_saddr(struct dst_entry *dst, struct in6_addr *daddr,
		   struct in6_addr *saddr)
{
	return 0;
}


#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

uint8_t
CHUNK_TYPE(struct sk_buff *skb, int has_ip)
{
        struct bare_ipv4_sctp_packet *ipkt4;
        struct bare_ipv6_sctp_packet *ipkt6;
        struct bare_sctp_packet *pkt;

        if (has_ip) {
                ipkt4 = (struct bare_ipv4_sctp_packet *) skb->data;
                ipkt6 = (struct bare_ipv6_sctp_packet *) skb->data;
		switch (ipkt4->iph.version) {
		case 4:
			pkt = &ipkt4->s;
			break;
		case 6:
			pkt = &ipkt6->s;
			break;
		default:
			DUMP_CORE;
		}

        } else {
                pkt = (struct bare_sctp_packet *)(skb->data);
        }

        return (pkt->ch.type);
} /* CHUNK_TYPE() */

static inline int
do_slaughter(struct sk_buff *nskb)
{

	if (slaughter) {
		if (num_slaughter) {
			__kfree_skb(nskb);
			num_slaughter--;
			if (!num_slaughter)
				slaughter = 0;
			return 1;
		}


		if (CHUNK_TYPE(nskb, /* has_ip */ 0) == scapegoat) {
			__kfree_skb(nskb);
			slaughter = 0;
			return 1; /* Skip the rcv. */
		}
	}

	return 0;
} /* do_slaughter() */

static inline int
do_congest(struct sk_buff *nskb)
{
	void*  nh;

	if (!congest)
		return 0;

	nh = skb_network_header(nskb);
	if (CHUNK_TYPE(nskb, /* has_ip */ 0) == scapegoat) {
		congest = 0;

		switch (((struct iphdr*)nh)->version) {
		case 4:
		{
			struct iphdr *iph = nh;

			if (INET_ECN_is_capable(ipv4_get_dsfield(iph)))
				IP_ECN_set_ce(iph);
			else
				/* Not ECN capable so drop the packet, as an
				 * indicator of congestion */
				return 1;
			break;
		}
		case 6:
		{
			struct ipv6hdr *ipv6h = nh;

			if (INET_ECN_is_capable(ipv6_get_dsfield(ipv6h)))
				IP6_ECN_set_ce(ipv6h);
			else
				/* Not ECN capable so drop the packet, as an
				 * indicator of congestion */
				return 1;
			break;
		}
		default:
			DUMP_CORE;
		}
	}

	return 0;  /* Don't drop the packet.  */
} /* do_congest() */

/* Break an skb into fragments of size 'size'. */
static inline int
do_split_skb(struct sk_buff *skb, int size)
{
	struct sk_buff *frag;
	struct sk_buff **next = &skb_shinfo(skb)->frag_list;
	int nfrags, i;
	int len = skb->len;
	int copy;

	nfrags = len/size;

	/* Truncate the data in the original skb to size bytes. */
	skb->tail = skb->data + size;
	skb->data_len = skb->len - size;

	/* Create the remaining fragments and attach to the original skb. */
	for (i = 0; i < nfrags; i++) {
		len = len - size;
		if (len > size)
			copy = size;
		else
			copy = len;
		frag = alloc_skb(copy, 0);
		skb_put(frag, copy);
		memcpy(frag->data, skb->data+((i+1)*size), copy);
		*next = frag;
		next = &frag->next;
	}

	/* Clear the excess bytes in the original skb. */
	memset(skb->tail, 0, skb->data_len);

	return 0;
}

/* Call SCTP v4 error handler with an ICMP message of type:dest. unreachable
 * and code:fragmentation needed.
 */
void icmp_frag_needed(struct sk_buff *skb)
{
	struct sk_buff *iskb;
	struct icmphdr *icmph;
	struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	unsigned int len;

	len = min_t(unsigned int, 576, skb->len);
	/* Update the mtu and expires fields of any dst entry in the routing
	 * table that matches the skb.
	 */
	for (rt = rt_list; rt != NULL; rt = rt->u.dst.rt_next) {
		if ((rt->rt_src == iph->saddr) && (rt->rt_dst == iph->daddr)) {
			rt->u.dst.metrics[RTAX_MTU-1] = ip_mtu;
			dst_set_expires(&rt->u.dst, ip_rt_mtu_expires);
		}
	}

	/* Allocate an skb for icmp packet. */
	iskb = alloc_skb(len, 0);

	/* Fill in the icmp header. */
	icmph = (struct icmphdr *)skb_put(iskb, len);
	memset(icmph, 0, sizeof(struct icmphdr));
	icmph->type = ICMP_DEST_UNREACH;
	icmph->code = ICMP_FRAG_NEEDED;
	icmph->un.frag.mtu = ip_mtu;
	skb_reset_transport_header(iskb);
	skb_pull(iskb, sizeof(struct icmphdr));

	len -= sizeof(struct icmphdr);

	/* Copy 'len' bytes of the original skb starting from the iphdr to
	 * the icmp skb.
	 */
	memcpy(iskb->data, iph, len);

	/* Call SCTP v4 icmp error handler. */
	sctp_v4_err(iskb, ip_mtu);
	return;
}

/* Call SCTP v6 error handler with an ICMP message of type:packet too big
 * and code:0
 */
void icmpv6_frag_needed(struct sk_buff *skb)
{
#if defined(CONFIG_IPV6)
	struct sk_buff *iskb;
	struct icmp6hdr *icmph;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	unsigned int len;
	struct rt6_info *rt;
	
	len = min_t(unsigned int, IPV6_MIN_MTU - sizeof(struct ipv6hdr), 
		    skb->len);
	/* Update the mtu and expires fields of any dst entry in the routing
	 * table that matches the skb.
	 */

	for (rt = rt6_list; rt != NULL; rt = rt->u.dst.rt6_next) {
		if (!ipv6_addr_cmp(&rt->rt6i_dst.addr, &ip6h->daddr)) {
									      
			rt->u.dst.metrics[RTAX_MTU-1] = ip_mtu;
			dst_set_expires(&rt->u.dst, ip_rt_mtu_expires);
			rt->rt6i_flags |= RTF_MODIFIED|RTF_EXPIRES;
		}
	}

	/* Allocate an skb for icmp packet. */
	iskb = alloc_skb(len, 0);

	/* Fill in the icmp header. */
	icmph = (struct icmp6hdr *)skb_put(iskb, len);
	memset(icmph, 0, sizeof(struct icmp6hdr));
	icmph->icmp6_type = ICMPV6_PKT_TOOBIG;
	icmph->icmp6_code = 0;
	icmph->icmp6_pointer = htonl(ip_mtu);
		       
	skb_reset_transport_header(iskb);
	skb_pull(iskb, sizeof(struct icmp6hdr));

	len -= sizeof(struct icmp6hdr);

	/* Copy 'len' bytes of the original skb starting from the iphdr to
	 * the icmp skb.
	 */
	memcpy(iskb->data, ip6h, len);

	/* Call SCTP v4 icmp error handler. */
	sctp_v6_err(iskb, NULL, ICMPV6_PKT_TOOBIG, 0, 0, htonl(ip_mtu));
#endif /* CONFIG_IPV6 */
	return;
}

/* Simulate transport of 1 packet on the specificed network. */
void
simulate_network_once(int net)
{
	struct sk_buff *skb;
	struct sk_buff *nskb;
	struct iphdr *iph = NULL;
	int max_skb_len;

	skb = skb_dequeue(&Internet[net]);
	if (!skb || !network_up[net]) {
		return;
	}

	/* This copy thing is VERY IMPORTANT!
         * Remember that the data portion of skb is still lolly-gagging
	 * about in transport.transmitted...
	 */

	if (replacement && CHUNK_TYPE(skb, /* has_ip */ 1) == scapegoat) {
		nskb = make_skb(replacement, replacement_len);
		replacement = NULL;
		replacement_len = 0;
	} else {
		nskb = skb_copy(skb, GFP_KERNEL);
	}
	nskb->sk = skb->sk;
	__kfree_skb(skb);

	/* Save the network header for later */
	iph = ip_hdr(nskb);

	/* Set the transport header.  */
	skb_pull(nskb, test_hdr_size(nskb->data));
	skb_reset_transport_header(nskb);
	/* Mark the "device" we received on.  */
	nskb->dev = devices[net];

	/* Do we need to blow this away?  */
	if (do_slaughter(nskb)) {
		return;  /* drop packet */
	} else if (do_congest(nskb)) {
		return; /* drop packet */
	}

	/* Check if ip fragmentation is needed.  */
	max_skb_len = ip_mtu - sctp_sk(nskb->sk)->pf->af->net_header_len;
	if (nskb->len > max_skb_len) {
		if (iph->version == 4) {
			/* If ip fragmentation is allowed fragment the skb. */
			if (!(iph->frag_off & htons(IP_DF))) {
				do_split_skb(nskb, max_skb_len);
			} else {
				icmp_frag_needed(nskb);
				return;
			}
		} else {
			icmpv6_frag_needed(nskb);
		}
	}
	
	/* Feed the packet to SCTP.  */
	(void) sctp_rcv(nskb);

} /* simulate_network_once() */

/* Simulate transport on the Internet.  */
void
simulate_internet()
{
        struct sk_buff *skb;
        int i;

        /* If it is the beginning of time, initialize the Internet.  */
        if (!epoch_started) {
                init_Internet();
        }

        for (i = 0; i < NUM_NETWORKS; ++i) {
                while (NULL != (skb = skb_peek(&Internet[i]))) {
			simulate_network_once(i);
                } /* while (there are more packets to receive) */
        } /* for (each network on the Internet) */

} /* simulate_internet() */


int printk(const char *fmt, ...)
{
	int i;
	va_list args;
	va_start(args, fmt);
	i = vprintf(fmt, args);
	va_end(args);
	return i;
} /* printk() */

int
fprintk(int fd, const char *fmt, ...)
{
	int i;
	va_list args;
	va_start(args, fmt);
	i = vfprintf(fdopen(fd, "w"), fmt, args);
	va_end(args);
	return i;

} /* fprintk() */

void
freopenk(char *file, char *mode, int fd)
{
	freopen(file, mode, fdopen(fd, mode));
}

void
sock_wfree(struct sk_buff *skb) {
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_wmem_alloc);
} /* sock_wfree() */

unsigned long
copy_from_user(void *dest, const void *source, unsigned long len)
{
        memcpy(dest, source, len);
        return (0);
} /* copy_from_user() */

unsigned long
__copy_from_user_ll(void *dest, const void *source, unsigned long len)
{
        memcpy(dest, source, len);
        return (0);
} /* copy_from_user() */

unsigned long
copy_to_user(void *dest, const void *source, unsigned long len)
{
        memcpy(dest, source, len);
        return (0);
} /* copy_to_user() */

int
memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len)
{
        int err = -EFAULT;

        while(len>0) {
                if (iov->iov_len) {
                        int copy = min_t(unsigned int, len, iov->iov_len);
                        if (copy_from_user(kdata, iov->iov_base, copy))
                                goto out;
                        len-=copy;
                        kdata+=copy;
                        iov->iov_base+=copy;
                        iov->iov_len-=copy;
                }
                iov++;
        }
        err = 0;
out:
        return err;
} /* memcpy_fromiovec() */

/*
 *	For use with ip_build_xmit
 */

int memcpy_fromiovecend(unsigned char *kdata, struct iovec *iov, int offset,
			int len)
{
	int err = -EFAULT;

	/* Skip over the finished iovecs */
	while(offset >= iov->iov_len)
	{
		offset -= iov->iov_len;
		iov++;
	}

	while (len > 0)
	{
		u8 *base = iov->iov_base + offset;
		int copy = min_t(unsigned int, len, iov->iov_len - offset);

		offset = 0;
		if (copy_from_user(kdata, base, copy))
			goto out;
		len   -= copy;
		kdata += copy;
		iov++;
	}
	err = 0;
out:
	return err;
}


int memcpy_toiovec(struct iovec *iov, unsigned char *kdata, int len)
{
	int err = -EFAULT;

	while(len>0)
	{
		if (iov->iov_len)
		{
			int copy = min_t(unsigned int, iov->iov_len, len);
			if (copy_to_user(iov->iov_base, kdata, copy)) {
				goto out;
			}
			kdata+=copy;
			len-=copy;
			iov->iov_len-=copy;
			iov->iov_base+=copy;
		}
		iov++;
	}
	err = 0;
out:
	return err;
} /* int memcpy_toiovec() */

/*
 *	Copy a datagram to an iovec.
 *	Note: the iovec is modified during the copy.
 */
int skb_copy_datagram_iovec(const struct sk_buff *skb, int offset, struct iovec *to,
			    int len)
{
	int copy;
	int start = skb->len - skb->data_len;

	/* Copy header. */
	if ((copy = start-offset) > 0) {
		if (copy > len)
			copy = len;
		if (memcpy_toiovec(to, skb->data + offset, copy))
			goto fault;
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
	}

	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *list;

		for (list = skb_shinfo(skb)->frag_list; list; list=list->next) {
			int end;

			BUG_TRAP(start <= offset+len);

			end = start + list->len;
			if ((copy = end-offset) > 0) {
				if (copy > len)
					copy = len;
				if (skb_copy_datagram_iovec(list, offset-start, to, copy))
					goto fault;
				if ((len -= copy) == 0)
					return 0;
				offset += copy;
			}
			start = end;
		}
	}
	if (len == 0)
		return 0;

fault:
	return -EFAULT;
}

int
ip_setsockopt(struct sock *sk, int level,
              int optname, char *optval, int optlen)
{
        return 0; /* STUB */
} /* ip_setsockopt() */

int ip_getsockopt(struct sock *sk, int level,
              int optname, char *optval, int *optlen)
{
        return 0; /* STUB */
}


/* Stubs for wait queue handling. */
void fastcall add_wait_queue(wait_queue_head_t *q, wait_queue_t * wait)
{
	return;
}

void fastcall add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t * wait)
{
	return;
}

void fastcall remove_wait_queue(wait_queue_head_t *q, wait_queue_t * wait)
{
	return;
}

void fastcall prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	return;
}

void fastcall prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	return;
}
void fastcall finish_wait(wait_queue_head_t *q, wait_queue_t *wait)
{
	return;
}

int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	return 0;
}

/* Simulate the scheduler (with timeout!)  */
fastcall signed long __sched schedule_timeout(long timeo)
{
	/* BUG:  we do not actually implement the timeout part...
	 * We just run the Internet until it is empty.
	 */
	simulate_internet();
	return timeo;

} /* schedule_timeout() */

/* The function put_cmsg() lives in linux/net/core/scm.c and is the
 * canonical way of copying the headers up or down.  We use it in
 * sctp_recvmsg() to copy them up.  This is a straight copy, since we
 * reference the prototype in linux/socket.h.
 */
int put_cmsg(struct msghdr * msg, int level, int type, int len, void *data)
{
	struct cmsghdr *cm = (struct cmsghdr*)msg->msg_control;
	struct cmsghdr cmhdr;
	int cmlen = CMSG_LEN(len);
	int err;

	if (cm==NULL || msg->msg_controllen < sizeof(*cm)) {
		msg->msg_flags |= MSG_CTRUNC;
		return 0; /* XXX: return error? check spec. */
	}
	if (msg->msg_controllen < cmlen) {
		msg->msg_flags |= MSG_CTRUNC;
		cmlen = msg->msg_controllen;
	}


	cmhdr.cmsg_level = level;
	cmhdr.cmsg_type = type;
	cmhdr.cmsg_len = cmlen;

	err = -EFAULT;
	if (copy_to_user(cm, &cmhdr, sizeof cmhdr))
		goto out;
	if (copy_to_user(CMSG_DATA(cm), data, cmlen - sizeof(struct cmsghdr)))
		goto out;
	cmlen = CMSG_SPACE(len);
	msg->msg_control += cmlen;
	msg->msg_controllen -= cmlen;
	err = 0;
out:
	return err;
}

/* These are dummy structure definitions so that we can use the static
 * inlines init_timer() and timer_pending() from include/linux/timer.h.
 */
struct tvec_t_base_s {
	int jnk;
};
struct tvec_t_base_s timer_base;

void fastcall init_timer(struct timer_list *timer)
{
	timer->entry.next = NULL;
	timer->base = NULL;
}

int __mod_timer(struct timer_list *timer, unsigned long expires)
{
	struct list_head *lh;
	struct timer_list *before;

        INIT_LIST_HEAD(&timer->entry);

	list_for_each(lh, &test_timers) {
		before = list_entry(lh, struct timer_list, entry);
		if (before->expires > timer->expires) {
			break;	/* Quit once we know where to insert. */
		}
	}
	list_add_tail(&timer->entry, lh);

	timer->base = &timer_base;

	return 0;

} /* __mod_timer() */

int del_timer(struct timer_list * timer)
{
	if (timer_pending(timer)) {
		list_del(&timer->entry);
		init_timer(timer);
		return 1;
	}

	timer->base = NULL;

	return 0;

} /* del_timer() */

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	int  detach;
	detach = del_timer(timer);
        timer->expires = expires;
        add_timer(timer);
        return detach;
} /* mod_timer() */

int timer_len(struct list_head *list)
{
	int i = 0;
	struct list_head *t;

	list_for_each(t, list) {
		++i;
	}
	return(i);
}

unsigned int inet_addr_type(u32 addr)
{
	return RTN_LOCAL;
}

int ipv6_chk_addr(struct in6_addr *addr, struct net_device *dev, int strict)
{
	return 1;
}

int
__read_lock_failed(rwlock_t *rw)
{
	return(0);
}


int __ipv6_addr_type(const struct in6_addr *addr)
{
	u32 st;

	st = addr->s6_addr32[0];

	/* Consider all addresses with the first three bits different of
	   000 and 111 as unicasts.
	 */
	if (((st & __constant_htonl(0xE0000000))
             != __constant_htonl(0x00000000))

	    && ((st & __constant_htonl(0xE0000000))
                != __constant_htonl(0xE0000000))) {

		return IPV6_ADDR_UNICAST;
        }

	if ((st & __constant_htonl(0xFF000000))
            == __constant_htonl(0xFF000000)) {

		int type = IPV6_ADDR_MULTICAST;

		switch((st & __constant_htonl(0x00FF0000))) {
			case __constant_htonl(0x00010000):
				type |= IPV6_ADDR_LOOPBACK;
				break;

			case __constant_htonl(0x00020000):
				type |= IPV6_ADDR_LINKLOCAL;
				break;

			case __constant_htonl(0x00050000):
				type |= IPV6_ADDR_SITELOCAL;
				break;
		};
		return type;
	}

	if ((st & __constant_htonl(0xFFC00000))
            == __constant_htonl(0xFE800000)) {
		return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST);
        }

	if ((st & __constant_htonl(0xFFC00000))
            == __constant_htonl(0xFEC00000)) {
		return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST);
        }

	if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
		if (addr->s6_addr32[2] == 0) {
			if (addr->in6_u.u6_addr32[3] == 0) {
				return IPV6_ADDR_ANY;
                        }

			if (addr->s6_addr32[3]
                            == __constant_htonl(0x00000001)) {
				return (IPV6_ADDR_LOOPBACK
                                        | IPV6_ADDR_UNICAST);
                        }

			return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST);
		}

		if (addr->s6_addr32[2] == __constant_htonl(0x0000ffff))
			return IPV6_ADDR_MAPPED;
	}

	return IPV6_ADDR_RESERVED;
} /* ipv6_addr_type()  */

int
register_inetaddr_notifier(struct notifier_block *nb)
{
	inetaddr_notifier_on = nb;
	return(0);
} /* register_inetaddr_notifier() */

int
unregister_inetaddr_notifier(struct notifier_block *nb)
{
	inetaddr_notifier_on = NULL;
	return(0);
} /* unregister_inetaddr_notifier() */

int
register_inet6addr_notifier(struct notifier_block *nb)
{
	return(0);
} /* register_inet6addr_notifier() */

int
unregister_inet6addr_notifier(struct notifier_block *nb)
{
	return(0);
} /* unregister_inet6addr_notifier() */

/* This is a testing stub for a function which wakes up threads which
 * are sleeping on sockets.
 */
void fastcall
__wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key)
{
	/* Do nothing.  */
	/* Could we be cleverer?  Probably... */
} /* __wake_up() */

void
inet_register_protosw(struct inet_protosw *p)
{
}

void
inet_unregister_protosw(struct inet_protosw *p)
{
}

int
inet_add_protocol(struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int
inet_del_protocol(struct net_protocol *prot, unsigned char num)
{
	return 0;
}

int
inet_release(struct socket *sock)
{
	return 0;
}

int
inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	return 0;
}

int
inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr,
			int addr_len, int flags)
{
	return 0;
}

int
inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	return 0;
}

int
inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	return 0;
}

int
inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return 0;
}

int
inet_shutdown(struct socket *sock, int how)
{
	return 0;
}

int
sock_common_setsockopt(struct socket *sock, int level, int optname,
			char *optval, int optlen)
{
	return 0;
}

int
sock_common_getsockopt(struct socket *sock, int level, int optname, char *optval,
			int *optlen)
{
	return 0;
}

int
sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
		    struct msghdr *msg, size_t size, int flags)
{
	return 0;
}

int
inet_sendmsg(struct socket *sock, struct msghdr *msg,
			int size, struct scm_cookie *scm)
{
	return 0;
}

static struct dst_entry *ip6_dst_check(struct dst_entry *dst, u32 cookie)
{
	return dst;
}

static void ip6_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
}

static struct dst_ops ip6_dst_ops = {
	.family			=	AF_INET6,
	.protocol		=	__constant_htons(ETH_P_IPV6),
	.gc_thresh		=	1024,
	.check			=	ip6_dst_check,
	.update_pmtu		=	ip6_rt_update_pmtu,
	.entry_size		=	sizeof(struct rt6_info),
};

/* Hacked testframe version of ip_route_output_key. It returns a route entry
 * for a given destination and source. If an entry is not present the the list,
 * a new entry is created and added to rt_list.
 */
int ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	struct rtable *rt;

	for (rt = rt_list; rt != NULL; rt = rt->u.dst.rt_next) {
		if ((rt->rt_dst == flp->fl4_dst) &&
		    (((flp->fl4_src == 0) && (rt->rt_src == rt->rt_dst)) ||
		      (rt->rt_src == flp->fl4_src))) {
			*rp = rt;
			dst_hold(&rt->u.dst);
			return 0;
		}
	}

	rt = kmalloc(sizeof(struct rtable), GFP_KERNEL);

	rt->u.dst.path = &rt->u.dst;
	rt->u.dst.metrics[RTAX_MTU-1] = ip_mtu;
	rt->u.dst.obsolete = 0;
	rt->u.dst.ops = &ipv4_dst_ops;
	rt->rt_flags = 0;
	atomic_set(&rt->u.dst.__refcnt, 1);

	switch(flp->fl4_dst) {
	case 0x100007f:
		rt->u.dst.dev = &loopback_dev;
		rt->rt_dst = SCTP_ADDR_LO;
		break;
	case 0x100000a:
		rt->u.dst.dev = &eth0_dev;
		rt->rt_dst = SCTP_ADDR_ETH0;
		break;
	case 0x200000a:
		rt->u.dst.dev = &eth0_dev;
		rt->rt_dst = SCTP_B_ETH0;
		break;
	case 0x300000a:
		rt->u.dst.dev = &eth0_dev;
		rt->rt_dst = SCTP_C_ETH0;
		break;
	case 0x400000a:
		rt->u.dst.dev = &eth0_dev;
		rt->rt_dst = SCTP_D_ETH0;
		break;
	case 0x10010ac:
		rt->u.dst.dev = &eth1_dev;
		rt->rt_dst = SCTP_ADDR_ETH1;
		break;
	case 0x12aa8c0:
		rt->u.dst.dev = &eth2_dev;
		rt->rt_dst = SCTP_ADDR_ETH2;
		break;
	case 0x06a81104:
		rt->u.dst.dev = &eth0_dev;
		rt->rt_dst =  SCTP_GLOBAL_ETH0;
		break;
	default:
		kfree(rt);
		return -1;
	}

	if (flp->fl4_src) {
		rt->rt_src = flp->fl4_src;
	} else {
		rt->rt_src = rt->rt_dst;
	}

	*rp = rt;

	rt->u.dst.rt_next = rt_list;
	rt_list = rt;

	dst_hold(&rt->u.dst);

	return 0;
}

static void ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	return;
}

/* Cleanup any expired entries from the v4 and v6 routing tables. */
void test_update_rtables(void)
{
	struct rtable *rt, **rtp;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	struct rt6_info *rt6, **rt6p;
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	rtp = &rt_list;
	while ((rt = *rtp) != NULL) {
		if (rt->u.dst.expires && (rt->u.dst.expires < jiffies)) {
			rt->u.dst.obsolete = 2;
			*rtp = rt->u.dst.rt_next;
			continue;
		}
		rtp = &rt->u.dst.rt_next;
	}

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	rt6p = &rt6_list;
	while ((rt6 = *rt6p) != NULL) {
		if (rt6->u.dst.expires && (rt6->u.dst.expires < jiffies)) {
			rt6->u.dst.obsolete = 2;
			*rt6p = rt6->u.dst.rt6_next;
			continue;
		}
		rt6p = &rt6->u.dst.rt6_next;
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
}

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)

void
inet6_register_protosw(struct inet_protosw *p)
{
}

void inet6_unregister_protosw(struct inet_protosw *p)
{
}

int inet6_add_protocol(struct inet6_protocol *prot, unsigned char num)
{
	return 0;
}

int inet6_del_protocol(struct inet6_protocol *prot, unsigned char num)
{
	return 0; /* STUB */
}

int inet6_release(struct socket *sock)
{
	return 0; /* STUB */
}

int inet6_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	return 0; /* STUB */
}

int inet6_getname(struct socket *sock, struct sockaddr *uaddr,
                 int *uaddr_len, int peer)
{
	return 0; /* STUB */
}

int inet6_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return 0; /* STUB */
}

int
ipv6_setsockopt(struct sock *sk, int level,
              int optname, char *optval, int optlen)
{
        return 0; /* STUB */
} /* ipv6_setsockopt() */

int
ipv6_getsockopt(struct sock *sk, int level,
              int optname, char *optval, int *optlen)
{
        return 0; /* STUB */
} /* ipv6_getsockopt() */

/* Hacked testframe version of ip6_route_output. It returns a dst entry for a
 * given ipv6 destination and source. If an entry is not present the the list,
 * a new entry is created and added to rt6_list.
 */
struct dst_entry *ip6_route_output(struct sock *sk, struct flowi *flp)
{
	struct rt6_info *rt6;

        if (!epoch_started) {
                init_Internet();
        }

	/* Look for an entry. */
	for (rt6 = rt6_list; rt6 != NULL; rt6 = rt6->u.dst.rt6_next) {
		if (!ipv6_addr_cmp(&rt6->rt6i_dst.addr, &flp->fl6_dst)) {
			dst_hold(&rt6->u.dst);
			return &rt6->u.dst;
		}
	}

	/* Didn't find an entry, so lets just make one up. */
	rt6 = kmalloc(sizeof(struct rt6_info), GFP_KERNEL);

	rt6->u.dst.path = &rt6->u.dst;
	rt6->u.dst.metrics[RTAX_MTU-1] = ip_mtu;
	rt6->u.dst.obsolete = -1;
	rt6->u.dst.error = 0;
	atomic_set(&rt6->u.dst.__refcnt, 1);
	rt6->u.dst.ops = &ip6_dst_ops;

	ipv6_addr_copy(&rt6->rt6i_dst.addr,  &flp->fl6_dst);
	if (ipv6_addr_any(&flp->fl6_src))
		ipv6_addr_copy(&rt6->rt6i_src.addr,  &flp->fl6_dst);
	else
		ipv6_addr_copy(&rt6->rt6i_src.addr,  &flp->fl6_src);

	if (!ipv6_addr_cmp(&flp->fl6_dst, &lo_inet6_ifa.addr)) {
		rt6->u.dst.dev = &loopback_dev;
		ipv6_addr_copy(&rt6->rt6i_dst.addr, &lo_inet6_ifa.addr);
		goto done;
	}

	if (!ipv6_addr_cmp(&flp->fl6_dst, &eth0_inet6_global_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth0_inet6_sitelocal_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth0_inet6_linklocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer_eth0_inet6_global_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer_eth0_inet6_linklocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer_eth0_inet6_sitelocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer2_eth0_inet6_linklocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer2_eth0_inet6_sitelocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer3_eth0_inet6_linklocal_ifa.addr) ||
		!ipv6_addr_cmp(&flp->fl6_dst, &peer3_eth0_inet6_sitelocal_ifa.addr)) {
		rt6->u.dst.dev = &eth0_dev;
		goto done;
	}

	if (!ipv6_addr_cmp(&flp->fl6_dst, &eth1_inet6_global_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth1_inet6_sitelocal_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth1_inet6_linklocal_ifa.addr)) {
		rt6->u.dst.dev = &eth1_dev;
		goto done;
	}

	if (!ipv6_addr_cmp(&flp->fl6_dst, &eth2_inet6_global_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth2_inet6_sitelocal_ifa.addr) ||
	    !ipv6_addr_cmp(&flp->fl6_dst, &eth2_inet6_linklocal_ifa.addr)) {
		rt6->u.dst.dev = &eth2_dev;
		goto done;
	}

	kfree(rt6);
	return NULL;

done:
	rt6->u.dst.rt6_next = rt6_list;
	rt6_list = rt6;

	dst_hold(&rt6->u.dst);
	return &rt6->u.dst;
}

#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

int
sock_no_socketpair(struct socket *sock1, struct socket *sock2)
{
	return -EOPNOTSUPP;
}

int
sock_no_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	/* Mirror missing mmap method error code */
	return -ENODEV;
}


ssize_t
sock_no_sendpage(struct socket *sock, struct page *page, int offset,
		 size_t size, int flags)
{
	/* Mirror missing sendpage method error code */
	/* Note: this does not match the kernel sock_no_sendpage
	 * behavior.   This no-op version may need more work if
	 * it is found lksctp depends upon it.
	 */
	return -ENOTSUPP;
}


unsigned int
datagram_poll(struct file * file, struct socket *sock, poll_table *wait)
{
	return 0;
}

void
do_BUG(const char *file, int line)
{
    fprintf (stderr, "Error in file %s at line %d\n", file, line);
    exit (1);
}

/* Moving to here since the core code doesn't really use anymore. */
struct sctp_endpoint *
sctp_lookup_endpoint(const union sctp_addr *laddr)
{
	struct sctp_hashbucket *head;
	struct sctp_ep_common *ep;
	int hash;

	hash = sctp_ep_hashfn(ntohs(laddr->v4.sin_port));
	head = &sctp_ep_hashtable[hash];
	read_lock(&head->lock);
	for (ep= head->chain; ep; ep = ep->next) {
		if (sctp_endpoint_is_match(sctp_ep(ep), laddr)) { goto hit; }
	}

	ep = NULL;

hit:
	read_unlock(&head->lock);
	return sctp_ep(ep);

} /* sctp_lookup_endpoint() */


/* API 3.1.1 socket() - UDP Style Syntax
 *
 * Applications use socket() to create a socket descriptor to represent
 * an SCTP endpoint.
 *
 * The syntax is,
 *
 *   sd = socket(PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
 *
 * or,
 *
 *   sd = socket(PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP);
 *
 * Here, SOCK_SEQPACKET indicates the creation of a UDP-style socket.
 *
 * The first form creates an endpoint which can use only IPv4 addresses,
 * while, the second form creates an endpoint which can use both IPv6 and
 * IPv4 mapped addresses.
 *
 */

struct sock *
sctp_socket(int class, int type)
{
        struct sock *retval;
	struct socket *socket;
	struct file *file;

	printk("sctp_socket(...)\n");

	switch (class){
	case PF_INET:
	{
        	/* BUG:  There must be a real way to do this.  Sleaze out. */
        	retval = (struct sock *)t_new(struct sctp_sock, GFP_KERNEL);
        	if (NULL == retval) { return(NULL); }
		memset(retval, 0, sizeof(struct sctp_sock));
		retval->sk_family = PF_INET;
		break;
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	case PF_INET6:
	{
		struct sctp6_sock *sctp6sk;

        	/* BUG:  There must be a real way to do this.  Sleaze out. */
        	retval = (struct sock *)t_new(struct sctp6_sock, GFP_KERNEL);
        	if (NULL == retval) { return(NULL); }
		memset(retval, 0, sizeof(struct sctp6_sock));
		retval->sk_family = PF_INET6;
		sctp6sk = (struct sctp6_sock *)retval;
		inet_sk(retval)->pinet6 = &(sctp6sk->inet6);
		break;
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	default:
		return NULL;
	} /* switch class */

	retval->sk_prot = &sctp_prot;
	socket = (struct socket *)t_new(struct socket, GFP_KERNEL);
	if (NULL == socket) { return(NULL); }
	file = (struct file *)t_new(struct file, GFP_KERNEL);
	if (NULL == file) { return(NULL); }
	memset(socket, 0, sizeof(struct socket));
	memset(file, 0, sizeof(struct file));
	retval->sk_socket = socket;
	socket->file = file;
	socket->type = type;

	retval->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;

	skb_queue_head_init(&retval->sk_receive_queue);
	skb_queue_head_init(&retval->sk_write_queue);
	atomic_set(&retval->sk_refcnt, 1);

	sock_init_data(socket, retval);

	if (sctp_init_sock(retval)) {
		kfree(retval);
		retval = NULL;
	}

	/* Enable data and association events on UDP-style sockets which
	 * are now off by default as per the SCTP sockets API draft 07.
	 * Most of the tests assume that these events are on.
	 */
	if (SOCK_SEQPACKET == type)
		test_frame_enable_data_assoc_events(retval);

	sctp_sk(retval)->nodelay = 1;

        /* BUG:  we do not fill in any of those other juicy fields... */
        return(retval);

} /* sctp_socket() */

int
sock_create(int family, int type, int protocol, struct socket **res)
{
	struct socket *socket;
	struct sock *sk;

	socket = t_new(struct socket, GFP_KERNEL);
	if (socket == NULL) {
		return(-ENOMEM);
        }

	sk = sctp_socket(family, type);
	if (sk) {
		sk->sk_prot = &sctp_prot;
		socket->sk = sk;
		sk->sk_socket = socket;
		*res = socket;
		return(0);
	}
	else {
		return(-ENOMEM);
	}

} /* sock_create */

void
sock_release(struct socket *socket)
{
	sctp_close(socket->sk, 0);
	kfree(socket);
} /* sock_release */

struct sock *sk_alloc(int family, unsigned int priority, struct proto *prot,
			 int zero_it)
{
	struct sock *sk;

	switch (family){
	case PF_INET:
	{
        	sk = (struct sock *)t_new(struct sctp_sock, GFP_KERNEL);
        	if (NULL == sk) { return(NULL); }
		memset(sk, 0, sizeof(struct sctp_sock));
		sk->sk_family = PF_INET;
		sk->sk_prot = prot;
		break;
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	case PF_INET6:
	{
		struct sctp6_sock *sctp6sk;

        	sk = (struct sock *)t_new(struct sctp6_sock, GFP_KERNEL);
        	if (NULL == sk) { return(NULL); }
		memset(sk, 0, sizeof(struct sctp6_sock));
		sk->sk_family = PF_INET6;
		sk->sk_prot = prot;
		sctp6sk = (struct sctp6_sock *)sk;
		inet_sk(sk)->pinet6 = &(sctp6sk->inet6);
		break;
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	default:
		return NULL;
	}

	return sk;
}

void sock_def_wakeup(struct sock *sk)
{
	read_lock(&sk->sk_callback_lock);
	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible(sk->sk_sleep);
	read_unlock(&sk->sk_callback_lock);
}

void sock_def_error_report(struct sock *sk)
{
	read_lock(&sk->sk_callback_lock);
	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible(sk->sk_sleep);
	read_unlock(&sk->sk_callback_lock);
}

void sock_def_readable(struct sock *sk, int len)
{
	read_lock(&sk->sk_callback_lock);
	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible(sk->sk_sleep);
	read_unlock(&sk->sk_callback_lock);
}

void sock_def_write_space(struct sock *sk)
{
	read_lock(&sk->sk_callback_lock);

	/* Do not wake up a writer until he can make "significant"
	 * progress.  --DaveM
	 */
	if((atomic_read(&sk->sk_wmem_alloc) << 1) <= sk->sk_sndbuf) {
		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
        }

	read_unlock(&sk->sk_callback_lock);
}

void sock_def_destruct(struct sock *sk)
{
	if (sk->sk_protinfo)
		kfree(sk->sk_protinfo);
}

void sock_init_data(struct socket *sock, struct sock *sk)
{
	skb_queue_head_init(&sk->sk_receive_queue);
	skb_queue_head_init(&sk->sk_write_queue);
	skb_queue_head_init(&sk->sk_error_queue);

	init_timer(&sk->sk_timer);

	sk->sk_allocation	= GFP_KERNEL;
	sk->sk_rcvbuf	= sysctl_rmem_default;
	sk->sk_sndbuf	= sysctl_wmem_default;
	sk->sk_state 	= TCP_CLOSE;
	sk->sk_socket	= sock;

	if(sock)
	{
		sk->sk_type	=	sock->type;
		sk->sk_sleep	=	&sock->wait;
		sock->sk	=	sk;
	} else
		sk->sk_sleep	=	NULL;

	sk->sk_dst_lock		=	RW_LOCK_UNLOCKED;
	sk->sk_callback_lock	=	RW_LOCK_UNLOCKED;

	sk->sk_state_change	=	sock_def_wakeup;
	sk->sk_data_ready	=	sock_def_readable;
	sk->sk_write_space	=	sock_def_write_space;
	sk->sk_error_report	=	sock_def_error_report;
	sk->sk_destruct         =       sock_def_destruct;

	sk->sk_peercred.pid 	=	0;
	sk->sk_peercred.uid	=	-1;
	sk->sk_peercred.gid	=	-1;
	sk->sk_rcvlowat		=	1;
	sk->sk_rcvtimeo		=	MAX_SCHEDULE_TIMEOUT;
	sk->sk_sndtimeo		=	MAX_SCHEDULE_TIMEOUT;

	atomic_set(&sk->sk_refcnt, 1);
}

void inet_sock_destruct(struct sock *sk)
{

}

struct tasklet_struct bh_task_vec[32];
spinlock_t tqueue_lock = SPIN_LOCK_UNLOCKED;

void fastcall
__tasklet_hi_schedule(struct tasklet_struct *t)
{
}

int ___pskb_trim(struct sk_buff *skb, unsigned int len)
{
	return 0;
}

int default_wake_function(wait_queue_t *curr, unsigned mode, int sync,
			  void *key)
{
	return 0;
}

/* A test frame version of sk_free.  This gets called when the
 * reference count of the sock goes to 0.
 */
void sk_free(struct sock *sk)
{
 	if (sk->sk_destruct)
 		sk->sk_destruct(sk);

 	kfree(sk);
}


/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 * This is a test frame version of sock_orphan without the callback
 * locks.
 */
static inline void sctp_sock_orphan(struct sock *sk)
{
	__set_bit(SOCK_DEAD, &sk->sk_flags);
 	sk->sk_socket = NULL;
 	sk->sk_sleep = NULL;
}


/* A test frame version of sk_common_release().   */
void sk_common_release(struct sock *sk)
{

#if 1
 	sctp_destroy_sock(sk);
#else
 	if (sk->prot->destroy)
 		sk->prot->destroy(sk);
#endif


 	/* Observation: when sk_common_release is called, processes have
 	 * no access to socket. But net still has.
 	 * Step one, detach it from networking:
 	 *
 	 * A. Remove from hash tables.
 	 */
#if 0
        if (sk->prot->unhash)
		sk->prot->unhash(sk);
#endif

 	/* In this point socket cannot receive new packets,
 	 * but it is possible that some packets are in flight
 	 * because some CPU runs receiver and did hash table lookup
 	 * before we unhashed socket. They will achieve receive queue
 	 * and will be purged by socket destructor.
 	 *
 	 * Also we still have packets pending on receive
 	 * queue and probably, our own packets waiting in device queues.
 	 * sock_destroy will drain receive queue, but transmitted
 	 * packets will delay socket destruction until the last reference
 	 * will be released.
 	 */

 	sctp_sock_orphan(sk);

#ifdef INET_REFCNT_DEBUG
 	if (atomic_read(&sk->refcnt) != 1) {
 		printk(KERN_DEBUG "Destruction inet %p delayed, c=%d\n", sk, atomic_read(&sk->refcnt));
 	}
#endif
 	sock_put(sk);
}

/* Simulate transport of 1 packet on the specificed network.
 * Change the packet sequence when submitted to SCTP.
 * It's for the simulation of the second case of INIT collision.
 */
void
change_chunk_sequence(int net)
{
	struct sk_buff *skb;
	struct sk_buff *nskb[2];
	int i;

	for(i=0;i<=1;i++) {
		skb = skb_dequeue(&Internet[net]);
		if (!skb || !network_up[net]) {
			return;
		}

		/* This copy thing is VERY IMPORTANT!
                 * Remember that the data portion of skb is still lolly-gagging
		 * about in transport.transmitted...
		 */

		if (replacement && CHUNK_TYPE(skb, /* has_ip */ 1) == scapegoat) {
			nskb[i] = make_skb(replacement, replacement_len);
			replacement = NULL;
			replacement_len = 0;
		} else {
			nskb[i] = skb_copy(skb, GFP_KERNEL);
		}
		nskb[i]->sk = skb->sk;
		__kfree_skb(skb);

		/* Set the transport header.  */
		skb_pull(nskb[i], test_hdr_size(nskb[i]->data));
		skb_reset_transport_header(nskb[i]);

		/* Mark the "device" we received on.  */
		nskb[i]->dev = devices[net];

		/* Do we need to blow this away?  */
		if (do_slaughter(nskb[i])) {
			return;  /* drop packet */
		} else if (do_congest(nskb[i])) {
			return; /* drop packet */
		}
	}/*for...*/

	/* Feed the packet to SCTP.  */
	(void) sctp_rcv(nskb[1]);
	(void) sctp_rcv(nskb[0]);

} /* change_chunk_sequence() */

/* Steal all the packets from the network to sidelist*/
void
test_steal_network(int net)
{
	struct sk_buff *skb;
        while ((skb = skb_dequeue(&Internet[net])) != NULL) {
		skb_queue_tail(&sidelist, skb);
	}
}

/* Restore all the packets to the network from sidelist*/
void
test_restore_network(int net)
{
	struct sk_buff *skb;
	
        while ((skb = skb_dequeue(&sidelist)) != NULL) {
		skb_queue_tail(&Internet[net], skb);
	}
}

int sock_map_fd(struct socket *sock)
{
	return 0; /* STUB */

} /* sock_map_fd() */

int sock_wake_async(struct socket *sock, int how, int band)
{
	return 0; /* STUB */
} /* sock_wake_async() */

void __pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
	/* STUB */
} /* __pollwait() */

void preempt_schedule(void)
{
	return; /* STUB */

} /* preempt_schedule() */

unsigned int xfrm_policy_count[XFRM_POLICY_MAX*2];
struct xfrm_policy *xfrm_policy_list[XFRM_POLICY_MAX*2];

int __xfrm_policy_check(struct sock *sk, int dir, struct sk_buff *skb, unsigned short family)
{
	return 1;
}

#ifdef CONFIG_SMP
void *__percpu_alloc_mask(size_t size, gfp_t gfp, cpumask_t *mask)
{
	return kmalloc(size, gfp);
}

void percpu_free(void *__pdata)
{
	kfree(__pdata);
}
#endif

struct sock_filter;
unsigned int sk_run_filter(struct sk_buff *skb, struct sock_filter *filter, int flen)
{
	return 0;
}

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	return 0;
}

int single_release(struct inode *inode, struct file *file)
{
	return 0;
}

ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return size;
}

loff_t seq_lseek(struct file *file, loff_t offset, int len)
{
	return offset;
}

int seq_printf(struct seq_file *file, const char *buf, ...)
{
	return 0;
}

int seq_open(struct file *file, const struct seq_operations *op)
{
	return 0;
}

int seq_release(struct inode *inode, struct file *file)
{
	return 0;
}

/* Start ipv6/icmp.c */
DEFINE_SNMP_STAT(struct icmpv6_mib, icmpv6_statistics);
static struct icmp6_err {
	int err;
	int fatal;
} tab_unreach[] = {
	{ ENETUNREACH,	0},	/* NOROUTE		*/
	{ EACCES,	1},	/* ADM_PROHIBITED	*/
	{ EHOSTUNREACH,	0},	/* Was NOT_NEIGHBOUR, now reserved */
	{ EHOSTUNREACH,	0},	/* ADDR_UNREACH		*/
	{ ECONNREFUSED,	1},	/* PORT_UNREACH		*/
};

int icmpv6_err_convert(int type, int code, int *err)
{
	int fatal = 0;

	*err = EPROTO;

	switch (type) {
	case ICMPV6_DEST_UNREACH:
		fatal = 1;
		if (code <= ICMPV6_PORT_UNREACH) {
			*err  = tab_unreach[code].err;
			fatal = tab_unreach[code].fatal;
		}
		break;

	case ICMPV6_PKT_TOOBIG:
		*err = EMSGSIZE;
		break;
		
	case ICMPV6_PARAMPROB:
		*err = EPROTO;
		fatal = 1;
		break;

	case ICMPV6_TIME_EXCEED:
		*err = EHOSTUNREACH;
		break;
	};

	return fatal;
}

/* End ipv6/icmp.c */

/* Allocate crypto transform. */ 
struct crypto_tfm *crypto_alloc_tfm(const char *alg_name, u32 tfm_flags) 
{
	struct crypto_tfm *tfm;

	/* A pure do-nothing hack. */
	tfm = kmalloc(sizeof(struct crypto_tfm), GFP_ATOMIC);
	return tfm;
}

struct crypto_tfm *crypto_alloc_base(const char *alg_name, u32 type, u32 mask)
{

	return crypto_alloc_tfm(alg_name, 0);
}

/* Free crypto transform. */
void crypto_free_tfm(struct crypto_tfm *tfm)
{
	kfree(tfm);
}

void crypto_hmac(struct crypto_tfm *tfm, u8 *key, unsigned int *keylen,
                 struct scatterlist *sg, unsigned int nsg, u8 *out)
{
	memset(out, 0x00, SCTP_SIGNATURE_SIZE);
}

struct page *mem_map;

int send_sig(int sig, struct task_struct *p, int priv)
{
	return 0;
}
void *_mmx_memcpy(void *to, const void *from, size_t size)
{
	return memcpy(to, from, size);
}


/* slab.c */
struct kmem_cache {
	int objsize;
};
struct kmem_cache *kmem_cache_create(const char *name, size_t size, 
		size_t align, unsigned long flags,
		void (*ctor)(void *, struct kmem_cache *, unsigned long),
		void (*dtor)(void *, struct kmem_cache *, unsigned long))
{
	struct kmem_cache *cachep;

	/* hack to initialize proc_net_sctp before the call to 
	 * sctp_proc_init()
	 */
	if (!proc_net_sctp)
		proc_net_sctp = malloc(sizeof(struct proc_dir_entry));	

	cachep = kmalloc(sizeof(struct kmem_cache), GFP_KERNEL);
	if (!cachep)
		return NULL;
	cachep->objsize = size;
	return cachep;
}
void kmem_cache_destroy(struct kmem_cache *cachep)
{
	kfree(cachep);
}
void *kmem_cache_alloc(struct kmem_cache *cachep, unsigned int flags)
{
	return kmalloc(cachep->objsize, flags);
}
void kmem_cache_free(struct kmem_cache *cachep, void *obj)
{
	kfree(obj);
}	
unsigned int module_refcount(struct module *mod)
{
	return 0;
}

void in6_dev_finish_destroy(struct inet6_dev *idev)
{
}

unsigned long num_physpages = 65536;

fastcall unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	
	return ((unsigned long)kmalloc(((1UL << order) * PAGE_SIZE), gfp_mask));
}

fastcall void free_pages(unsigned long addr, unsigned int order)
{
	kfree((void *)addr);
}

void idr_init(struct idr *idp)
{
	return;
}

int idr_pre_get(struct idr *idp, unsigned gfp_mask)
{
	return 1;
}

int idr_get_new(struct idr *idp, void *ptr, int *id)
{
	*id = (int)ptr;
	return 0;
}

int idr_get_new_above(struct idr *idp, void *ptr, int starting_id, int *id)
{
	*id = (int)ptr;
	return 0;
}

void *idr_find(struct idr *idp, int id)
{
	return (void *)id;
}

void idr_remove(struct idr *idp, int id)
{
	return;
}

void sock_enable_timestamp(struct sock *sk)
{
	return;
}

void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_tail(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}

struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, flags);
	result = __skb_dequeue(list);
	spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

void skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(list)) != NULL)
		kfree_skb(skb);
}

void skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_unlink(skb, list);
	spin_unlock_irqrestore(&list->lock, flags);
}

int sock_create_kern(int family, int type, int protocol, struct socket **res)
{
	return sock_create(family, type, protocol, res);
}

void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_head(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}

int sk_alloc_slab(struct proto *prot, char *name)
{
	return 0;
}

void sk_free_slab(struct proto *prot)
{
	return;
}

void __lockfunc _read_lock(rwlock_t *lock)
{
	return;
}

void __lockfunc _read_unlock(rwlock_t *lock)
{
	return;
}

unsigned long __lockfunc _spin_lock_irqsave(spinlock_t *lock)
{
	return 0;
}

void __lockfunc _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	return;
}

void __lockfunc _spin_lock(spinlock_t *lock)
{
	return;
}

void __lockfunc _spin_unlock(spinlock_t *lock)
{
	return;
}

void __lockfunc _spin_lock_bh(spinlock_t *lock)
{
	return;
}

void __lockfunc _spin_unlock_bh(spinlock_t *lock)
{
	return;
}

void dump_stack(void)
{
	return;
}

/* Make a DATA chunk for the given association to ride on stream id
 * 'stream', with a payload id of 'payload', and a body of 'data'.
 */
struct sctp_chunk *sctp_make_data(struct sctp_association *asoc,
				  const struct sctp_sndrcvinfo *sinfo,
				  int data_len, const __u8 *data)
{
	struct sctp_chunk *retval = NULL;

	retval = sctp_make_data_empty(asoc, sinfo, data_len);
	if (retval)
		sctp_addto_chunk(retval, data_len, data);
	return retval;
}

/* Make a DATA chunk for the given association to ride on stream id
 * 'stream', with a payload id of 'payload', and a body big enough to
 * hold 'data_len' octets of data.  We use this version when we need
 * to build the message AFTER allocating memory.
 */
struct sctp_chunk *sctp_make_data_empty(struct sctp_association *asoc,
					const struct sctp_sndrcvinfo *sinfo,
					int data_len)
{
	__u8 flags = SCTP_DATA_NOT_FRAG;

	return sctp_make_datafrag_empty(asoc, sinfo, data_len, flags, 0);
}

/* Rewind an sctp_cmd_seq_t to iterate from the start.  */
int sctp_rewind_sequence(sctp_cmd_seq_t *seq)
{
	seq->next_cmd = 0;
	return 1;               /* We always succeed. */
}

#if defined(CONFIG_PREEMPT) && defined(CONFIG_DEBUG_PREEMPT)
unsigned int smp_processor_id(void)
{
	return 0;
}
#endif

#ifdef CONFIG_DEBUG_PREEMPT
void fastcall add_preempt_count(int val)
{
	return;
}

void fastcall sub_preempt_count(int val)
{
	return;
}
#endif

void sock_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
}

int proto_register(struct proto *prot, int alloc_slab)
{
	return 0;
}

void proto_unregister(struct proto *prot)
{
	return;
}

int sock_i_uid(struct sock *sk)
{
	int uid;

	uid = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_uid : 0;
	return uid;
}

unsigned long sock_i_ino(struct sock *sk)
{
	unsigned long ino;

	ino = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_ino : 0;
	return ino;
}

struct net_device *dev_get_by_index(int ifindex)
{
	int i;
	struct net_device *dev = NULL;

        for (i = 0; i < NUM_NETWORKS; ++i) {
		if (devices[i]->ifindex == ifindex) {
			dev = devices[i];
			dev_hold(dev);
			break;
		}	
	}

	return dev; 
}

ktime_t ktime_get_real(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	return timeval_to_ktime(tv);
}

cpumask_t cpu_possible_map = CPU_MASK_ALL;

int find_next_bit(const unsigned long *addr, int size, int offset)
{
	const unsigned long *base;
	const int NBITS = sizeof(*addr) * 8;
	unsigned long tmp;

	base = addr;
	if (offset) {
		int suboffset;

		addr += offset / NBITS;

		suboffset = offset % NBITS;
		if (suboffset) {
			tmp = *addr;
			tmp >>= suboffset;
			if (tmp)
				goto finish;
		}

		addr++;
	}

	while ((tmp = *addr) == 0)
		addr++;

	offset = (addr - base) * NBITS;

 finish:
	/* count the remaining bits without using __ffs() since that takes a 32-bit arg */
	while (!(tmp & 0xff)) {
		offset += 8;
		tmp >>= 8;
	}

	while (!(tmp & 1)) {
		offset++;
		tmp >>= 1;
	}

	return offset;
}

int capable(int cap)
{
	return 1;
}

int __first_cpu(const cpumask_t *srcp)
{
	return min_t(int, NR_CPUS, find_first_bit(srcp->bits, NR_CPUS));
}

int __next_cpu(int n, const cpumask_t *srcp)
{
	return min_t(int, NR_CPUS, find_next_bit(srcp->bits, NR_CPUS, n+1));
}

/**
 *	__pskb_pull_tail - advance tail of skb header
 *	@skb: buffer to reallocate
 *	@delta: number of bytes to advance tail
 *
 *	The function makes a sense only on a fragmented &sk_buff,
 *	it expands header moving its tail forward and copying necessary
 *	data from fragmented part.
 *
 *	&sk_buff MUST have reference count of 1.
 *
 *	Returns %NULL (and &sk_buff does not change) if pull failed
 *	or value of new tail of skb in the case of success.
 *
 *	All the pointers pointing into skb header may change and must be
 *	reloaded after call to this function.
 */

/* Moves tail of skb head forward, copying data from fragmented part,
 * when it is necessary.
 * 1. It may fail due to malloc failure.
 * 2. It may change skb pointers.
 *
 * It is pretty complicated. Luckily, it is called only in exceptional cases.
 */
unsigned char *__pskb_pull_tail(struct sk_buff *skb, int delta)
{
	/* If skb has not enough free space at tail, get new one
	 * plus 128 bytes for future expansions. If we have enough
	 * room at tail, reallocate without expansion only if skb is cloned.
	 */
	int i, k, eat = (skb->tail + delta) - skb->end;

	if (eat > 0 || skb_cloned(skb)) {
		if (pskb_expand_head(skb, 0, eat > 0 ? eat + 128 : 0,
				     GFP_ATOMIC))
			return NULL;
	}

	if (skb_copy_bits(skb, skb_headlen(skb), skb->tail, delta))
		BUG();

	/* Optimization: no fragments, no reasons to preestimate
	 * size of pulled pages. Superb.
	 */
	if (!skb_shinfo(skb)->frag_list)
		goto pull_pages;

	/* Estimate size of pulled pages. */
	eat = delta;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size >= eat)
			goto pull_pages;
		eat -= skb_shinfo(skb)->frags[i].size;
	}

	/* If we need update frag list, we are in troubles.
	 * Certainly, it possible to add an offset to skb data,
	 * but taking into account that pulling is expected to
	 * be very rare operation, it is worth to fight against
	 * further bloating skb head and crucify ourselves here instead.
	 * Pure masohism, indeed. 8)8)
	 */
	if (eat) {
		struct sk_buff *list = skb_shinfo(skb)->frag_list;
		struct sk_buff *clone = NULL;
		struct sk_buff *insp = NULL;

		do {
			BUG_ON(!list);

			if (list->len <= eat) {
				/* Eaten as whole. */
				eat -= list->len;
				list = list->next;
				insp = list;
			} else {
				/* Eaten partially. */

				if (skb_shared(list)) {
					/* Sucks! We need to fork list. :-( */
					clone = skb_clone(list, GFP_ATOMIC);
					if (!clone)
						return NULL;
					insp = list->next;
					list = clone;
				} else {
					/* This may be pulled without
					 * problems. */
					insp = list;
				}
				if (!pskb_pull(list, eat)) {
					if (clone)
						kfree_skb(clone);
					return NULL;
				}
				break;
			}
		} while (eat);

		/* Free pulled out fragments. */
		while ((list = skb_shinfo(skb)->frag_list) != insp) {
			skb_shinfo(skb)->frag_list = list->next;
			kfree_skb(list);
		}
		/* And insert new clone at head. */
		if (clone) {
			clone->next = list;
			skb_shinfo(skb)->frag_list = clone;
		}
	}
	/* Success! Now we may commit changes to skb data. */

pull_pages:
	eat = delta;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;

	skb->tail     += delta;
	skb->data_len -= delta;

	return skb->tail;
}

/* Copy some data bits from skb to kernel buffer. */

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
	int i, copy;
	int start = skb_headlen(skb);

	if (offset > (int)skb->len - len)
		goto fault;

	/* Copy header. */
	if ((copy = start - offset) > 0) {
		if (copy > len)
			copy = len;
		memcpy(to, skb->data + offset, copy);
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		to     += copy;
	}

#if 0 /* This code is broken and needs to be fixed when we start using it */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		BUG_TRAP(start <= offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;

			memcpy(to, skb_shinfo(skb)->frags[i].page_offset +
			       offset - start, copy);

			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to     += copy;
		}
		start = end;
	}
#endif

	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *list = skb_shinfo(skb)->frag_list;

		for (; list; list = list->next) {
			int end;

			BUG_TRAP(start <= offset + len);

			end = start + list->len;
			if ((copy = end - offset) > 0) {
				if (copy > len)
					copy = len;
				if (skb_copy_bits(list, offset - start,
						  to, copy))
					goto fault;
				if ((len -= copy) == 0)
					return 0;
				offset += copy;
				to     += copy;
			}
			start = end;
		}
	}
	if (!len)
		return 0;

fault:
	return -EFAULT;
}

static void skb_clone_fraglist(struct sk_buff *skb)
{
	struct sk_buff *list;

	for (list = skb_shinfo(skb)->frag_list; list; list = list->next)
		skb_get(list);
}

/**
 *	pskb_expand_head - reallocate header of &sk_buff
 *	@skb: buffer to reallocate
 *	@nhead: room to add at head
 *	@ntail: room to add at tail
 *	@gfp_mask: allocation priority
 *
 *	Expands (or creates identical copy, if &nhead and &ntail are zero)
 *	header of skb. &sk_buff itself is not changed. &sk_buff MUST have
 *	reference count of 1. Returns zero in the case of success or error,
 *	if expansion failed. In the last case, &sk_buff is not changed.
 *
 *	All the pointers pointing into skb header may change and must be
 *	reloaded after call to this function.
 */

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
		     gfp_t gfp_mask)
{
	int i;
	u8 *data;
	int size = nhead + (skb->end - skb->head) + ntail;
	long off;

	if (skb_shared(skb))
		BUG();

	size = SKB_DATA_ALIGN(size);

	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (!data)
		goto nodata;

	/* Copy only real data... and, alas, header. This should be
	 * optimized for the cases when header is void. */
	memcpy(data + nhead, skb->head, skb->tail - skb->head);
	memcpy(data + size, skb->end, sizeof(struct skb_shared_info));

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		get_page(skb_shinfo(skb)->frags[i].page);

	if (skb_shinfo(skb)->frag_list)
		skb_clone_fraglist(skb);

	skb_release_data(skb);

	off = (data + nhead) - skb->head;

	skb->head     = data;
	skb->end      = data + size;
	skb->data    += off;
	skb->tail    += off;
	skb->mac_header += off;
	skb->network_header   += off;
	skb->transport_header  += off;
	skb->cloned   = 0;
	skb->nohdr    = 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return 0;

nodata:
	return -ENOMEM;
}

void put_page(struct page *page)
{
}

static struct proc_dir_entry p;

struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
					 struct proc_dir_entry *parent)
{
	return &p;
}

void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
	return;
}

void init_waitqueue_head(wait_queue_head_t *q)
{
        spin_lock_init(&q->lock);
        INIT_LIST_HEAD(&q->task_list);
}

#ifdef CONFIG_HIGHMEM
void *kmap_atomic(struct page *page, enum km_type type)
{
	return NULL;
}

void kunmap_atomic(void *kvaddr, enum km_type type)
{
}
#endif

void local_bh_enable(void)
{
}

void local_bh_disable(void)
{
}

void *__kzalloc(size_t s, gfp_t flags)
{
	void *p;

	p = malloc(s);
	memset(p, 0, s);
	return p;
}

void *kmemdup(const void *src, size_t len, gfp_t gfp)
{
	void *p;

	p = kmalloc(len, gfp);
	if (p)
		memcpy(p, src, len);
	return p;
}

void *kmem_cache_zalloc(struct kmem_cache *cache, gfp_t flags)
{
	return kzalloc(cache->objsize, flags);
}

unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
	return (j * MSEC_PER_SEC) / HZ;
#endif
}

unsigned long msecs_to_jiffies(const unsigned int m)
{
	if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return m * (HZ / MSEC_PER_SEC);
#else
	return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}

#ifdef CONFIG_DEBUG_LIST
void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

void __list_add(struct list_head *new, struct list_head *prev,
		struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
#endif

#ifdef CONFIG_DEBUG_SPINLOCK

void __spin_lock_init(spinlock_t *lock, const char *name,
		      struct lock_class_key *key)
{
	*lock = SPIN_LOCK_UNLOCKED;
}

void __rwlock_init(rwlock_t *lock, const char *name,
		    struct lock_class_key *key)
{
	*lock = RW_LOCK_UNLOCKED;
}
#endif

struct timeval ns_to_timeval(const s64 nsec)
{
	struct timespec ts = ns_to_timespec(nsec);
	struct timeval tv;

	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = (suseconds_t) ts.tv_nsec / 1000;

	return tv;
}

struct timespec ns_to_timespec(const s64 nsec)
{
        struct timespec ts;

	ts.tv_sec = nsec/NSEC_PER_SEC;
	ts.tv_nsec = nsec%NSEC_PER_SEC;

	return ts;
}

void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
			    struct sk_buff *skb)
{
	/* We never bother setting the timestamp flag in the frame tests */
}

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
void nf_conntrack_destroy(struct nf_conntrack *nfct)
{
	/* do nothing */
}
#endif

int net_ratelimit(void)
{
	return 1;
}

void fastcall lock_sock_nested(struct sock *sk, int subclass)
{
	return;
}
