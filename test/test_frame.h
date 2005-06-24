/* SCTP kernel reference Implementation
 * Copyright (c) 1999-2000 Cisco, Inc.
 * Copyright (c) 1999-2001 Motorola, Inc.
 * Copyright (c) 2001-2002 International Business Machines, Corp.
 * Copyright (c) 2001 Intel Corp.
 * 
 * This file is part of the SCTP kernel reference Implementation
 * 
 * $Header: /cvsroot/lksctp/lksctp/test/test_frame.h,v 1.10 2002/07/23 15:58:48 jgrimm Exp $
 * 
 * This header holds things moved out of the kernel header files
 * but needed for the testframe.
 * 
 * The SCTP reference implementation is free software; 
 * you can redistribute it and/or modify it under the terms of 
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * The SCTP reference implementation is distributed in the hope that it 
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
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <sctp-developers-list@cig.mot.com>
 * 
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by: 
 *    La Monte H.P. Yarroll <piggy@acm.org>
 *    Xingang Guo           <xingang.guo@intel.com>
 *    Jon Grimm             <jgrimm@us.ibm.com>
 *    Sridhar Samudrala     <sri@us.ibm.com>
 * 
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#ifndef __test_frame_h__

#undef copy_from_user
#undef copy_to_user
#undef get_user
#undef put_user
#undef access_ok
#undef __set_current_state

#define get_user(x, ptr) ({ x = *ptr; 0; })
#define put_user(x, ptr) ({ *ptr = x; 0; })
#define access_ok(x, y, z) ({1==1;})
#define __set_current_state(x)
#define signal_pending(x) 0

#undef memcpy        
#undef memset
#include <string.h>

static inline void sctp_spin_lock(spinlock_t *lock){ return; }
static inline void sctp_spin_unlock(spinlock_t *lock) { return; }
static inline void sctp_write_lock(rwlock_t *lock){ return; }
static inline void sctp_write_unlock(rwlock_t *lock) { return; }
static inline void sctp_read_lock(rwlock_t *lock){ return; }
static inline void sctp_read_unlock(rwlock_t *lock) { return; }
static inline void sctp_local_bh_disable(void) { return; }
static inline void sctp_local_bh_enable(void) { return; }
static inline void 
sctp_spin_lock_irqsave(spinlock_t *lock, unsigned long flags) { return; }
static inline void 
sctp_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags) { return; }

/* This is the per-socket lock.  The spinlock provides synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 * 
 * Moving here until we use this again.  Right now the locking granularity
 * is at the socket level.  Some day we may want to do association
 * granular locking.  
 */
typedef struct {
	spinlock_t		slock;
	unsigned int		users;
	wait_queue_head_t	wq;

} sctp_lock_t;
extern int ft_sctp_lock_bug;

/* Control level of debugging for the testframe. 
 * 0  - Set the ft_frame_sctp_lock_bug only.
 * 1  - Halt. 
 * 2  - Check a little more stringently and halt.
 */
extern int ft_sctp_lock_assert;

/* Initialize the sctp_lock. */
static inline void sctp_lock_init(sctp_lock_t *lock) 
{ 
	spin_lock_init(&lock->slock); 
	lock->users = 0; 
	return; 

} /* sctp_lock_init() */

/* Acquire the user lock. */
static inline void sctp_lock_acquire(sctp_lock_t *lock) 
{  
	/* Ignore stringent checks. */
	if (ft_sctp_lock_assert != 1) {
		if (spin_is_locked(&lock->slock)) {
			goto error;
		}
	}
	spin_lock(&lock->slock);
	if (lock->users != 0) {
		/* The test frame is single threaded, so until we figure out
		 * a good wait to emulate waitqueues, this is an error. 
		 */
	        goto error_unlock;
	} else {
		lock->users++;
	}
	spin_unlock(&lock->slock);
	return;

error_unlock:
	spin_unlock(&lock->slock);
error:
	if (ft_sctp_lock_assert) {
		BUG();
	}
	ft_sctp_lock_bug=1;
	return;

} /* sctp_lock_acquire() */

/* Release the user lock. */	
static inline void sctp_lock_release(sctp_lock_t *lock) { 
	spin_lock(&lock->slock);
	if (lock->users != 1) {
		/* The test frame is single threaded. */
	        goto error;
	} else {
		lock->users--;
	}
	spin_unlock(&lock->slock);
	
	return;
error:
	spin_unlock(&lock->slock);
	if (ft_sctp_lock_assert) {
		BUG();
	}
	ft_sctp_lock_bug=1;
	return;
	
} /* sctp_lock_release() */

/* Check whether the bh really owns the lock (or else there is 
 * a task in the lock too. The spinlock should be aquired before 
 * this call. 
 */
static inline int sctp_lock_bh_locked(sctp_lock_t *lock) 
{ 
	if (!spin_is_locked(&lock->slock)) {
		printk("The lock must be acquired first.\n");
		goto error;
	} 
	return( lock->users ? 0 : 1);	
       
error:
	if (ft_sctp_lock_assert) {
		BUG();
	}
	ft_sctp_lock_bug = 1;
	return 0;

} /* sctp_lock_bh_locked() */

/* Acquire the lock, BH version. */
static inline void sctp_lock_bh_acquire(sctp_lock_t *lock) 
{
	/* If it is already locked, something is wrong as the testframe
	 * is single threaded.  
	 */
	if (ft_sctp_lock_assert != 1) {
		if (spin_is_locked(&lock->slock)) {
			goto error;
		}
	}
	spin_lock(&lock->slock);
	return;

error:
	if (ft_sctp_lock_assert) {
		BUG();
	}
	ft_sctp_lock_bug = 1;

	return; 

} /* sctp_lock_bh_acquire() */

/* Release the lock, BH version. */
static inline void sctp_lock_bh_release(sctp_lock_t *lock) { 

	/* If the lock is not held, we have a mismatch.
	 */

	if (!spin_is_locked(&lock->slock)) {
		goto error;
	}

	spin_unlock(&lock->slock);
	return;

error:
	if (ft_sctp_lock_assert) {
		BUG();
	}
	ft_sctp_lock_bug = 1;
	return; 

} /* sctp_lock_bh_release() */


/* Determine if this is a valid kernel address.
 */
static inline int 
sctp_is_valid_kaddr(unsigned long addr) 
{
	return(addr && (addr < PAGE_OFFSET));

} /* sctp_is_valid_kaddr() */


#define sctp_lock_sock(sk) do {} while(0)
#define sctp_release_sock(sk) do {} while(0)
#define sctp_bh_lock_sock(sk) do {} while(0)
#define sctp_bh_unlock_sock(sk)  do {} while(0)
#define __sctp_sock_busy(sk) 0 
#define SCTP_SOCK_SLEEP_PRE(sk)
#define SCTP_SOCK_SLEEP_POST(sk)



#if 0 /* FIXME Discourage use until locking gets decided. */
#define sctp_lock_asoc(__asoc) do {} while(0)
#define sctp_release_asoc(__asoc)  do {} while(0)
#endif /* 0 */

#define sctp_bh_lock_asoc(__asoc) do {} while(0)
#define sctp_bh_unlock_asoc(__asoc)  do {} while(0)

/* 
 * sctp_protocol.c 
 */
int sctp_init(void);
void sctp_exit(void);

/*
 * sctp_socket.c 
 */
int sctp_bind(struct sock *, struct sockaddr *, int);
int sctp_bindx(struct sock *, struct sockaddr_storage *, int, int);
int sctp_connect(struct sock *, struct sockaddr *, int);
void sctp_close(struct sock *, long);
int sctp_recvmsg(struct kiocb *, struct sock *, struct msghdr *, size_t, int,
		 int, int *);
int sctp_sendmsg(struct kiocb *, struct sock *, struct msghdr *, size_t);
int sctp_setsockopt(struct sock *, int, int, char *, int);
int sctp_getsockopt(struct sock *, int, int, char *, int *);
int sctp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int sctp_disconnect(struct sock *sk, int flags);
struct sock *sctp_accept(struct sock *sk, int flags, int *err);
int sctp_ioctl(struct sock *sk, int cmd, unsigned long arg);
int sctp_init_sock(struct sock *sk);
int sctp_destroy_sock(struct sock *sk);
void sctp_shutdown(struct sock *sk, int how);
int sctp_seqpacket_listen(struct sock *sk, int backlog);
int sctp_stream_listen(struct sock *sk, int backlog);
int sctp_do_peeloff(struct sctp_association *, struct socket **);

#undef IP_INC_STATS_BH
#define IP_INC_STATS_BH(x)

#undef NET_INC_STATS_BH
#define NET_INC_STATS_BH(x)

#undef ICMP_INC_STATS_BH
#define ICMP_INC_STATS_BH(x)

#undef SCTP_INC_STATS
#define SCTP_INC_STATS(x)

#undef SCTP_INC_STATS_BH
#define SCTP_INC_STATS_BH(x)

#undef SCTP_INC_STATS_USER
#define SCTP_INC_STATS_USER(x)

#undef SCTP_DEC_STATS
#define SCTP_DEC_STATS(x)

DECLARE_SNMP_STAT(struct sctp_mib, sctp_statistics);
#endif /* __test_frame_h__ */
