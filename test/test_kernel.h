/* test_kernel.h */

#ifndef __test_kernel_h__

void debug_halt(void);
void freopenk(char *file, char *mode, int fd);
int fprintk(int fd, const char *fmt, ...);

/* We borrow slightly modified functions from skbuff.h for testing.  */
void			__kfree_skb(struct sk_buff *skb);
void			skb_queue_head_init(struct sk_buff_head *list);
void			skb_queue_head(struct sk_buff_head *list,struct sk_buff *buf);
void			skb_queue_tail(struct sk_buff_head *list,struct sk_buff *buf);
struct sk_buff *		skb_dequeue(struct sk_buff_head *list);
void 			skb_insert(struct sk_buff *old,struct sk_buff *newsk);
void			skb_append(struct sk_buff *old,struct sk_buff *newsk);
void			skb_unlink(struct sk_buff *buf);
__u32			skb_queue_len(const struct sk_buff_head *list);
struct sk_buff *		skb_peek_copy(struct sk_buff_head *list);
struct sk_buff *		alloc_skb(unsigned int size, int priority);
struct sk_buff *		dev_alloc_skb(unsigned int size);
void			kfree_skbmem(struct sk_buff *skb);
struct sk_buff *	skb_clone(struct sk_buff *skb, int priority);
struct sk_buff *	skb_copy(const struct sk_buff *skb, int priority);

#define dev_kfree_skb(a)	kfree_skb(a)

unsigned char *		skb_put(struct sk_buff *skb, unsigned int len);
unsigned char *		skb_push(struct sk_buff *skb, unsigned int len);
unsigned char *		skb_pull(struct sk_buff *skb, unsigned int len);
int			skb_headroom(const struct sk_buff *skb);
int			skb_tailroom(const struct sk_buff *skb);
void			skb_reserve(struct sk_buff *skb, unsigned int len);
void 			skb_trim(struct sk_buff *skb, unsigned int len);
void	skb_over_panic(struct sk_buff *skb, int len, void *here);
void	skb_under_panic(struct sk_buff *skb, int len, void *here);


#if 0
__inline__ void kfree_skb(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users))
		__kfree_skb(skb);
}

/* Use this if you didn't touch the skb state [for fast switching] */
__inline__ void kfree_skb_fast(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users))
		kfree_skbmem(skb);	
}
#endif /* 0 */

/*
 *	Copy shared buffers into a new sk_buff. We effectively do COW on
 *	packets to handle cases where we have a local reader and forward
 *	and a couple of other messy ones. The normal one is tcpdumping
 *	a packet thats being forwarded.
 */
 
#if 0
__inline__ struct sk_buff *skb_unshare(struct sk_buff *skb, int pri)
{
	struct sk_buff *nskb;
	if(!skb_cloned(skb))
		return skb;
	nskb=skb_copy(skb, pri);
	kfree_skb(skb);		/* Free our shared copy */
	return nskb;
}
#endif /* 0 */


void skb_init(void);
void skb_add_mtu(int mtu);


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
void sctp_hash(struct sock *sk);
void sctp_unhash(struct sock *sk);
int sctp_seqpacket_listen(struct sock *sk, int backlog);
int sctp_do_peeloff(struct sctp_association *, struct socket **);

/* sctp_endpointola.c */
void sctp_endpoint_destroy(struct sctp_endpoint *ep);

#endif /* __test_kernel_h__ */
