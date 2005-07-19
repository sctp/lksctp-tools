/* test_kernel.h */

#ifndef __test_kernel_h__

void debug_halt(void);
void freopenk(char *file, char *mode, int fd);
int fprintk(int fd, const char *fmt, ...);

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
