#ifndef __sctp_darn_h__
#define __sctp_darn_h__

#define REALLY_BIG 65536
#define SCTP_TESTPORT_1 1
#define SCTP_TESTPORT_2 2

void parse_arguments(int argc, char *argv[]);
void usage(char *argv0);
int command_listen(char *arg0, int sk);
int command_send(char *arg0,   int *skp);
int command_poll(char *arg0);
int test_print_message(int sk, struct msghdr *, size_t msg_len);

typedef enum {
	COMMAND_NONE = 0,
	COMMAND_LISTEN,
	COMMAND_SEND,
	COMMAND_POLL,
} command_t;

typedef union {
	struct sockaddr_storage ss;
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
        struct sockaddr sa;
} sockaddr_storage_t;

#endif /* __sctp_darn_h__ */
