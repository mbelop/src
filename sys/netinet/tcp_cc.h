#ifndef _TCP_CC_H_
#define _TCP_CC_H_

enum {
	TCP_CC_CWND_INIT		= 1,
	TCP_CC_CWND_PMTU_SHRINK		= 2,
	TCP_CC_ACK_RECEIVED		= 3,
	TCP_CC_ECN_RECEIVED		= 4,
	TCP_CC_CONG_EXPERIENCED		= 5,
	TCP_CC_PARTIAL_ACK		= 6,
	TCP_CC_ENTER_FASTRECOVERY	= 7,
	TCP_CC_IN_FASTRECOVERY		= 8,
	TCP_CC_EXIT_FASTRECOVERY	= 9,
	TCP_CC_IDLE_TIMEOUT		= 10
};

void	tcp_cc_trace(struct tcpcb *, struct tcphdr *, int);

void	tcp_cc_init_connection(struct tcpcb *);
void	tcp_cc_ack_received(struct tcpcb *, struct tcphdr *);
#ifdef TCP_ECN
int	tcp_cc_cong_experienced(struct tcpcb *);
#endif
void	tcp_cc_enter_fastrecovery(struct tcpcb *, struct tcphdr *);
void	tcp_cc_exit_fastrecovery(struct tcpcb *, struct tcphdr *);
void	tcp_cc_after_idle(struct tcpcb *);

#endif	/* _TCP_CC_H_ */
