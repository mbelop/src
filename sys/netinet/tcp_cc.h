#ifndef _TCP_CC_H_
#define _TCP_CC_H_

void	tcp_cc_init_connection(struct tcpcb *);
void	tcp_cc_ack_received(struct tcpcb *, struct tcphdr *);
#ifdef TCP_ECN
int	tcp_cc_cong_experienced(struct tcpcb *);
#endif
void	tcp_cc_enter_fastrecovery(struct tcpcb *, struct tcphdr *);
void	tcp_cc_exit_fastrecovery(struct tcpcb *, struct tcphdr *);
void	tcp_cc_after_idle(struct tcpcb *);

#endif	/* _TCP_CC_H_ */
