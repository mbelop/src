/*-
 * Copyright (c) 2007-2008
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>

/* XXX */

SLIST_HEAD(, tcp_cc) tcp_cc_list = SLIST_HEAD_INITIALIZER(tcp_cc_list);

struct tcp_cc *tcp_default_cc = &tcp_newreno_cc;

/*
 * Initialise CC subsystem on system boot.
 */
void
cc_init(void)
{
#ifdef TCP_CUBIC
	extern struct tcp_cc tcp_cubic_cc;
	if (tcp_cubic_cc.init() == 0)
		SLIST_INSERT_HEAD(&tcp_cc_list, &tcp_cubic_cc, entries);
#endif
	SLIST_INSERT_HEAD(&tcp_cc_list, &tcp_newreno_cc, entries);
}

/*
 * CC wrapper hook functions
 */
void
cc_ack_received(struct tcpcb *tp, struct tcphdr *th, uint16_t type)
{
	tp->t_ccvar.bytes_this_ack = th->th_ack - tp->snd_una;
	if (tp->snd_cwnd <= tp->snd_wnd)
		tp->t_ccvar.flags |= CCF_CWND_LIMITED;
	else
		tp->t_ccvar.flags &= ~CCF_CWND_LIMITED;

	if (type == CC_ACK) {
		if (tp->snd_cwnd > tp->snd_ssthresh) {
			tp->t_bytes_acked += min(tp->t_ccvar.bytes_this_ack,
			     tcp_abc_limit * tp->t_maxseg);
			if (tp->t_bytes_acked >= tp->snd_cwnd) {
				tp->t_bytes_acked -= tp->snd_cwnd;
				tp->t_ccvar.flags |= CCF_ABC_SENTAWND;
			}
		} else {
				tp->t_ccvar.flags &= ~CCF_ABC_SENTAWND;
				tp->t_bytes_acked = 0;
		}
	}

	if (tp->t_ccalg->ack_received != NULL) {
		/* XXXLAS: Find a way to live without this */
		tp->t_ccvar.curack = th->th_ack;
		tp->t_ccalg->ack_received(&tp->t_ccvar, type);
	}
}

void
cc_conn_init(struct tcpcb *tp)
{
	u_int maxseg;

	maxseg = tp->t_maxseg;

	/*
	 * Set the initial slow-start flight size.
	 *
	 * RFC5681 Section 3.1 specifies the default conservative values.
	 * RFC3390 specifies slightly more aggressive values.
	 * RFC6928 increases it to ten segments.
	 * Support for user specified value for initial flight size.
	 *
	 * If a SYN or SYN/ACK was lost and retransmitted, we have to
	 * reduce the initial CWND to one segment as congestion is likely
	 * requiring us to be cautious.
	 */
	if (tp->snd_cwnd == 1)
		tp->snd_cwnd = maxseg;		/* SYN(-ACK) lost */
	else if (tcp_do_rfc3390 == 2) {
		/* increase initial window  */
		tp->snd_cwnd = ulmin(10 * maxseg, ulmax(2 * maxseg, 14600));
	} else if (tcp_do_rfc3390) {
		/* increase initial window  */
		tp->snd_cwnd = ulmin(4 * maxseg, ulmax(2 * maxseg, 4380));
	} else {
		/* Per RFC5681 Section 3.1 */
		if (maxseg > 2190)
			tp->snd_cwnd = 2 * maxseg;
		else if (maxseg > 1095)
			tp->snd_cwnd = 3 * maxseg;
		else
			tp->snd_cwnd = 4 * maxseg;
	}

	if (tp->t_ccalg->conn_init != NULL)
		tp->t_ccalg->conn_init(&tp->t_ccvar);
}

void
cc_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type)
{
	u_int maxseg;

	switch(type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(tp)) {
#ifdef TCP_SACK
			if (tp->sack_enable)
				tp->snd_last = tp->snd_max;
#endif
#ifdef TCP_ECN
			if (tp->t_flags & TF_ECN_PERMIT)
				tp->t_flags |= TF_SEND_CWR;
#endif
		}
		break;
#ifdef TCP_ECN
	case CC_ECN:
		if (!IN_CONGRECOVERY(tp)) {
			/* tcpstat_inc(tcps_ecn_rcwnd); */
			tcpstat_inc(tcps_cwr_ecn);
#ifdef TCP_SACK
			if (tp->sack_enable)
				tp->snd_last = tp->snd_max;
#endif
			if (tp->t_flags & TF_ECN_PERMIT)
				tp->t_flags |= TF_SEND_CWR;
		}
		break;
#endif
	case CC_RTO:
		maxseg = tp->t_maxseg;
		tp->t_dupacks = 0;
		tp->t_bytes_acked = 0;
		EXIT_RECOVERY(tp);
		tp->snd_ssthresh = max(2, min(tp->snd_wnd, tp->snd_cwnd) / 2 /
		    maxseg) * maxseg;
		tp->snd_cwnd = maxseg;
		break;
	case CC_RTO_ERR:
		/* tcpstat_inc(tcps_sndrexmitbad); */
		/* RTO was unnecessary, so reset everything. */
		tp->snd_cwnd = tp->snd_cwnd_prev;
		tp->snd_ssthresh = tp->snd_ssthresh_prev;
		tp->snd_last = tp->snd_last_prev;
		if (tp->t_flags & TF_WASFRECOVERY)
			ENTER_FASTRECOVERY(tp);
		if (tp->t_flags & TF_WASCRECOVERY)
			ENTER_CONGRECOVERY(tp);
		tp->snd_nxt = tp->snd_max;
		tp->t_flags &= ~TF_PREVVALID;
		tp->t_badrxtwin = 0;
		break;
	}

	if (tp->t_ccalg->cong_signal != NULL) {
		if (th != NULL)
			tp->t_ccvar.curack = th->th_ack;
		tp->t_ccalg->cong_signal(&tp->t_ccvar, type);
	}
}

void
cc_post_recovery(struct tcpcb *tp, struct tcphdr *th)
{
	/* XXXLAS: KASSERT that we're in recovery? */

	if (tp->t_ccalg->post_recovery != NULL) {
		tp->t_ccvar.curack = th->th_ack;
		tp->t_ccalg->post_recovery(&tp->t_ccvar);
	}
	/* XXXLAS: EXIT_RECOVERY ? */
	tp->t_bytes_acked = 0;
}

void
cc_after_idle(struct tcpcb *tp)
{
	if (tp->t_ccalg->after_idle != NULL)
		tp->t_ccalg->after_idle(&tp->t_ccvar);
}
