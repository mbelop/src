/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2008,2010
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart, James
 * Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>

void	newreno_ack_received(struct tcp_ccvar *ccv, uint16_t type);
void	newreno_after_idle(struct tcp_ccvar *ccv);
void	newreno_cong_signal(struct tcp_ccvar *ccv, uint32_t type);
void	newreno_post_recovery(struct tcp_ccvar *ccv);

struct tcp_cc tcp_newreno_cc = {
	.name		= "newreno",
	.ack_received	= newreno_ack_received,
	.after_idle	= newreno_after_idle,
	.cong_signal	= newreno_cong_signal,
	.post_recovery	= newreno_post_recovery,
};

void
newreno_ack_received(struct tcp_ccvar *ccv, uint16_t type)
{
	struct tcpcb *tp = ccv->tp;

	if (type == CC_ACK && !IN_RECOVERY(tp) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
		u_int cw = tp->snd_cwnd;
		u_int incr = tp->t_maxseg;

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_limit * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > tp->snd_ssthresh) {
			if (tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = MAX((incr * incr / cw), 1);
		} else if (tcp_do_rfc3465) {
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_limit > 1 if slow starting after
			 * an RTO. On RTO, snd_nxt = snd_una, so the
			 * snd_nxt == snd_max check is sufficient to
			 * handle this).
			 *
			 * XXXLAS: Find a way to signal SS after RTO that
			 * doesn't rely on tcpcb vars.
			 */
			incr = MIN(ccv->bytes_this_ack, tp->t_maxseg *
			    ((tp->snd_nxt == tp->snd_max) ? tcp_abc_limit : 1));
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			tp->snd_cwnd = MIN(cw + incr,
			    (u_int)TCP_MAXWIN << tp->snd_scale);
	}
}

void
newreno_after_idle(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;
	u_int rw;

	/*
	 * If we've been idle for more than one retransmit timeout the old
	 * congestion window is no longer current and we have to reduce it to
	 * the restart window before we can transmit again.
	 *
	 * The restart window is the initial window or the last CWND, whichever
	 * is smaller.
	 *
	 * This is done to prevent us from flooding the path with a full CWND at
	 * wirespeed, overloading router and switch buffers along the way.
	 *
	 * See RFC5681 Section 4.1. "Restarting Idle Connections".
	 */
	if (tcp_do_rfc3390)
		rw = MIN(4 * tp->t_maxseg, MAX(2 * tp->t_maxseg, 4380));
	else
		rw = tp->t_maxseg * 2;

	tp->snd_cwnd = MIN(rw, tp->snd_cwnd);
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
void
newreno_cong_signal(struct tcp_ccvar *ccv, uint32_t type)
{
	struct tcpcb *tp = ccv->tp;
	u_int win;

	/* Catch algos which mistakenly leak private signal types. */
	if ((type & CC_SIGPRIVMASK) != 0)
		panic("congestion signal type %#x is private", type);

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(tp)) {
			if (!IN_CONGRECOVERY(tp)) {
				win = MAX(tp->snd_cwnd / 2 / tp->t_maxseg, 2) *
				    tp->t_maxseg;
				tp->snd_ssthresh = win;
			}
			ENTER_RECOVERY(tp);
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(tp)) {
			win = MAX(tp->snd_cwnd / 2 / tp->t_maxseg, 2) *
			    tp->t_maxseg;
			tp->snd_ssthresh = win;
			tp->snd_cwnd = win;
			ENTER_CONGRECOVERY(tp);
		}
		break;
	}
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
void
newreno_post_recovery(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;

	if (IN_FASTRECOVERY(tp)) {
		/*
		 * Fast recovery will conclude after returning from this
		 * function. Window inflation should have left us with
		 * approximately snd_ssthresh outstanding data. But in case we
		 * would be inclined to send a burst, better to do it via the
		 * slow start mechanism.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		if (tcp_seq_subtract(tp->snd_max, ccv->curack) <
		    tp->snd_ssthresh)
			tp->snd_cwnd =
			    tcp_seq_subtract(tp->snd_max, ccv->curack) +
			    tp->t_maxseg;
		else
			tp->snd_cwnd = tp->snd_ssthresh;
	}
}
