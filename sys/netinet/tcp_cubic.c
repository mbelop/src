/*-
 * Copyright (c) 2008-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Lawrence Stewart while studying at the Centre
 * for Advanced Internet Architectures, Swinburne University of Technology, made
 * possible in part by a grant from the Cisco University Research Program Fund
 * at Community Foundation Silicon Valley.
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
 * An implementation of the CUBIC congestion control algorithm for FreeBSD,
 * based on the Internet Draft "draft-rhee-tcpm-cubic-02" by Rhee, Xu and Ha.
 * Originally released as part of the NewTCP research project at Swinburne
 * University of Technology's Centre for Advanced Internet Architectures,
 * Melbourne, Australia, which was made possible in part by a grant from the
 * Cisco University Research Program Fund at Community Foundation Silicon
 * Valley. More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/pool.h>
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

/* Number of bits of precision for fixed point math calcs. */
#define	CUBIC_SHIFT		8

#define	CUBIC_SHIFT_4		32

/* 0.5 << CUBIC_SHIFT. */
#define	RENO_BETA		128

/* ~0.8 << CUBIC_SHIFT. */
#define	CUBIC_BETA		204

/* ~0.2 << CUBIC_SHIFT. */
#define	ONE_SUB_CUBIC_BETA	51

/* 3 * ONE_SUB_CUBIC_BETA. */
#define	THREE_X_PT2		153

/* (2 << CUBIC_SHIFT) - ONE_SUB_CUBIC_BETA. */
#define	TWO_SUB_PT2		461

/* ~0.4 << CUBIC_SHIFT. */
#define	CUBIC_C_FACTOR		102

/* CUBIC fast convergence factor: ~0.9 << CUBIC_SHIFT. */
#define	CUBIC_FC_FACTOR		230

/* Don't trust s_rtt until this many rtt samples have been taken. */
#define	CUBIC_MIN_RTT_SAMPLES	8

struct pool cubic_pl;

/*
 * Compute the CUBIC K value used in the cwnd calculation, using an
 * implementation of eqn 2 in the I-D. The method used
 * here is adapted from Apple Computer Technical Report #KT-32.
 */
static inline int64_t
cubic_k(unsigned long wmax_pkts)
{
	int64_t s, K;
	uint16_t p;

	K = s = 0;
	p = 0;

	/* (wmax * beta)/C with CUBIC_SHIFT worth of precision. */
	s = ((wmax_pkts * ONE_SUB_CUBIC_BETA) << CUBIC_SHIFT) / CUBIC_C_FACTOR;

	/* Rebase s to be between 1 and 1/8 with a shift of CUBIC_SHIFT. */
	while (s >= 256) {
		s >>= 3;
		p++;
	}

	/*
	 * Some magic constants taken from the Apple TR with appropriate
	 * shifts: 275 == 1.072302 << CUBIC_SHIFT, 98 == 0.3812513 <<
	 * CUBIC_SHIFT, 120 == 0.46946116 << CUBIC_SHIFT.
	 */
	K = (((s * 275) >> CUBIC_SHIFT) + 98) -
	    (((s * s * 120) >> CUBIC_SHIFT) >> CUBIC_SHIFT);

	/* Multiply by 2^p to undo the rebasing of s from above. */
	return (K <<= p);
}

/*
 * Compute the new cwnd value using an implementation of eqn 1 from the I-D.
 * Thanks to Kip Macy for help debugging this function.
 *
 * XXXLAS: Characterise bounds for overflow.
 */
static inline unsigned long
cubic_cwnd(int ticks_since_cong, unsigned long wmax, uint32_t smss, int64_t K)
{
	int64_t cwnd;

	/* K is in fixed point form with CUBIC_SHIFT worth of precision. */

	/* t - K, with CUBIC_SHIFT worth of precision. */
	cwnd = ((int64_t)(ticks_since_cong << CUBIC_SHIFT) - (K * hz)) / hz;

	/* (t - K)^3, with CUBIC_SHIFT^3 worth of precision. */
	cwnd *= (cwnd * cwnd);

	/*
	 * C(t - K)^3 + wmax
	 * The down shift by CUBIC_SHIFT_4 is because cwnd has 4 lots of
	 * CUBIC_SHIFT included in the value. 3 from the cubing of cwnd above,
	 * and an extra from multiplying through by CUBIC_C_FACTOR.
	 */
	cwnd = ((cwnd * CUBIC_C_FACTOR * smss) >> CUBIC_SHIFT_4) + wmax;

	return ((unsigned long)cwnd);
}

/*
 * Compute an approximation of the "TCP friendly" cwnd some number of ticks
 * after a congestion event that is designed to yield the same average cwnd as
 * NewReno while using CUBIC's beta of 0.8. RTT should be the average RTT
 * estimate for the path measured over the previous congestion epoch and wmax is
 * the value of cwnd at the last congestion event.
 */
static inline unsigned long
tf_cwnd(int ticks_since_cong, int rtt_ticks, unsigned long wmax,
    uint32_t smss)
{

	/* Equation 4 of I-D. */
	return (((wmax * CUBIC_BETA) + (((THREE_X_PT2 * ticks_since_cong *
	    smss) << CUBIC_SHIFT) / TWO_SUB_PT2 / rtt_ticks)) >> CUBIC_SHIFT);
}

int	cubic_init(void);
void	cubic_ack_received(struct tcp_ccvar *ccv, uint16_t type);
void	cubic_cb_destroy(struct tcp_ccvar *ccv);
int	cubic_cb_init(struct tcp_ccvar *ccv);
void	cubic_cong_signal(struct tcp_ccvar *ccv, uint32_t type);
void	cubic_conn_init(struct tcp_ccvar *ccv);
void	cubic_post_recovery(struct tcp_ccvar *ccv);
void	cubic_record_rtt(struct tcp_ccvar *ccv);
void	cubic_ssthresh_update(struct tcp_ccvar *ccv);

struct cubic {
	/* Cubic K in fixed point form with CUBIC_SHIFT worth of precision. */
	int64_t		K;
	/* Sum of RTT samples across an epoch in ticks. */
	int64_t		sum_rtt_ticks;
	/* cwnd at the most recent congestion event. */
	unsigned long	max_cwnd;
	/* cwnd at the previous congestion event. */
	unsigned long	prev_max_cwnd;
	/* Number of congestion events. */
	uint32_t	num_cong_events;
	/* Minimum observed rtt in ticks. */
	int		min_rtt_ticks;
	/* Mean observed rtt between congestion epochs. */
	int		mean_rtt_ticks;
	/* ACKs since last congestion event. */
	int		epoch_ack_count;
	/* Time of last congestion event in ticks. */
	int		t_last_cong;
};

struct tcp_cc tcp_cubic_cc = {
	.name		= "cubic",
	.init		= cubic_init,
	.ack_received	= cubic_ack_received,
	.cb_destroy	= cubic_cb_destroy,
	.cb_init	= cubic_cb_init,
	.cong_signal	= cubic_cong_signal,
	.conn_init	= cubic_conn_init,
	.post_recovery	= cubic_post_recovery,
};

int
cubic_init(void)
{
	tcp_cubic_cc.after_idle = tcp_newreno_cc.after_idle;
	pool_init(&cubic_pl, sizeof(struct cubic), 0, IPL_SOFTNET, 0,
	    "cubicpl", NULL);
	return (0);
}

void
cubic_ack_received(struct tcp_ccvar *ccv, uint16_t type)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;
	unsigned long w_tf, w_cubic_next;
	int ticks_since_cong;

	cubic_data = ccv->cc_data;
	cubic_record_rtt(ccv);

	/*
	 * Regular ACK and we're not in cong/fast recovery and we're cwnd
	 * limited and we're either not doing ABC or are slow starting or are
	 * doing ABC and we've sent a cwnd's worth of bytes.
	 */
	if (type == CC_ACK && !IN_RECOVERY(tp) &&
	    (ccv->flags & CCF_CWND_LIMITED) && (!tcp_do_rfc3465 ||
	    tp->snd_cwnd <= tp->snd_ssthresh ||
	    (tcp_do_rfc3465 && ccv->flags & CCF_ABC_SENTAWND))) {
		 /* Use the logic in NewReno ack_received() for slow start. */
		if (tp->snd_cwnd <= tp->snd_ssthresh ||
		    cubic_data->min_rtt_ticks == TCPTV_SRTTBASE)
			tcp_newreno_cc.ack_received(ccv, type);
		else {
			ticks_since_cong = tcp_now - cubic_data->t_last_cong;

			/*
			 * The mean RTT is used to best reflect the equations in
			 * the I-D. Using min_rtt in the tf_cwnd calculation
			 * causes w_tf to grow much faster than it should if the
			 * RTT is dominated by network buffering rather than
			 * propagation delay.
			 */
			w_tf = tf_cwnd(ticks_since_cong,
			    cubic_data->mean_rtt_ticks, cubic_data->max_cwnd,
			    tp->t_maxseg);

			w_cubic_next = cubic_cwnd(ticks_since_cong +
			    cubic_data->mean_rtt_ticks, cubic_data->max_cwnd,
			    tp->t_maxseg, cubic_data->K);

			ccv->flags &= ~CCF_ABC_SENTAWND;

			if (w_cubic_next < w_tf)
				/*
				 * TCP-friendly region, follow tf
				 * cwnd growth.
				 */
				tp->snd_cwnd = w_tf;

			else if (tp->snd_cwnd < w_cubic_next) {
				/*
				 * Concave or convex region, follow CUBIC
				 * cwnd growth.
				 */
				if (tcp_do_rfc3465)
					tp->snd_cwnd = w_cubic_next;
				else
					tp->snd_cwnd += ((w_cubic_next -
					    tp->snd_cwnd) *
					    tp->t_maxseg) /
					    tp->snd_cwnd;
			}

			/*
			 * If we're not in slow start and we're probing for a
			 * new cwnd limit at the start of a connection
			 * (happens when hostcache has a relevant entry),
			 * keep updating our current estimate of the
			 * max_cwnd.
			 */
			if (cubic_data->num_cong_events == 0 &&
			    cubic_data->max_cwnd < tp->snd_cwnd)
				cubic_data->max_cwnd = tp->snd_cwnd;
		}
	}
}

void
cubic_cb_destroy(struct tcp_ccvar *ccv)
{

	if (ccv->cc_data != NULL)
		pool_put(&cubic_pl, ccv->cc_data);
}

int
cubic_cb_init(struct tcp_ccvar *ccv)
{
	struct cubic *cubic_data;

	cubic_data = pool_get(&cubic_pl, PR_NOWAIT | PR_ZERO);
	if (cubic_data == NULL)
		return (ENOMEM);

	/* Init some key variables with sensible defaults. */
	cubic_data->t_last_cong = tcp_now;
	cubic_data->min_rtt_ticks = TCPTV_SRTTBASE;
	cubic_data->mean_rtt_ticks = 1;

	ccv->cc_data = cubic_data;

	return (0);
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
void
cubic_cong_signal(struct tcp_ccvar *ccv, uint32_t type)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(tp)) {
			if (!IN_CONGRECOVERY(tp)) {
				cubic_ssthresh_update(ccv);
				cubic_data->num_cong_events++;
				cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
				cubic_data->max_cwnd = tp->snd_cwnd;
			}
			ENTER_RECOVERY(tp);
		}
		break;

	case CC_ECN:
		if (!IN_CONGRECOVERY(tp)) {
			cubic_ssthresh_update(ccv);
			cubic_data->num_cong_events++;
			cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
			cubic_data->max_cwnd = tp->snd_cwnd;
			cubic_data->t_last_cong = tcp_now;
			tp->snd_cwnd = tp->snd_ssthresh;
			ENTER_CONGRECOVERY(tp);
		}
		break;

	case CC_RTO:
		/*
		 * Grab the current time and record it so we know when the
		 * most recent congestion event was. Only record it when the
		 * timeout has fired more than once, as there is a reasonable
		 * chance the first one is a false alarm and may not indicate
		 * congestion.
		 */
		if (tp->t_rxtshift >= 2) {
			cubic_data->num_cong_events++;
			cubic_data->t_last_cong = tcp_now;
		}
		break;
	}
}

void
cubic_conn_init(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * Ensure we have a sane initial value for max_cwnd recorded. Without
	 * this here bad things happen when entries from the TCP hostcache
	 * get used.
	 */
	cubic_data->max_cwnd = tp->snd_cwnd;
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
void
cubic_post_recovery(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/* Fast convergence heuristic. */
	if (cubic_data->max_cwnd < cubic_data->prev_max_cwnd)
		cubic_data->max_cwnd = (cubic_data->max_cwnd * CUBIC_FC_FACTOR)
		    >> CUBIC_SHIFT;

	if (IN_FASTRECOVERY(tp)) {
		/*
		 * If inflight data is less than ssthresh, set cwnd
		 * conservatively to avoid a burst of data, as suggested in
		 * the NewReno RFC. Otherwise, use the CUBIC method.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		if (tcp_seq_subtract(tp->snd_max, ccv->curack) <
		    tp->snd_ssthresh)
			tp->snd_cwnd =
			    tcp_seq_subtract(tp->snd_max, ccv->curack) +
			    tp->t_maxseg;
		else
			/* Update cwnd based on beta and adjusted max_cwnd. */
			tp->snd_cwnd = max(1, ((CUBIC_BETA *
			    cubic_data->max_cwnd) >> CUBIC_SHIFT));
	}
	cubic_data->t_last_cong = tcp_now;

	/* Calculate the average RTT between congestion epochs. */
	if (cubic_data->epoch_ack_count > 0 &&
	    cubic_data->sum_rtt_ticks >= cubic_data->epoch_ack_count) {
		cubic_data->mean_rtt_ticks = (int)(cubic_data->sum_rtt_ticks /
		    cubic_data->epoch_ack_count);
	}

	cubic_data->epoch_ack_count = 0;
	cubic_data->sum_rtt_ticks = 0;
	cubic_data->K = cubic_k(cubic_data->max_cwnd / tp->t_maxseg);
}

/*
 * Record the min RTT and sum samples for the epoch average RTT calculation.
 */
void
cubic_record_rtt(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;
	int t_srtt_ticks;

	/* Ignore srtt until a min number of samples have been taken. */
	if (tp->t_rttupdated >= CUBIC_MIN_RTT_SAMPLES) {
		cubic_data = ccv->cc_data;
		t_srtt_ticks = tp->t_srtt >> TCP_RTT_SHIFT;

		/*
		 * Record the current SRTT as our minrtt if it's the smallest
		 * we've seen or minrtt is currently equal to its initialised
		 * value.
		 *
		 * XXXLAS: Should there be some hysteresis for minrtt?
		 */
		if ((t_srtt_ticks < cubic_data->min_rtt_ticks ||
		    cubic_data->min_rtt_ticks == TCPTV_SRTTBASE)) {
			cubic_data->min_rtt_ticks = max(1, t_srtt_ticks);

			/*
			 * If the connection is within its first congestion
			 * epoch, ensure we prime mean_rtt_ticks with a
			 * reasonable value until the epoch average RTT is
			 * calculated in cubic_post_recovery().
			 */
			if (cubic_data->min_rtt_ticks >
			    cubic_data->mean_rtt_ticks)
				cubic_data->mean_rtt_ticks =
				    cubic_data->min_rtt_ticks;
		}

		/* Sum samples for epoch average RTT calculation. */
		cubic_data->sum_rtt_ticks += t_srtt_ticks;
		cubic_data->epoch_ack_count++;
	}
}

/*
 * Update the ssthresh in the event of congestion.
 */
void
cubic_ssthresh_update(struct tcp_ccvar *ccv)
{
	struct tcpcb *tp = ccv->tp;
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * On the first congestion event, set ssthresh to cwnd * 0.5, on
	 * subsequent congestion events, set it to cwnd * beta.
	 */
	if (cubic_data->num_cong_events == 0)
		tp->snd_ssthresh = tp->snd_cwnd >> 1;
	else
		tp->snd_ssthresh = ((u_long)tp->snd_cwnd *
		    CUBIC_BETA) >> CUBIC_SHIFT;
}
