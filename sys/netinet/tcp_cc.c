/*	$OpenBSD$	*/
/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)COPYRIGHT	1.1 (NRL) 17 January 1995
 *
 * NRL grants permission for redistribution and use in source and binary
 * forms, with or without modification, of the software and documentation
 * created at NRL provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgements:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 *	This product includes software developed at the Information
 *	Technology Division, US Naval Research Laboratory.
 * 4. Neither the name of the NRL nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THE SOFTWARE PROVIDED BY NRL IS PROVIDED BY NRL AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NRL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of the US Naval
 * Research Laboratory (NRL).
 */

#define TCP_DEBUG

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#ifdef TCP_DEBUG
#include <lib/libkern/libkern.h>
#endif

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>

extern int tcprexmtthresh;

#ifdef TCP_DEBUG
void
tcp_cc_trace(struct tcpcb *tp, struct tcphdr *th, int event)
{
	struct inpcb *inp = tp->t_inpcb;
	char daddr[INET6_ADDRSTRLEN], saddr[INET6_ADDRSTRLEN];
	ushort dport, sport;
	struct timeval tv;
	uint64_t tstamp;

	getmicrouptime(&tv);
	tstamp = tv.tv_sec * 1000000 + tv.tv_usec;

	if (inp->inp_flags & INP_IPV6) {
		inet_ntop(AF_INET6, (void *)&inp->inp_faddr6, daddr,
		    INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *)&inp->inp_laddr6, saddr,
		    INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, (void *)&inp->inp_faddr.s_addr, daddr,
		    INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *)&inp->inp_laddr.s_addr, saddr,
		    INET6_ADDRSTRLEN);
	}
	dport = ntohs(inp->inp_fport);
	sport = ntohs(inp->inp_lport);

	log(LOG_DEBUG, "%llu: %s:%u -> %s:%u state %s event %d\n",
	    tstamp, saddr, sport, daddr, dport, tcpstates[tp->t_state], event);
	addlog("\trcv_(nxt,wnd,up) (%x,%lx,%x) snd_(una,nxt,max) (%x,%x,%x)\n",
	    tp->rcv_nxt, tp->rcv_wnd, tp->rcv_up, tp->snd_una, tp->snd_nxt,
	    tp->snd_max);
	addlog("\tsnd_(wl1,wl2,wnd,cwnd) (%x,%x,%lx,%lx)\n", tp->snd_wl1,
	    tp->snd_wl2, tp->snd_wnd, tp->snd_cwnd);
}
#else
void
tcp_cc_trace(struct tcpcb *tp __unused, struct tcphdr *th __unused,
    int event __unused)
{
	/* do nothing */
}
#endif

void
tcp_cc_init_connection(struct tcpcb *tp)
{
	if (tcp_do_rfc3390 == 2) {
		/* increase initial window  */
		tp->snd_cwnd = ulmin(10 * tp->t_maxseg,
		    ulmax(2 * tp->t_maxseg, 14600));
	} else if (tcp_do_rfc3390) {
		/* increase initial window  */
		tp->snd_cwnd = ulmin(4 * tp->t_maxseg,
		    ulmax(2 * tp->t_maxseg, 4380));
	} else
		tp->snd_cwnd = tp->t_maxseg;
}

void
tcp_cc_ack_received(struct tcpcb *tp, struct tcphdr *th)
{
	u_int cw = tp->snd_cwnd;
	u_int incr = tp->t_maxseg;

	/*
	 * If the window gives us less than ssthresh packets
	 * in flight, open exponentially (maxseg per packet).
	 * Otherwise open linearly: maxseg per window
	 * (maxseg^2 / cwnd per packet).
	 */
	if (cw > tp->snd_ssthresh)
		incr = incr * incr / cw;
	if (tp->t_dupacks < tcprexmtthresh)
		tp->snd_cwnd = ulmin(cw + incr, TCP_MAXWIN << tp->snd_scale);
}

#ifdef TCP_ECN
int
tcp_cc_cong_experienced(struct tcpcb *tp)
{
	u_int win;

	win = min(tp->snd_wnd, tp->snd_cwnd) / tp->t_maxseg;
	if (win > 1) {
		tp->snd_ssthresh = win / 2 * tp->t_maxseg;
		tp->snd_cwnd = tp->snd_ssthresh;
		tp->snd_last = tp->snd_max;
		return (1);
	}
	return (0);
}
#endif

void
tcp_cc_enter_fastrecovery(struct tcpcb *tp, struct tcphdr *th)
{
	u_long win;

	/*
	 * We know we're losing at the current window size so do congestion
	 * avoidance (set ssthresh to half the current window and pull our
	 * congestion window back to the new ssthresh).
	 *
	 * Dup acks mean that packets have left the network (they're now
	 * cached at the receiver) so bump cwnd by the amount in the receiver
	 * to keep a constant cwnd packets in the network.
	 */
	win = ulmin(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
	if (win < 2)
		win = 2;
	tp->snd_ssthresh = win * tp->t_maxseg;
}

void
tcp_cc_exit_fastrecovery(struct tcpcb *tp, struct tcphdr *th)
{
	tp->snd_cwnd = tp->snd_ssthresh;
	if (tcp_seq_subtract(tp->snd_max, th->th_ack) < tp->snd_ssthresh)
		tp->snd_cwnd = tcp_seq_subtract(tp->snd_max, th->th_ack);
}

void
tcp_cc_after_idle(struct tcpcb *tp)
{
	/*
	 * We have been idle for "a while" and no acks are
	 * expected to clock out any data we send --
	 * slow start to get ack "clock" running again.
	 */
	tp->snd_cwnd = 2 * tp->t_maxseg;
}
