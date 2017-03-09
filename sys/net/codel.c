/*
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *  Copyright (C) 2017 Mike Belopuhov <mikeb@openbsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 * IETF draft-ietf-aqm-codel-07
 *
 * Implemented on linux by Dave Taht and Eric Dumazet;
 * OpenBSD implementation by Mike Belopuhov.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <net/codel.h>

/* Delay target, 5ms */
static const struct timeval codel_target = { 0, 5000 };

/* Default interval, 100ms RTT */
static const struct timeval codel_interval = { 0, 100000 };

#ifdef CODEL_FREEBSD
/* Grace period after last drop, 8 * 100ms RTT */
static const struct timeval codel_grace = { 0, 800000 };
#else
/* Grace period after last drop, 16 * 100ms RTT */
static const struct timeval codel_grace = { 1, 600000 };
#endif

/* First 400 "100 / sqrt(x)" intervarls, us */
static const uint32_t codel_intervals[] = {
	100000, 70711, 57735, 50000, 44721, 40825, 37796, 35355, 33333, 31623,
	 30151, 28868, 27735, 26726, 25820, 25000, 24254, 23570, 22942, 22361,
	 21822, 21320, 20851, 20412, 20000, 19612, 19245, 18898, 18570, 18257,
	 17961, 17678, 17408, 17150, 16903, 16667, 16440, 16222, 16013, 15811,
	 15617, 15430, 15250, 15076, 14907, 14744, 14586, 14434, 14286, 14142,
	 14003, 13868, 13736, 13608, 13484, 13363, 13245, 13131, 13019, 12910,
	 12804, 12700, 12599, 12500, 12403, 12309, 12217, 12127, 12039, 11952,
	 11868, 11785, 11704, 11625, 11547, 11471, 11396, 11323, 11251, 11180,
	 11111, 11043, 10976, 10911, 10847, 10783, 10721, 10660, 10600, 10541,
	 10483, 10426, 10370, 10314, 10260, 10206, 10153, 10102, 10050, 10000,
	  9950,  9901,  9853,  9806,  9759,  9713,  9667,  9623,  9578,  9535,
	  9492,  9449,  9407,  9366,  9325,  9285,  9245,  9206,  9167,  9129,
	  9091,  9054,  9017,  8980,  8944,  8909,  8874,  8839,  8805,  8771,
	  8737,  8704,  8671,  8639,  8607,  8575,  8544,  8513,  8482,  8452,
	  8422,  8392,  8362,  8333,  8305,  8276,  8248,  8220,  8192,  8165,
	  8138,  8111,  8085,  8058,  8032,  8006,  7981,  7956,  7931,  7906,
	  7881,  7857,  7833,  7809,  7785,  7762,  7738,  7715,  7692,  7670,
	  7647,  7625,  7603,  7581,  7559,  7538,  7516,  7495,  7474,  7454,
	  7433,  7412,  7392,  7372,  7352,  7332,  7313,  7293,  7274,  7255,
	  7236,  7217,  7198,  7180,  7161,  7143,  7125,  7107,  7089,  7071,
	  7053,  7036,  7019,  7001,  6984,  6967,  6950,  6934,  6917,  6901,
	  6884,  6868,  6852,  6836,  6820,  6804,  6788,  6773,  6757,  6742,
	  6727,  6712,  6696,  6682,  6667,  6652,  6637,  6623,  6608,  6594,
	  6580,  6565,  6551,  6537,  6523,  6509,  6496,  6482,  6468,  6455,
	  6442,  6428,  6415,  6402,  6389,  6376,  6363,  6350,  6337,  6325,
	  6312,  6299,  6287,  6275,  6262,  6250,  6238,  6226,  6214,  6202,
	  6190,  6178,  6166,  6155,  6143,  6131,  6120,  6108,  6097,  6086,
	  6075,  6063,  6052,  6041,  6030,  6019,  6008,  5998,  5987,  5976,
	  5965,  5955,  5944,  5934,  5923,  5913,  5903,  5893,  5882,  5872,
	  5862,  5852,  5842,  5832,  5822,  5812,  5803,  5793,  5783,  5774,
	  5764,  5754,  5745,  5735,  5726,  5717,  5707,  5698,  5689,  5680,
	  5670,  5661,  5652,  5643,  5634,  5625,  5617,  5608,  5599,  5590,
	  5581,  5573,  5564,  5556,  5547,  5538,  5530,  5522,  5513,  5505,
	  5496,  5488,  5480,  5472,  5464,  5455,  5447,  5439,  5431,  5423,
	  5415,  5407,  5399,  5392,  5384,  5376,  5368,  5361,  5353,  5345,
	  5338,  5330,  5322,  5315,  5307,  5300,  5293,  5285,  5278,  5270,
	  5263,  5256,  5249,  5241,  5234,  5227,  5220,  5213,  5206,  5199,
	  5192,  5185,  5178,  5171,  5164,  5157,  5150,  5143,  5137,  5130,
	  5123,  5116,  5110,  5103,  5096,  5090,  5083,  5077,  5070,  5064,
	  5057,  5051,  5044,  5038,  5032,  5025,  5019,  5013,  5006
};

void
codel_gettime(struct timeval *tvp)
{
	/* 1ms precision is required to make a decision */
#if defined(HZ) && HZ >= 1000
	getmicrouptime(tvp);
#else
	microuptime(tvp);
#endif
}

unsigned int
codel_backlog(struct codel *cd)
{
	return (cd->backlog);
}

unsigned int
codel_qlength(struct codel *cd)
{
	return (ml_len(&cd->q));
}

void
codel_enqueue(struct codel *cd, struct timeval *now, struct mbuf *m)
{
	memcpy(&m->m_pkthdr.ph_timestamp, now, sizeof(*now));

	ml_enqueue(&cd->q, m);
	cd->backlog += m->m_pkthdr.len;
}

/*
 * Select the next interval according to the number of drops
 * in the current one relative to the provided timestamp.
 */
static inline void
control_law(struct codel *cd, struct timeval *rts)
{
	struct timeval itv;
	unsigned int idx;

	idx = min(cd->drops, nitems(codel_intervals) - 1);
	itv.tv_sec = 0;
	itv.tv_usec = codel_intervals[idx];
	timeradd(rts, &itv, &cd->next);
}

/*
 * Pick the next enqueued packet and determine the queueing delay
 * as well as whether or not it's a good candidate for dropping
 * from the queue.
 *
 * The decision whether to drop the packet or not is made based
 * on the queueing delay target of 5ms and on the current queue
 * lenght in bytes which shouldn't be less than the amount of data
 * that arrives in a typical interarrival time (MTU-sized packets
 * arriving spaced by the amount of time it takes to send such a
 * packet on the bottleneck).
 */
static inline struct mbuf *
codel_next(struct codel *cd, struct timeval *now, int quantum, int *drop)
{
	struct timeval delay;
	struct mbuf *m;

	*drop = 0;

	m = MBUF_LIST_FIRST(&cd->q);
	if (m == NULL) {
		KASSERT(cd->backlog == 0);
		/* Empty queue, reset interval */
		timerclear(&cd->start);
		return (NULL);
	}

	timersub(now, &m->m_pkthdr.ph_timestamp, &delay);
	if (timercmp(&delay, &codel_target, <) || cd->backlog <= quantum) {
		/*
		 * Went below target - stay below for at least one interval
		 */
		timerclear(&cd->start);
		return (m);
	}

	if (!timerisset(&cd->start)) {
		/*
		 * Just went above from below.  If we stay above the
		 * target for at least 100ms we'll say it's ok to drop.
		 */
		timeradd(now, &codel_interval, &cd->start);
	} else if (timercmp(now, &cd->start, >)) {
		*drop = 1;
	}
	return (m);
}

struct mbuf *
codel_dequeue(struct codel *cd, int quantum, struct timeval *now,
    struct mbuf_list *ml, unsigned int *dpkts, unsigned int *dbytes)
{
	struct timeval diff;
	struct mbuf *m;
	int drop;
#ifndef CODEL_FREEBSD
	unsigned short delta;
#endif

	*dpkts = *dbytes = 0;

	if ((m = codel_next(cd, now, quantum, &drop)) == NULL) {
		cd->dropping = 0;
		return (NULL);
	}

	if (cd->dropping && !drop) {
		/* Sojourn time is below the target - leave dropping state */
		cd->dropping = 0;
		return (m);
	}

	if (cd->dropping) {
		while (timercmp(now, &cd->next, >=) && cd->dropping) {
			/*
			 * It's time for the next drop. Drop the current
			 * packet and dequeue the next. The dequeue might
			 * take us out of dropping state. If not, schedule
			 * the next drop. A large backlog might result in
			 * drop rates so high that the next drop should
			 * happen now, hence the while loop.
			 */
			m = codel_commit(cd, m);
			ml_enqueue(ml, m);
			cd->drops++;

			(*dpkts)++;
			*dbytes += m->m_pkthdr.len;

			m = codel_next(cd, now, quantum, &drop);

			if (!drop)
				cd->dropping = 0;
			else
				control_law(cd, &cd->next);
		}
	} else if (drop) {
		m = codel_commit(cd, m);
		ml_enqueue(ml, m);

		(*dpkts)++;
		*dbytes += m->m_pkthdr.len;

		m = codel_next(cd, now, quantum, &drop);

		cd->dropping = 1;

		/*
		 * If min went above target close to when we last went below
		 * it, assume that the drop rate that controlled the queue on
		 * the last cycle is a good starting point to control it now.
		 */
#ifdef CODEL_FREEBSD
		if (cd->drops > 2) {
			timersub(now, &cd->next, &diff);
			if (timercmp(now, &cd->next, <) ||
			    timercmp(&diff, &codel_grace, <))
				cd->drops -= 2;
			else
				cd->drops = 1;
		} else
			cd->drops = 1;
		control_law(cd, now);
#else
		delta = cd->drops - cd->ldrops;
		if (delta > 1) {
			/*
			 * If we're still within the grace period and not
			 * meeting our delay target we treat this condition
			 * as a continuation of the previous interval and
			 * shrink it further.
			 */
			timersub(now, &cd->next, &diff);
			if (timercmp(now, &cd->next, <) ||
			    timercmp(&diff, &codel_grace, <))
				cd->drops = delta;
			else
				cd->drops = 1;
		} else
			cd->drops = 1;
		control_law(cd, now);
		cd->ldrops = cd->drops;
#endif
	}
	return (m);
}

struct mbuf *
codel_commit(struct codel *cd, struct mbuf *m)
{
	struct mbuf *n;

	n = ml_dequeue(&cd->q);
	if (m)
		KASSERT(n == m);
	KASSERT(n != NULL);
	KASSERT(cd->backlog >= n->m_pkthdr.len);
	cd->backlog -= n->m_pkthdr.len;
	return (n);
}

void
codel_purge(struct codel *cd, struct mbuf_list *ml)
{
	ml_enlist(ml, &cd->q);
	cd->backlog = 0;
}
