/*
 * Copyright (c) 2017 Mike Belopuhov
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The FlowQueue-CoDel Packet Scheduler and Active Queue Management
 * IETF draft-ietf-aqm-fq-codel-06
 *
 * Based on the implementation by Rasool Al-Saadi <ralsaadi@swin.edu.au>
 *
 * Copyright (C) 2016 Centre for Advanced Internet Architectures,
 *  Swinburne University of Technology, Melbourne, Australia.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfvar.h>
#include <net/codel.h>
#include <net/fq_codel.h>

/* #define FQCODEL_DEBUG 1 */

#ifdef FQCODEL_DEBUG
#define DPRINTF(x...)		printf(x)
#else
#define DPRINTF(x...)
#endif

struct flow {
	struct codel		 cd;
	int			 active:1;
	int			 deficit:31;
#ifdef FQCODEL_DEBUG
	uint16_t		 id;
#endif
	SIMPLEQ_ENTRY(flow)	 flowentry;
};
SIMPLEQ_HEAD(flowq, flow);

struct fqcodel {
	struct flowq		 newq;
	struct flowq		 oldq;

	struct flow		*flows;

	unsigned int		 nflows;
	unsigned int		 qlimit;
	int			 quantum;

	unsigned int		 flags;
#define FQCF_FIXED_QUANTUM	  0x1

	/* stats */
	struct fqcodel_pktcntr   xmit_cnt;
	struct fqcodel_pktcntr 	 drop_cnt;
};

unsigned int	 fqcodel_idx(unsigned int, const struct mbuf *);
void		*fqcodel_alloc(unsigned int, void *);
void		 fqcodel_free(unsigned int, void *);
struct mbuf	*fqcodel_enq(struct ifqueue *, struct mbuf *);
struct mbuf	*fqcodel_deq_begin(struct ifqueue *, void **);
void		 fqcodel_deq_commit(struct ifqueue *, struct mbuf *, void *);
void		 fqcodel_purge(struct ifqueue *, struct mbuf_list *);

/*
 * ifqueue glue.
 */

static const struct ifq_ops fqcodel_ops = {
	fqcodel_idx,
	fqcodel_enq,
	fqcodel_deq_begin,
	fqcodel_deq_commit,
	fqcodel_purge,
	fqcodel_alloc,
	fqcodel_free,
};

const struct ifq_ops * const ifq_fqcodel_ops = &fqcodel_ops;

void		*fqcodel_pf_alloc(struct ifnet *);
int		 fqcodel_pf_addqueue(void *, struct pf_queuespec *);
void		 fqcodel_pf_free(void *);
int		 fqcodel_pf_qstats(struct pf_queuespec *, void *, int *);

/* Default aggregate queue depth */
static const unsigned int fqcodel_qlimit = 1024;

static inline struct flow *
classify_flow(struct fqcodel *fqc, struct mbuf *m)
{
	unsigned int index;

	if (m->m_pkthdr.ph_flowid & M_FLOWID_VALID)
		index = (m->m_pkthdr.ph_flowid & M_FLOWID_MASK) % fqc->nflows;
	else
		index = arc4random_uniform(fqc->nflows);

	DPRINTF("%s: %u\n", __func__, index);

	return (&fqc->flows[index]);
}

struct mbuf *
fqcodel_enq(struct ifqueue *ifq, struct mbuf *m)
{
	struct fqcodel *fqc = ifq->ifq_q;
	struct flow *flow;
	struct timeval now;
	unsigned int backlog = 0;
	int i;

	flow = classify_flow(fqc, m);
	if (flow == NULL)
		return (m);

	codel_gettime(&now);
	codel_enqueue(&flow->cd, &now, m);

	if (!flow->active) {
		SIMPLEQ_INSERT_TAIL(&fqc->newq, flow, flowentry);
		flow->deficit = fqc->quantum;
		flow->active = 1;
		DPRINTF("%s: flow %u active deficit %d\n", __func__,
		    flow->id, flow->deficit);
	}

	/*
	 * Check the limit for all queues and remove a packet
	 * from the largest one, start with the queue for the
	 * unclassified traffic.
	 */
	if (ifq_len(ifq) >= fqcodel_qlimit) {
		for (i = 0; i < fqc->nflows; i++) {
			if (codel_backlog(&fqc->flows[i].cd) > backlog) {
				flow = &fqc->flows[i];
				backlog = codel_backlog(&flow->cd);
			}
		}
		KASSERT(flow != NULL);
		m = codel_commit(&flow->cd, NULL);
		DPRINTF("%s: dropping from flow %u\n", __func__,
		    flow->id);
		return (m);
	}

	return (NULL);
}

#ifdef CODEL_FREEBSD
struct mbuf *
fqcodel_deq_begin(struct ifqueue *ifq, void **cookiep)
{
	struct timeval now;
	struct ifnet *ifp = ifq->ifq_if;
	struct fqcodel *fqc = ifq->ifq_q;
	struct flowq *fq;
	struct flow *flow;
	struct mbuf *m;
	unsigned int dpkts, dbytes;

	if ((fqc->flags & FQCF_FIXED_QUANTUM) == 0)
		fqc->quantum = ifp->if_mtu + max_linkhdr;

	codel_gettime(&now);

	do {
		if (!SIMPLEQ_EMPTY(&fqc->newq))
			fq = &fqc->newq;
		else
			fq = &fqc->oldq;
		if (SIMPLEQ_EMPTY(fq))
			return (NULL);

		flow = SIMPLEQ_FIRST(fq);
		while (flow != NULL) {
			if (flow->deficit < 0) {
				flow->deficit += fqc->quantum;
				SIMPLEQ_REMOVE_HEAD(fq, flowentry);
				SIMPLEQ_INSERT_TAIL(&fqc->oldq, flow,
				    flowentry);
				DPRINTF("%s: flow %u deficit %d\n", __func__,
				    flow->id, flow->deficit);
			} else
				break;
			flow = SIMPLEQ_FIRST(fq);
		}

		if (SIMPLEQ_EMPTY(fq))
			continue;

		m = codel_dequeue(&flow->cd, fqc->quantum, &now,
		    &ifq->ifq_free, &dpkts, &dbytes);

		if (dpkts > 0) {
			KASSERT(ifq->ifq_len >= dpkts);
			ifq->ifq_len -= dpkts;
			ifq->ifq_qdrops += dpkts;
			fqc->drop_cnt.packets += dpkts;
			fqc->drop_cnt.bytes += dbytes;
		}

		if (m == NULL) {
			if (fq == &fqc->newq) {
				/* A packet was dropped, starve the queue */
				SIMPLEQ_REMOVE_HEAD(fq, flowentry);
				SIMPLEQ_INSERT_TAIL(&fqc->oldq, flow,
				    flowentry);
				DPRINTF("%s: flow %u ->oldq deficit %d\n",
				    __func__, flow->id, flow->deficit);
			} else {
				/*
				 * A packet was dropped on a starved queue,
				 * disable it
				 */
				flow->active = 0;
				SIMPLEQ_REMOVE_HEAD(fq, flowentry);
				DPRINTF("%s: flow %u inactive deficit %d\n",
				    __func__, flow->id, flow->deficit);
			}
			/* start again */
			continue;
		}

		flow->deficit -= m->m_pkthdr.len;
		DPRINTF("%s: flow %u deficit %d\n", __func__,
		    flow->id, flow->deficit);
		*cookiep = flow;
		return (m);
	} while (1);

	return (NULL);
}
#else
static inline struct flowq *
select_queue(struct fqcodel *fqc)
{
	struct flowq *fq = NULL;

	if (!SIMPLEQ_EMPTY(&fqc->newq))
		fq = &fqc->newq;
	else if (!SIMPLEQ_EMPTY(&fqc->oldq))
		fq = &fqc->oldq;
	return (fq);
}

static inline struct flow *
first_flow(struct fqcodel *fqc, struct flowq **fq)
{
	struct flow *flow;

	while ((*fq = select_queue(fqc)) != NULL) {
		while ((flow = SIMPLEQ_FIRST(*fq)) != NULL) {
			if (flow->deficit <= 0) {
				flow->deficit += fqc->quantum;
				SIMPLEQ_REMOVE_HEAD(*fq, flowentry);
				SIMPLEQ_INSERT_TAIL(&fqc->oldq, flow,
				    flowentry);
				DPRINTF("%s: flow %u deficit %d\n", __func__,
				    flow->id, flow->deficit);
			} else
				return (flow);
		}
	}

	return (NULL);
}

static inline struct flow *
next_flow(struct fqcodel *fqc, struct flow *flow, struct flowq **fq)
{
	SIMPLEQ_REMOVE_HEAD(*fq, flowentry);

	if (*fq == &fqc->newq && !SIMPLEQ_EMPTY(&fqc->oldq)) {
		/* A packet was dropped, starve the queue */
		SIMPLEQ_INSERT_TAIL(&fqc->oldq, flow, flowentry);
		DPRINTF("%s: flow %u ->oldq deficit %d\n", __func__,
		    flow->id, flow->deficit);
	} else {
		/* A packet was dropped on a starved queue, disable it */
		flow->active = 0;
		DPRINTF("%s: flow %u inactive deficit %d\n", __func__,
		    flow->id, flow->deficit);
	}

	return (first_flow(fqc, fq));
}

struct mbuf *
fqcodel_deq_begin(struct ifqueue *ifq, void **cookiep)
{
	struct timeval now;
	struct ifnet *ifp = ifq->ifq_if;
	struct fqcodel *fqc = ifq->ifq_q;
	struct flowq *fq;
	struct flow *flow;
	struct mbuf *m;
	unsigned int dpkts, dbytes;

	if ((fqc->flags & FQCF_FIXED_QUANTUM) == 0)
		fqc->quantum = ifp->if_mtu + max_linkhdr;

	codel_gettime(&now);

	for (flow = first_flow(fqc, &fq); flow != NULL;
	     flow = next_flow(fqc, flow, &fq)) {
		m = codel_dequeue(&flow->cd, fqc->quantum, &now,
		    &ifq->ifq_free, &dpkts, &dbytes);

		if (dpkts > 0) {
			KASSERT(ifq->ifq_len >= dpkts);
			ifq->ifq_len -= dpkts;
			ifq->ifq_qdrops += dpkts;
			fqc->drop_cnt.packets += dpkts;
			fqc->drop_cnt.bytes += dbytes;
		}

		if (m != NULL) {
			flow->deficit -= m->m_pkthdr.len;
			DPRINTF("%s: flow %u deficit %d\n", __func__,
			    flow->id, flow->deficit);
			*cookiep = flow;
			return (m);
		}
	}

	return (NULL);
}
#endif	/* CODEL_FREEBSD */

void
fqcodel_deq_commit(struct ifqueue *ifq, struct mbuf *m, void *cookie)
{
	struct fqcodel *fqc = ifq->ifq_q;
	struct flow *flow = cookie;

	fqc->xmit_cnt.packets++;
	fqc->xmit_cnt.bytes += m->m_pkthdr.len;

	(void)codel_commit(&flow->cd, m);
}

void
fqcodel_purge(struct ifqueue *ifq, struct mbuf_list *ml)
{
	struct fqcodel *fqc = ifq->ifq_q;
	unsigned int i;

	for (i = 0; i < fqc->nflows; i++)
		codel_purge(&fqc->flows[i].cd, ml);
}

void *
fqcodel_pf_alloc(struct ifnet *ifp)
{
	struct fqcodel *fqc;

	fqc = malloc(sizeof(struct fqcodel), M_DEVBUF, M_WAITOK | M_ZERO);

	return (fqc);
}

int
fqcodel_pf_addqueue(void *arg, struct pf_queuespec *qs)
{
	struct ifnet *ifp = qs->kif->pfik_ifp;
	struct fqcodel *fqc = arg;

	KASSERT(qs->parent_qid == 0);

	fqc->nflows = qs->flowqueue.flows;
	fqc->quantum = qs->flowqueue.quantum;
	if (qs->qlimit > 0)
		fqc->qlimit = qs->qlimit;
	else
		fqc->qlimit = fqcodel_qlimit;
	if (fqc->quantum > 0)
		fqc->flags |= FQCF_FIXED_QUANTUM;
	else
		fqc->quantum = ifp->if_mtu + max_linkhdr;

	fqc->flows = mallocarray(fqc->nflows, sizeof(struct flow),
	    M_DEVBUF, M_WAITOK | M_ZERO);

#ifdef FQCODEL_DEBUG
	{
		unsigned int i;

		for (i = 0; i < fqc->nflows; i++)
			fqc->flows[i].id = i;
	}
#endif

	printf("fq-codel on %s: %d queues %d deep, quantum %d\n",
	    ifp->if_xname, fqc->nflows, fqc->qlimit, fqc->quantum);

	return (0);
}

void
fqcodel_pf_free(void *arg)
{
	struct fqcodel *fqc = arg;

	free(fqc->flows, M_DEVBUF, fqc->nflows * sizeof(struct flow));
	free(fqc, M_DEVBUF, sizeof(struct fqcodel));
}

int
fqcodel_pf_qstats(struct pf_queuespec *qs, void *ubuf, int *nbytes)
{
	return (EBADF);
}

unsigned int
fqcodel_idx(unsigned int nqueues, const struct mbuf *m)
{
	return (0);
}

void *
fqcodel_alloc(unsigned int idx, void *arg)
{
	struct fqcodel *fqc = arg;

	SIMPLEQ_INIT(&fqc->newq);
	SIMPLEQ_INIT(&fqc->oldq);

	return (fqc);
}

void
fqcodel_free(unsigned int idx, void *arg)
{
	/* nothing to do here */
}
