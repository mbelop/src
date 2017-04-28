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

#ifndef _NET_CODEL_H_
#define _NET_CODEL_H_

struct codel {
	struct mbuf_list q;

	unsigned int	 dropping:1;	/* Dropping state */
	unsigned int	 backlog:31;	/* Number of bytes in the queue */

	unsigned short	 drops;		/* Free running counter of drops */
	unsigned short	 ldrops;	/* Value from the previous run */

	struct timeval	 start;		/* The moment queue was above target */
	struct timeval	 next;		/* Next interval */
};

struct codel_params {
	struct timeval	 tstamp;
	int64_t		 tgen;
	int		 ticks;

	struct timeval	 target;
	struct timeval	 interval;
	int		 quantum;

	uint32_t	*intervals;
};

void		 codel_initparams(struct codel_params *, unsigned int,
		    unsigned int, int);
void		 codel_freeparams(struct codel_params *);
void		 codel_gettime(struct codel_params *, struct timeval *,
		    long long gen);
unsigned int	 codel_backlog(struct codel *);
unsigned int	 codel_qlength(struct codel *);
void		 codel_enqueue(struct codel *, struct timeval *,
		    struct mbuf *);
struct mbuf	*codel_dequeue(struct codel *, struct codel_params *,
		    struct timeval *, struct mbuf_list *, unsigned int *,
		    unsigned int *);
struct mbuf	*codel_commit(struct codel *, struct mbuf *);
void		 codel_purge(struct codel *, struct mbuf_list *ml);

#endif	/* _NET_CODEL_H_ */
