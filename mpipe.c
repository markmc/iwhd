#include <config.h>

#include "iwh.h"
#include "mpipe.h"

void
pipe_init_shared (pipe_shared *ps, void *owner, unsigned short ncons)
{
	ps->owner = owner;
	pthread_mutex_init(&ps->lock,NULL);
	pthread_cond_init(&ps->prod_cond,NULL);
	pthread_cond_init(&ps->cons_cond,NULL);
	ps->data_ptr = NULL;
	ps->data_len = 0;
	ps->sequence = 0;	/* TBD: randomize? */
	ps->in_init = 1;	/* TBD: use sequence == 0 or something? */
	ps->cons_total = ncons;
	ps->cons_done = 0;
	ps->cons_error = 0;
}

pipe_private *
pipe_init_private (pipe_shared *ps)
{
	pipe_private	*pp;

	pp = malloc(sizeof(*pp));
	if (pp) {
		pp->shared = ps;
		pp->sequence = ps->sequence + 1;
		pp->offset = 0;
	}
	return pp;
}

int
pipe_cons_wait (pipe_private *pp)
{
	pipe_shared	*ps	= pp->shared;
	int		 rc;

	pthread_mutex_lock(&ps->lock);

	while (ps->sequence != pp->sequence) {
		DPRINTF("consumer about to wait for %lu\n",pp->sequence);
		pthread_cond_wait(&ps->cons_cond,&ps->lock);
		DPRINTF("consumer done waiting\n");
	}

	rc = (ps->data_len != 0);
	if (!rc) {
		DPRINTF("consumer saw producer is done\n");
		if (++ps->cons_done + ps->cons_error >= ps->cons_total) {
			pthread_cond_signal(&ps->prod_cond);
		}
		rc = 0;
	}

	pthread_mutex_unlock(&ps->lock);
	return rc;
}

/*
 * TBD: maybe return to pipe_cons_signal that cannot report errors.
 */
void
pipe_cons_signal (pipe_private *pp, int error)
{
	pipe_shared	*ps	= pp->shared;

	pthread_mutex_lock(&ps->lock);
	++pp->sequence;
	pp->offset = 0;

	if (error)
		++ps->cons_error;
	else
		++ps->cons_done;
	if (ps->cons_done + ps->cons_error >= ps->cons_total) {
		DPRINTF("consumer signal, done %u total %u\n",
			ps->cons_done,ps->cons_total);
		pthread_cond_signal(&ps->prod_cond);
	}
	pthread_mutex_unlock(&ps->lock);
}

void
pipe_cons_siginit (pipe_shared *ps, int error)
{
	pthread_mutex_lock(&ps->lock);
	if (!ps->in_init) {
		pthread_mutex_unlock(&ps->lock);
		return;
	}
	if (error)
		++ps->cons_error;
	else
		++ps->cons_done;
	pthread_cond_broadcast(&ps->prod_cond);
	DPRINTF("consumer init signal (total %u done %u error %u)\n",
		ps->cons_total,ps->cons_done,ps->cons_error);
	ps->in_init = 0;
	pthread_mutex_unlock(&ps->lock);
}

/*
 * Return the number of bad children, or -1 if some other error.
 */
int
pipe_prod_wait_init (pipe_shared *ps)
{
	pthread_mutex_lock(&ps->lock);
	DPRINTF("producer initializing (total %u error %u)\n",
		ps->cons_total,ps->cons_error);
	while (ps->cons_done + ps->cons_error < ps->cons_total) {
		pthread_cond_broadcast(&ps->cons_cond);
		pthread_cond_wait(&ps->prod_cond,&ps->lock);
		DPRINTF("%u children yet to poll (total %u done %u error %u)\n",
			ps->cons_total - (ps->cons_done + ps->cons_error),
			ps->cons_total,ps->cons_done,ps->cons_error);
	}
	pthread_mutex_unlock(&ps->lock);
	return ps->cons_error;
}

void
pipe_prod_signal (pipe_shared *ps, void *ptr, size_t total)
{
	pthread_mutex_lock(&ps->lock);
	if (ps->cons_error >= ps->cons_total) {
		DPRINTF("producer posting %zu bytes as %ld, no sinks"
			" (total %u error %u)\n",
			total,ps->sequence+1, ps->cons_total,ps->cons_error);
		pthread_mutex_unlock(&ps->lock);
		return;
	}
	ps->data_ptr = ptr;
	ps->data_len = total;
	ps->cons_done = ps->cons_error;
	++ps->sequence;
	DPRINTF("producer posting %zu bytes as %ld (total %u error %u)\n",
		total,ps->sequence, ps->cons_total,ps->cons_error);
	while (ps->cons_done + ps->cons_error < ps->cons_total) {
		pthread_cond_broadcast(&ps->cons_cond);
		pthread_cond_wait(&ps->prod_cond,&ps->lock);
		DPRINTF("%u children yet to read (total %u done %u error %u)\n",
			ps->cons_total - (ps->cons_done + ps->cons_error),
			ps->cons_total,ps->cons_done,ps->cons_error);
	}
	pthread_mutex_unlock(&ps->lock);
}

void
pipe_prod_finish (pipe_shared *ps)
{
	pthread_mutex_lock(&ps->lock);
	ps->data_len = 0;
	ps->cons_done = ps->cons_error;
	++ps->sequence;
	DPRINTF("waiting for %u children (total %u error %u)\n",
		ps->cons_total - (ps->cons_done + ps->cons_error),
		ps->cons_total,ps->cons_error);
	while (ps->cons_done + ps->cons_error < ps->cons_total) {
		pthread_cond_broadcast(&ps->cons_cond);
		pthread_cond_wait(&ps->prod_cond,&ps->lock);
		DPRINTF("%u children left (total %u done %u error %u)\n",
			ps->cons_total - (ps->cons_done + ps->cons_error),
			ps->cons_total,ps->cons_done,ps->cons_error);
	}
	pthread_mutex_unlock(&ps->lock);
}
