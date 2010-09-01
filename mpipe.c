#include "repo.h"
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
	ps->cons_total = ncons;
	ps->cons_done = 0;
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
		if (++ps->cons_done >= ps->cons_total) {
			pthread_cond_signal(&ps->prod_cond);
		}
		rc = 0;
	}

	pthread_mutex_unlock(&ps->lock);
	return rc;
}

void
pipe_cons_signal (pipe_private *pp)
{
	pipe_shared	*ps	= pp->shared;

	++pp->sequence;
	pp->offset = 0;

	pthread_mutex_lock(&ps->lock);
	if (++ps->cons_done >= ps->cons_total) {
		pthread_cond_signal(&ps->prod_cond);
	}
	pthread_mutex_unlock(&ps->lock);
}

void
pipe_prod_signal (pipe_shared *ps, void *ptr, size_t total)
{
	DPRINTF("producer posting %zu bytes as %ld\n",total,ps->sequence+1);

	pthread_mutex_lock(&ps->lock);
	ps->data_ptr = ptr;
	ps->data_len = total;
	ps->cons_done = 0;
	++ps->sequence;
	do {
		pthread_cond_broadcast(&ps->cons_cond);
		pthread_cond_wait(&ps->prod_cond,&ps->lock);
		DPRINTF("%u children yet to read\n",
			ps->cons_total - ps->cons_done);
	} while (ps->cons_done < ps->cons_total);
	pthread_mutex_unlock(&ps->lock);
}

void
pipe_prod_finish (pipe_shared *ps)
{
	pthread_mutex_lock(&ps->lock);
	ps->data_len = 0;
	ps->cons_done = 0;
	++ps->sequence;
	DPRINTF("waiting for %u children\n",ps->cons_total);
	do {
		pthread_cond_broadcast(&ps->cons_cond);
		pthread_cond_wait(&ps->prod_cond,&ps->lock);
		DPRINTF("%u children left\n",
			ps->cons_total - ps->cons_done);
	} while (ps->cons_done < ps->cons_total);
	pthread_mutex_unlock(&ps->lock);
}

