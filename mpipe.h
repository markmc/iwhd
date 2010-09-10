#if !defined(_MPIPE_H)
#define _MPIPE_H

#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * This is an in-memory "pipe" construct with a twist: it lets you have
 * multiple consumers instead of just one.  For example, you might want
 * to stream data from a back-end store both to the user and into the
 * local cache, or you might want to replicate out to several back ends
 * simultaneously.  The basic flow for the producer is as follows:
 *
 * 	while data available
 *	 	read a chunk of data
 * 		lock shared structure
 *		update the shared pointer/data/sequence
 *		signal the consumer event
 *		wait on the producer event
 *		unlock shared structure
 *	lock shared structure
 *	set prod_done
 *	signal the consumer event
 *	wait on the producer event
 *
 * For consumers, it's a mirror image:
 * 	lock shared structure
 * 	loop
 * 		wait on the consumer event
 * 		continue if shared sequence != own sequence
 * 		break if len == 0
 * 		unlock shared structure
 * 		write the data somewhere
 * 		increment own sequence
 * 		lock shared structure
 * 		signal producer event if ++cons_done == cons_total
 * 	do cons_count/producer-event handshake one more time
 *
 * The sequence checking is not strictly necessary, but it makes things a lot
 * easier to debug if there is a bug that causes producer and consumers to get
 * out of sync.  Instead of corrupting data and continuing, consumers block
 * waiting for the "right" sequence number while the producer blocks waiting
 * for a signal that will never come.
 */

typedef struct {
	void		*owner;
	pthread_mutex_t	 lock;
	pthread_cond_t	 prod_cond;
	pthread_cond_t	 cons_cond;
	void		*data_ptr;
	size_t		 data_len;
	unsigned long	 sequence;
	unsigned short	 cons_total;
	unsigned short	 cons_done;
} pipe_shared;

typedef struct {
	pipe_shared	*shared;
	unsigned long	 sequence;
	size_t		 offset;
} pipe_private;


void		 pipe_init_shared	(pipe_shared *ps,
					 void *owner, unsigned short ncons);
pipe_private	*pipe_init_private	(pipe_shared *ps);
int		 pipe_cons_wait		(pipe_private *pp);
void		 pipe_cons_signal	(pipe_private *pp);
void		 pipe_prod_signal	(pipe_shared *ps,
					 void *ptr, size_t total);
void		 pipe_prod_finish	(pipe_shared *ps);

#endif
