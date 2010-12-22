/* Copyright (C) 2010-2011 Red Hat, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#if !defined(_MPIPE_H)
#define _MPIPE_H

#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>

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
 *
 * The cons_error is the "deadweight" that only increments. This way the
 * thread ping-pong and zeroing of cons_done are left alone.
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
        unsigned short   cons_init_done;
        unsigned short   cons_init_error;
	unsigned short	 cons_done;
	unsigned short   cons_error;
        enum { PROD_INIT, PROD_RUNNING, PROD_ERROR } prod_state;
} pipe_shared;

typedef struct {
	pipe_shared	*shared;
	unsigned long	 sequence;
	size_t		 offset;
	void		*prov;
} pipe_private;


void		 pipe_init_shared	(pipe_shared *ps,
					 void *owner, unsigned short ncons);
pipe_private	*pipe_init_private	(pipe_shared *ps);
int		 pipe_cons_wait		(pipe_private *pp);
void		 pipe_cons_signal	(pipe_private *pp, int error);
void		 pipe_cons_siginit	(pipe_shared *ps, int error);
int		 pipe_prod_wait_init	(pipe_shared *ps);
void             pipe_prod_siginit      (pipe_shared *ps, int error);
int              pipe_cons_wait_init    (pipe_shared *ps);
void		 pipe_prod_signal	(pipe_shared *ps,
					 void *ptr, size_t total);
void		 pipe_prod_finish	(pipe_shared *ps);
void		 pipe_reset		(pipe_shared *ps, unsigned short ncons);

#endif
