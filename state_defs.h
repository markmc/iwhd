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

#ifndef _STATE_DEFS_H
#define _STATE_DEFS_H

#include <microhttpd.h>
#include "hash.h"
#include "mpipe.h"
#include "template.h"

#define MAX_FIELD_LEN	64

/* Avoid circular (my_state->provider->backend->my_state) include. */
struct _provider;

typedef enum {
	MS_NEW,
	MS_NORMAL,
} ms_state;

/*
 * This structure is used for pthread_create targets that take a void*
 * argument, so that they can find the state_def and provider_t that they
 * need regardless of whether they were invoked from main-line request
 * code (using the thunk embedded here) or the replica code (using a thunk
 * embedded in the repl_item).
 */
typedef struct {
	struct _my_state	*parent;
	struct _provider	*prov;
} backend_thunk_t;

typedef struct _my_state {
	/* for everyone */
	MHD_AccessHandlerCallback	 handler;
	ms_state			 state;
	/* for proxy ops */
	char				*url;
	char				 bucket[MAX_FIELD_LEN];
	char				 key[MAX_FIELD_LEN];
	char				 attr[MAX_FIELD_LEN];
	/* for proxy gets */
	long				 rc;
	/* for proxy puts */
	size_t				 size;
	/* for proxy puts and queries */
	struct MHD_Connection		*conn;
	/* for proxy queries */
	struct MHD_PostProcessor	*post;
	void				*query;		/* object query */
	void				*aquery;	/* attribute query */
	/* for bucket-level puts */
	Hash_table			*dict;
	/* for new producer/consumer model */
	pipe_shared			 pipe;
	int				 from_master;
	pthread_t			 backend_th;
	pthread_t			 cache_th;
	/* for bucket/object/provider list generators */
	tmpl_ctx_t			*gen_ctx;
	char *buf;
	size_t buf_n_alloc;
	size_t buf_n_used;
	/* for back-end functions */
	backend_thunk_t			 thunk;
	int				 be_flags;
} my_state;

#define BACKEND_GET_SIZE	0x01	/* used in put_child_func */

#endif
