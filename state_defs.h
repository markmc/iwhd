/* Copyright (C) 2010 Red Hat, Inc.

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

#if !defined(_STATE_DEFS_H)
#define _STATE_DEFS_H

#include "mpipe.h"
#include "template.h"

#define MAX_FIELD_LEN	64

typedef enum {
	MS_NEW,
	MS_NORMAL,
} ms_state;

typedef struct {
	int				 cleanup;
	/* for everyone */
	MHD_AccessHandlerCallback	 handler;
	ms_state			 state;
	/* for local ops */
	int				 fd;
	/* for proxy ops */
	char				*url;
	char				 bucket[MAX_FIELD_LEN];
	char				 key[MAX_FIELD_LEN];
	char				 attr[MAX_FIELD_LEN];
	/* for proxy gets */
	CURL				*curl;
	long				 rc;
	/* for proxy puts */
	size_t				 size;
	/* for proxy puts and queries */
	struct MHD_Connection		*conn;
	/* for proxy queries */
	struct MHD_PostProcessor	*post;
	void				*query;
	/* for bucket-level puts */
	GHashTable			*dict;
	/* for new producer/consumer model */
	pipe_shared			 pipe;
	int				 from_master;
	pthread_t			 backend_th;
	pthread_t			 cache_th;
	/* for bucket/object/provider list generators */
	tmpl_ctx_t			*gen_ctx;
} my_state;

#define CLEANUP_CURL	0x01
#define CLEANUP_BUF_PTR	0x02
#define CLEANUP_POST	0x04
#define CLEANUP_DICT	0x08
#define CLEANUP_QUERY	0x10
#define CLEANUP_TMPL	0x20
#define CLEANUP_URL	0x40

#endif
