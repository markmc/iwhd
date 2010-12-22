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

#include <config.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hstor.h>
#include <microhttpd.h>	/* for HTTP status values */

#include "iwh.h"
#include "setup.h"
#include "query.h"
#include "meta.h"
#include "replica.h"

typedef enum {
	REPL_PUT,		/* store an object */
	REPL_ODELETE,		/* delete an object */
	REPL_BCREATE,		/* create a bucket */
	/* TBD: bucket deletion, others? */
} repl_t;

typedef struct _repl_item {
	struct _repl_item	*next;
	repl_t			 type;
	char			*path;
	provider_t		*server;
	size_t			 size;
	int			 pipes[2];
	my_state		*ms;
} repl_item;

typedef struct {
	char		*cur_bucket;
	char		*cur_key;
	provider_t	*cur_server;
} query_ctx_t;

static repl_item	*queue_head	= NULL;
static repl_item	*queue_tail	= NULL;
static pthread_mutex_t	 queue_lock;
static sem_t		 queue_sema;
static volatile gint	 rep_count	= 0;

static void *
proxy_repl_prod (void *ctx)
{
	repl_item		*item	= ctx;
	backend_thunk_t		 thunk;
	void			*result;

	thunk.parent = item->ms;
	thunk.prov = get_main_provider();

	result = thunk.prov->func_tbl->get_child_func(&thunk);
	return result;
}

static void *
proxy_repl_cons (void *ctx)
{
	repl_item		*item	= ctx;
	my_state		*ms	= item->ms;
	pipe_private		*pp;

	pp = pipe_init_private(&ms->pipe);
	if (!pp) {
		pipe_cons_siginit(&ms->pipe,-1);
		return THREAD_FAILED;
	}

	pp->prov = item->server;
	ms->be_flags = 0;

	return item->server->func_tbl->put_child_func(pp);
}

static void
repl_worker_del (const repl_item *item)
{
	char	*bucket;
	char	*key;
	int	 rc;

	bucket = strdup(item->path);
	if (!bucket) {
		error(0,errno,"ran out of memory replicating delete for %s",
			item->path);
		return;
	}

	key = strchr(bucket,'/');
	if (!key) {
		error(0,0,"invalid path replicating delete for %s",item->path);
		free(bucket);
		return;
	}
	++key;

	rc = item->server->func_tbl->delete_func(item->server,
		bucket, key, item->path);
	if (rc != MHD_HTTP_OK) {
		error(0,0,"got status %d replicating delete for %s",
			rc, item->path);
	}
	free(bucket);

	DPRINTF("finished replicating delete for %s, rc = %d\n",item->path,rc);
}

static void
repl_worker_bcreate (repl_item *item)
{
	int	 rc;

	rc = item->server->func_tbl->bcreate_func(item->server,item->path);
	if (rc != MHD_HTTP_OK) {
		error(0,0,"got status %d replicating bcreate for %s",
			rc, item->path);
	}

	DPRINTF("finished replicating bcreate for %s, rc = %d\n",item->path,rc);
}

/* Use this to diagnose failed thread creation.  */
#define xpthread_create(thread, start_routine, item, msg)		\
  do {									\
    int err = pthread_create (thread, NULL, start_routine, item);	\
    if (err) {								\
      error (0, err, msg);						\
      return NULL;							\
    }									\
  } while (0)

static void *
repl_worker (void *notused ATTRIBUTE_UNUSED)
{
	repl_item	*item;
	pthread_t	 cons;
	pthread_t	 prod;
	my_state	*ms;

	for (;;) {
		sem_wait(&queue_sema);
		pthread_mutex_lock(&queue_lock);
		item = queue_head;
		queue_head = item->next;
		if (!queue_head) {
			queue_tail = NULL;
		}
		pthread_mutex_unlock(&queue_lock);

		/*
		 * Do a full initialization here, not just in the rest.  It's
		 * necessary in the oddball case where we're re-replicating as
		 * a result of an attribute/policy change, and it's not harmful
		 * in the normal case where we're actually storing a new file.
		 */
		ms = item->ms;
		pipe_init_shared(&ms->pipe,ms,1);
		switch (item->type) {
		case REPL_PUT:
			if (pipe(item->pipes) >= 0) {
				xpthread_create(&prod,proxy_repl_prod,item,
					    "failed to start producer thread");
				xpthread_create(&cons,proxy_repl_cons,item,
					    "failed to start consumer thread");
				pthread_join(prod,NULL);
				pthread_join(cons,NULL);
			}
			else {
				error(0,errno,"pipe");
			}
			break;
		case REPL_ODELETE:
			repl_worker_del(item);
			break;
		case REPL_BCREATE:
			repl_worker_bcreate(item);
			break;
		default:
			error(0,0,"bad repl type %d (url=%s) skipped",
				item->type, item->path);
		}
		free_ms(item->ms);
		free(item->path);
		free(item);
		/* No atomic dec without test?  Lame. */
		(void)g_atomic_int_dec_and_test(&rep_count);
	}
}

void
repl_init (void)
{
	pthread_t	tid;

	sem_init(&queue_sema,0,0);
	pthread_mutex_init(&queue_lock,NULL);
	pthread_create(&tid,NULL,repl_worker,NULL);
}

static const char *
repl_oget (void *ctx, const char *id)
{
	query_ctx_t	*qctx = ctx;
	char		*cur_value = NULL;

	(void)meta_get_value(qctx->cur_bucket,qctx->cur_key,id,&cur_value);

	return cur_value;
}

static const char *
repl_sget (void *ctx, const char *id)
{
	query_ctx_t	*qctx	= ctx;
	provider_t	*prov	= qctx->cur_server;

	if (!strcmp(id,"name")) {
		return prov->name;
	}
	if (!strcmp(id,"type")) {
		return prov->type;
	}
	if (!strcmp(id,"host")) {
		return prov->host;
	}
	if (!strcmp(id,"key")) {
		return prov->username;
	}
	if (!strcmp(id,"secret")) {
		return prov->password;
	}
	if (!strcmp(id,"path")) {
		return prov->path;
	}

	return g_hash_table_lookup(prov->attrs,id);
}

void
replicate (const char *url, size_t size, const char *policy, my_state *ms)
{
	repl_item	*item;
	value_t		*expr;
	int		 res;
	char		*url2;
	char		*stctx;
	query_ctx_t	 qctx;
	getter_t	 oget;
	getter_t	 sget;
	GHashTableIter	 iter;
	gpointer	 key;
	gpointer	 value;
	provider_t	*prov;

	url2 = strdup(url);
	if (!url2) {
		error(0,0,"could not parse url %s",url);
		return;
	}
	qctx.cur_bucket = strtok_r(url2,"/",&stctx);
	qctx.cur_key = strtok_r(NULL,"/",&stctx);

	if (!size) {
		size = meta_get_size(qctx.cur_bucket,qctx.cur_key);
		DPRINTF("fetched size %zu for %s\n",size,url);
	}

	if (policy) {
		DPRINTF("--- policy = %s\n",policy);
		expr = parse(policy);
	}
	else {
		expr = NULL;
	}

	oget.func = repl_oget;
	oget.ctx = &qctx;
	sget.func = repl_sget;
	sget.ctx = &qctx;

	init_prov_iter(&iter);
	while (g_hash_table_iter_next(&iter,&key,&value)) {
		if (!strcmp(key,me)) {
			continue;
		}
		prov = (provider_t *)value;
		if (expr) {
			qctx.cur_server = prov;
			res = eval(expr,&oget,&sget);
		}
		else {
			res = 0;
		}
		if (res <= 0) {
			DPRINTF("skipping %s for %s\n",prov->name,url);
			continue;
		}
		DPRINTF("REPLICATING %s to %s\n",url,prov->name);
		item = malloc(sizeof(*item));
		if (!item) {
			error(0,errno,"could not create repl_item for %s",
			      url);
			break;
		}
		item->type = REPL_PUT;
		item->path = strdup(url);
		if (!item->path) {
			error(0,errno,"could not create repl_item for %s",
			      url);
			break;
		}
		item->server = prov;
		item->size = size;
		item->ms = ms;
		g_atomic_int_inc(&ms->refcnt);
		pthread_mutex_lock(&queue_lock);
		if (queue_tail) {
			item->next = queue_tail->next;
			queue_tail->next = item;
		}
		else {
			item->next = NULL;
			queue_head = item;
		}
		queue_tail = item;
		pthread_mutex_unlock(&queue_lock);
		g_atomic_int_inc(&rep_count);
		sem_post(&queue_sema);
	}

	free(url2);
}

static void
replicate_namespace_action (const char *name, repl_t action, my_state *ms)
{
	repl_item	*item;
	GHashTableIter	 iter;
	gpointer	 key;
	gpointer	 value;

	init_prov_iter(&iter);
	while (g_hash_table_iter_next(&iter,&key,&value)) {
		if (!strcmp(key,me)) {
			continue;
		}
		DPRINTF("replicating %s(%s) on %s\n",
			(action == REPL_ODELETE ? "delete" : "create"),
			name,
			((provider_t *)value)->name);
		item = malloc(sizeof(*item));
		if (!item) {
			error(0,errno,"could not create repl_item for %s",
			      name);
			return;
		}
		item->type = action;
		item->path = strdup(name);
		if (!item->path) {
			free(item);
			return;
		}
		item->server = (provider_t *)value;
		item->ms = ms;
		g_atomic_int_inc(&ms->refcnt);
		pthread_mutex_lock(&queue_lock);
		if (queue_tail) {
			item->next = queue_tail->next;
			queue_tail->next = item;
		}
		else {
			item->next = NULL;
			queue_head = item;
		}
		queue_tail = item;
		pthread_mutex_unlock(&queue_lock);
		g_atomic_int_inc(&rep_count);
		sem_post(&queue_sema);
	}
}

void
replicate_delete (const char *name, my_state *ms)
{
	replicate_namespace_action(name,REPL_ODELETE,ms);
}

void
replicate_bcreate (const char *name, my_state *ms)
{
	replicate_namespace_action(name,REPL_BCREATE,ms);
}

/* Part of our API to the query module. */
char *
follow_link (char *object, const char *key)
{
	char	*slash;
	char	*value	= NULL;

	slash = strchr(object,'/');
	if (!slash) {
		return NULL;
	}

	*(slash++) = '\0';
	(void)meta_get_value(object,slash,key,&value);
	*(--slash) = '/';

	DPRINTF("%s: %s:%s => %s\n",__func__,object,key,value);
	return value;
}

int
get_rep_count (void)
{
	return g_atomic_int_get(&rep_count);
}
