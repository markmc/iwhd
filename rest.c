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

#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>

#include <microhttpd.h>
#include <hstor.h>	/* only for ARRAY_SIZE at this point */
#include <curl/curl.h>
#include <glib.h>

#include "dirname.h"
#include "iwh.h"
#include "closeout.h"
#include "hash.h"
#include "progname.h"
#include "meta.h"
#include "backend.h"
#include "setup.h"
#include "replica.h"
#include "template.h"
#include "mpipe.h"
#include "state_defs.h"

/* Define-away for now.  Eventually, define to gettext.  */
#define _(msgid) (msgid)

#if defined(DEBUG)
#define MY_MHD_FLAGS MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG
//#define MY_MHD_FLAGS MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG
#else
#define MY_MHD_FLAGS MHD_USE_THREAD_PER_CONNECTION
#endif

typedef enum {
	URL_ROOT=0, URL_BUCKET, URL_OBJECT, URL_ATTR, URL_INVAL,
	URL_QUERY, URL_PROVLIST, URL_PROVIDER, URL_PROVIDER_SET_PRIMARY
} url_type;

typedef struct {
	const char			*method;
	url_type			 utype;
	MHD_AccessHandlerCallback	 handler;
} rule;

static unsigned short		 my_port	= MY_PORT;
char				*cfg_file	= NULL;

static const char *const (reserved_name[]) = {"_default", "_new", "_policy", "_query", NULL};
static const char *const (reserved_attr[]) = {"_bucket", "_date", "_etag", "_key", "_loc", "_size", NULL};
static const char *const (reserved_bucket_name[]) = {"_new", "_providers", NULL};

static int
validate_put (struct MHD_Connection *conn)
{
	const char	*mhdr;

	mhdr = MHD_lookup_connection_value(conn,MHD_HEADER_KIND,
		"X-redhat-role");
	/*
	 * This will fail most obviously in the case where we are not the
	 * master, we know we're not the master, and we don't see this
	 * header (which is set in master-to-slave replication requests).
	 * It will *also* fail, deliberately, if we do see this header when
	 * we think we're the master, as it means there's a mismatch between
	 * their config and ours.  This avoids "strange" behavior in such
	 * cases, in favor of a more obvious failure.
	 * TBD: this will be less of a problem if/when we identify the
	 * master and DB via the config file instead of -m/-d.
	 */
	if (master_host) {
		return (mhdr && !strcmp(mhdr,"master"));
	}
	else {
		return !mhdr;
	}
}

static int
is_reserved (const char *cand, char const *const *resv_list)
{
	int	i;

	for (i = 0; resv_list[i]; ++i) {
		if (!strcmp(cand,resv_list[i])) {
			return TRUE;
		}
	}

	return FALSE;
}

static int
validate_url (const char *url)
{
	char	*slash	= strrchr(url,'/');

	if (!slash) {
		/* There should be at least one betwixt bucket and key. */
		return 0;
	}

	return !is_reserved(slash+1,reserved_name);
}

/**********
 * The proxy has MHD on one side and CURL on the other.  The CURL side is
 * always run in a child thread.  Yes, there are both context switches
 * and copies between the threads.  Get over it.  The focus here is on
 * supporting multi-way replication on PUT, with minimal complexity.  These
 * were the two easiest libraries to use, and they both want to allocate
 * their own buffers so we're kind of stuck with the copies unless we want
 * to buffer whole files in memory (which would have to be virtual since
 * they're potentialy bigger than physical) or explicitly ping them through
 * a local filesystem.  We could potentially take over scheduling from one
 * or both to avoid some of the context switching, but those interfaces are
 * significantly more error-prone and (at least in CURL's case) buggy.
 *
 * For a GET, the CURL child acts as a producer while the MHD parent acts
 * as consumer.  For a PUT, the MHD parent is the producer and the CURL
 * child is the consumer.  For GET the MHD component is invoked via a
 * callback set up in the access handler; for PUT it's invoked via repeated
 * calls to the access handler itself.  Either way, the producer's job is
 * to post its pointer+length to the my_state structure and then wait for
 * all consumers to check back in saying they've finished it.  This might
 * involve multiple passes through each consumer for one pass through the
 * single producer.  When the producer is done, it does a similar handshake
 * with the consumers.  Each consumer has its own pipe_private structure,
 * containing a pointer to the shared my_state plus a per-consumer offset
 * into the current chunk.
 *
 * Attribute functions don't use CURL, so they do much simpler in-memory
 * buffering.  Queries also don't use CURL, but the MHD POST interface
 * introduces some of its own complexity so see below for that.
 **********/

static void
simple_closer (void *ctx)
{
	my_state	*ms	= ctx;

	DPRINTF("%s: cleaning up\n",__func__);
}

static void
child_closer (void * ctx)
{
	pipe_private	*pp	= ctx;

	DPRINTF("in %s\n",__func__);
}

/* Invoked from MHD. */
static ssize_t
proxy_get_cons (void *ctx, uint64_t pos, char *buf, size_t max)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	ssize_t		 done;
	void		*child_res;

	(void)pos;

	DPRINTF("consumer asked to read %zu\n",max);

	if (pipe_cons_wait(pp)) {
		DPRINTF("consumer offset %zu into %zu\n",
			pp->offset, ps->data_len);
		if (ps->data_len < pp->offset)
			// Warn about bogus offset?
			done = -1;
		else {
			done = ps->data_len - pp->offset;
			if ((size_t) done > max) {
				done = max;
			}
			memcpy(buf,(char *)(ps->data_ptr)+pp->offset,done);
			pp->offset += done;
			DPRINTF("consumer copied %zu, new offset %zu\n",
				done, pp->offset);
			if (pp->offset == ps->data_len) {
				DPRINTF("consumer finished chunk\n");
				pipe_cons_signal(pp, 0);
			}
		}
	}
	else {
		done = -1;
	}

	if (done == (-1)) {
		child_res = NULL;
		pthread_join(ms->backend_th,&child_res);
		if (child_res == THREAD_FAILED) {
			DPRINTF("GET producer failed\n");
			/* Nothing we can do; already sent status. */
		}
		if (ms->from_master) {
			pthread_join(ms->cache_th,NULL);
			/* TBD: do something about cache failure? */
		}
	}

	return done;
}

static int
proxy_get_data (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	pipe_private		*pp;
	pipe_private		*pp2;
	char			*my_etag;
	const char		*user_etag;
	int                      rc;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	DPRINTF("PROXY GET DATA %s\n",url);

	ms->url = strdup(url);
	if (!ms->url) {
		return MHD_NO;
	}

	my_etag = meta_has_copy(ms->bucket,ms->key,me);
	if (!my_etag) {
		DPRINTF("falling back to local for %s/%s\n",ms->bucket,ms->key);
		ms->from_master = 0;
	}
	else if (*my_etag) {
		user_etag = MHD_lookup_connection_value(
			conn, MHD_HEADER_KIND, "If-None-Match");
		if (user_etag && !strcmp(user_etag,my_etag)) {
			DPRINTF("ETag match!\n");
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			MHD_queue_response(conn,MHD_HTTP_NOT_MODIFIED,resp);
			MHD_destroy_response(resp);
			return MHD_YES;
		}
		ms->from_master = 0;
	}
	else {
		DPRINTF("%s/%s not found locally\n",ms->bucket,ms->key);
		if (!master_host) {
			DPRINTF("  that means it doesn't exist\n");
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			MHD_queue_response(conn,MHD_HTTP_NOT_FOUND,resp);
			MHD_destroy_response(resp);
			return MHD_YES;
		}
		DPRINTF("  will fetch from %s:%u\n", master_host,master_port);
		ms->from_master = 1;
	}

	pipe_init_shared(&ms->pipe,ms,ms->from_master+1);
	pp = pipe_init_private(&ms->pipe);
	if (!pp) {
		return MHD_NO;
	}
	provider_t *main_prov = get_main_provider();
	ms->thunk.parent = ms;
	ms->thunk.prov = ms->from_master ? g_master_prov : main_prov;
	pthread_create(&ms->backend_th,NULL,
		ms->thunk.prov->func_tbl->get_child_func,&ms->thunk);
	/* TBD: check return value */

	if (ms->from_master) {
		pp2 = pipe_init_private(&ms->pipe);
		if (!pp2) {
			return MHD_NO;
		}
		pp2->prov = main_prov;
		pthread_create(&ms->cache_th,NULL,
			main_prov->func_tbl->cache_child_func,pp2);
		/* TBD: check return value */
	}
	else {
		pp2 = NULL;
	}

	rc = pipe_cons_wait_init(&ms->pipe);
	ms->rc = (rc == 0) ? MHD_HTTP_OK : MHD_HTTP_INTERNAL_SERVER_ERROR;

	resp = MHD_create_response_from_callback(
		MHD_SIZE_UNKNOWN, 65536, proxy_get_cons, pp, child_closer);
	if (!resp) {
		fprintf(stderr,"MHD_crfc failed\n");
		if (pp2) {
			/* TBD: terminate thread */
		}
		child_closer(pp);
		return MHD_NO;
	}
	MHD_queue_response(conn,ms->rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static void
recheck_replication (my_state * ms, char *policy)
{
	int	rc;
	char	fixed[MAX_FIELD_LEN];

	if (is_reserved(ms->key,reserved_name)) {
		DPRINTF("declining to replicate reserved object %s\n",ms->key);
		return;
	}

	if (!policy && ms->dict) {
		DPRINTF("using new policy for %s/%s\n",ms->bucket,ms->key);
		policy = g_hash_table_lookup(ms->dict,"_policy");
	}

	if (!policy) {
		DPRINTF("fetching policy for %s/%s\n",ms->bucket,ms->key);
		rc = meta_get_value(ms->bucket,ms->key, "_policy", &policy);
	}

	if (!policy) {
		DPRINTF("  inheriting policy from %s\n",ms->bucket);
		rc = meta_get_value(ms->bucket,
			"_default", "_policy", &policy);
	}

	if (policy) {
		DPRINTF("  implementing policy %s\n",policy);
		/*
		 * Can't use ms->url here because it might be a bucket POST
		 * and in that case ms->url points to the bucket.
		 */
		snprintf(fixed,sizeof(fixed),"%s/%s",ms->bucket,ms->key);
		replicate(fixed,0,policy,ms);
	}
	else {
		DPRINTF("  could not find a policy anywhere!\n");
	}
}

static int
proxy_put_data (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	pipe_private		*pp;
	int			 rc;
	char			*etag	= NULL;
	void			*child_res;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("PROXY PUT DATA %s (%zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		if (!validate_put(conn) || !validate_url(url)) {
			DPRINTF("rejecting %s\n",url);
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			if (!resp) {
				return MHD_NO;
			}
			MHD_queue_response(conn,MHD_HTTP_FORBIDDEN,resp);
			MHD_destroy_response(resp);
			return MHD_YES;
		}
		ms->state = MS_NORMAL;
		ms->url = strdup(url);
		if (!ms->url) {
			return MHD_NO;
		}
		ms->size = 0;
		pipe_init_shared(&ms->pipe,ms,1);
		pp = pipe_init_private(&ms->pipe);
		if (!pp) {
			return MHD_NO;
		}
		provider_t *main_prov = get_main_provider();
		pp->prov = main_prov;
		ms->be_flags = BACKEND_GET_SIZE;
		pthread_create(&ms->backend_th,NULL,
			main_prov->func_tbl->put_child_func,pp);
		/* TBD: check return value */

		/*
		 * Do the initial handshake with children. If we return from
		 * this callback without an error response, Microhttpd posts
		 * the "100 Continue" header and the client starts sending
		 * the data. We must report errors here or forever keep
		 * our peace.
		 */
		rc = pipe_prod_wait_init(&ms->pipe);
		if (rc != 0) {
			DPRINTF("producer wait failed\n");
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			if (!resp) {
				return MHD_NO;
			}
			MHD_queue_response(conn,MHD_HTTP_INTERNAL_SERVER_ERROR,
				resp);
			MHD_destroy_response(resp);
		} else if (rc > 0) {
			/*
			 * Note that we fail here even if 1 of N replicas fail.
			 * Might want to fix this when we start looping over
			 * pipe_init_private() above.
			 */
			DPRINTF("producer replicas failed (%u of %u)\n",
				rc, ms->pipe.cons_total);
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			if (!resp) {
				return MHD_NO;
			}
			MHD_queue_response(conn,MHD_HTTP_INTERNAL_SERVER_ERROR,
				resp);
			MHD_destroy_response(resp);
		} else {
			DPRINTF("producer proceeding\n");
		}
	}
	else if (*data_size) {
		pipe_prod_signal(&ms->pipe,(void *)data,*data_size);
		ms->size += *data_size;
		DPRINTF("producer chunk finished\n");
		*data_size = 0;
	}
	else {
		pipe_prod_finish(&ms->pipe);
		pthread_join(ms->backend_th,&child_res);
		if (child_res == THREAD_FAILED) {
			DPRINTF("thread failed\n");
			rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
		else if (ms->pipe.cons_error == ms->pipe.cons_total) {
			DPRINTF("all %u consumers failed\n",
				ms->pipe.cons_error);
			rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			if (master_host) {
				meta_got_copy(ms->bucket,ms->key,me);
				etag = NULL;
			}
			else {
				etag = meta_did_put(ms->bucket,ms->key,me,
					ms->size);
			}
			DPRINTF("rereplicate (obj PUT)\n");
			recheck_replication(ms,NULL);
			rc = MHD_HTTP_OK;
		}
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			return MHD_NO;
		}
		if (etag) {
			MHD_add_response_header(resp,"ETag",etag);
		}
		MHD_queue_response(conn,rc,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

static int
proxy_get_attr (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	char			*fixed;
	my_state		*ms	= *rctx;
	int			 rc	= MHD_HTTP_NOT_FOUND;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	DPRINTF("PROXY GET ATTR %s\n",url);

	if (meta_get_value(ms->bucket,ms->key,ms->attr,&fixed) == 0) {
		resp = MHD_create_response_from_data(strlen(fixed),fixed,
			MHD_NO,MHD_NO);
		rc = MHD_HTTP_OK;
	}
	else {
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	}
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
proxy_put_attr (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	const char		*attrval;
	int			 send_resp = 0;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("PROXY PUT ATTR %s (%zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = strdup(url);
		if (!ms->url) {
			return MHD_NO;
		}
		attrval = MHD_lookup_connection_value(conn,MHD_HEADER_KIND,
			"X-redhat-value");
		if (attrval) {
			meta_set_value(ms->bucket,ms->key,ms->attr,
				(char *)attrval);
			send_resp = 1;
		}
	}
	else if (*data_size) {
		if (ms->pipe.data_len) {
			ms->pipe.data_len += *data_size;
			char *p = realloc(ms->pipe.data_ptr,ms->pipe.data_len);
			if (!p) {
				return MHD_NO;
			}
			ms->pipe.data_ptr = p;
		}
		else {
			ms->pipe.data_len = *data_size + 1;
			ms->pipe.data_ptr = malloc(ms->pipe.data_len);
			if (!ms->pipe.data_ptr) {
				return MHD_NO;
			}
			((char *)ms->pipe.data_ptr)[0] = '\0';
		}
		(void)strncat(ms->pipe.data_ptr,data,*data_size);
		/* TBD: check return value */
		*data_size = 0;
	}
	else {
		if (!ms->pipe.data_ptr) {
			return MHD_NO;
		}
		if (is_reserved(ms->attr,reserved_attr)) {
			resp = MHD_create_response_from_data(
				0,NULL,MHD_NO,MHD_NO);
			if (!resp) {
				return MHD_NO;
			}
			MHD_queue_response(conn,MHD_HTTP_BAD_REQUEST,
				resp);
			MHD_destroy_response(resp);
			return MHD_YES;
		}
		meta_set_value(ms->bucket,ms->key,ms->attr,ms->pipe.data_ptr);
		/*
		 * We should always re-replicate, because the replication
		 * policy might refer to this attr.
		 */
		DPRINTF("rereplicate (attr PUT)\n");
		recheck_replication(ms,NULL);
		send_resp = 1;
	}

	if (send_resp) {
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			return MHD_NO;
		}
		MHD_queue_response(conn,MHD_HTTP_CREATED,resp);
		MHD_destroy_response(resp);
		/*
		 * TBD: check if the attribute was a replication policy, and
		 * start/stop replication activities as appropriate.
		 */
	}

	return MHD_YES;
}

/**********
 * For queries, we have to deal with MHD's post-iterator interface (not
 * quite the same as the data-iteration even though we use it that way) on
 * one side, and a query-iterator interface on the other.  Data on both
 * sides could be quite large, so we can't just stick them in header lines.
 * We do still buffer the query in memory, though.  Once that's done, we do
 * very simple parsing - it will be more complicated later - and create the
 * query iterator.  That's also driven by MHD, this time though the
 * content-callback interface, and repeatedly calls in to the metadata
 * module to fetch one object name at a time.
 **********/

static int
query_iterator (void *ctx, enum MHD_ValueKind kind, const char *key,
		const char *filename, const char *content_type,
		const char *transfer_encoding, const char *data,
		uint64_t off, size_t size)
{
	(void)ctx;
	(void)kind;
	(void)key;
	(void)filename;
	(void)content_type;
	(void)transfer_encoding;
	(void)data;
	(void)off;
	(void)size;

	/* We actually accumulate the data in proxy_query. */
	return MHD_YES;
}

/* MHD reader function during queries.  Return -1 for EOF. */
static ssize_t
proxy_query_func (void *ctx, uint64_t pos, char *buf, size_t max)
{
	my_state	*ms	= ctx;
	size_t		 len;
	const char	*accept_hdr;
	char		*bucket;
	char		*key;

	(void)pos;

	accept_hdr = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,
		"Accept");

	if (!ms->gen_ctx) {
		ms->gen_ctx = tmpl_get_ctx(accept_hdr);
		if (!ms->gen_ctx) {
			return -1;
		}
		len = tmpl_list_header(ms->gen_ctx);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	if (ms->gen_ctx == TMPL_CTX_DONE) {
		return -1;
	}

	for(;;) {
		if (!meta_query_next(ms->query,&bucket,&key)) {
			break;
		}
		if (is_reserved(key,reserved_name)) {
			continue;
		}
		len = tmpl_list_entry(ms->gen_ctx,bucket,key);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	len = tmpl_list_footer(ms->gen_ctx);
	if (!len) {
		return -1;
	}
	if (len > max) {
		len = max;
	}
	memcpy(buf,ms->gen_ctx->buf,len);
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

static int
proxy_query (void *cctx, struct MHD_Connection *conn, const char *url,
	     const char *method, const char *version, const char *data,
	     size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("PROXY QUERY %s (%zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->post = MHD_create_post_processor(conn,4096,
			query_iterator,ms);
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		if (ms->pipe.data_len) {
			ms->pipe.data_len += *data_size;
			char *p = realloc(ms->pipe.data_ptr,ms->pipe.data_len);
			if (!p) {
				return MHD_NO;
			}
			ms->pipe.data_ptr = p;
		}
		else {
			ms->pipe.data_len = *data_size + 1;
			ms->pipe.data_ptr = malloc(ms->pipe.data_len);
			if (!ms->pipe.data_ptr) {
				return MHD_NO;
			}
			((char *)ms->pipe.data_ptr)[0] = '\0';
		}
		(void)strncat(ms->pipe.data_ptr,data,*data_size);
		/* TBD: check return value */
		*data_size = 0;
	}
	else {
		if (!ms->pipe.data_ptr) {
			return MHD_NO;
		}
		ms->query = meta_query_new(ms->bucket,NULL,ms->pipe.data_ptr);
		resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
			65536, proxy_query_func, ms, simple_closer);
		if (!resp) {
			fprintf(stderr,"MHD_crfc failed\n");
			simple_closer(ms);
			return MHD_NO;
		}
		MHD_queue_response(conn,MHD_HTTP_OK,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

static int
proxy_list_objs (void *cctx, struct MHD_Connection *conn, const char *url,
		 const char *method, const char *version, const char *data,
		 size_t *data_size, void **rctx)
{
	my_state	*ms	= *rctx;
	struct MHD_Response	*resp;

	(void)cctx;
	(void)url;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	ms->query = meta_query_new((char *)ms->bucket,NULL,NULL);

	resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		65536, proxy_query_func, ms, simple_closer);
	if (!resp) {
		fprintf(stderr,"MHD_crfc failed\n");
		simple_closer(ms);
		return MHD_NO;
	}

	MHD_queue_response(conn,MHD_HTTP_OK,resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

static int
proxy_delete (void *cctx, struct MHD_Connection *conn, const char *url,
	      const char *method, const char *version, const char *data,
	      size_t *data_size, void **rctx)
{
	my_state		*ms	= *rctx;
	struct MHD_Response	*resp;
	char			*copied_url;
	char			*bucket;
	char			*key;
	char			*stctx = NULL;
	int			 rc;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	DPRINTF("PROXY DELETE %s\n",url);

	provider_t *main_prov = get_main_provider();
	ms->thunk.parent = ms;
	ms->thunk.prov = main_prov;
	rc = ms->thunk.prov->func_tbl->delete_func(main_prov,
		ms->bucket,ms->key,url);
	if (rc == MHD_HTTP_OK) {
		copied_url = strdup(url);
		assert (copied_url);
		bucket = strtok_r(copied_url,"/",&stctx);
		key = strtok_r(NULL,"/",&stctx);
		meta_delete(bucket,key);
		replicate_delete(url,ms);
	}

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	error (0, 0, "DELETE BUCKET: rc=%d", rc);
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

/* TBD: get actual bucket list */
typedef struct {
	const char *rel;
	const char *link;
} fake_bucket_t;

/* FIXME: ensure that the RHS values here stay in sync with those
   in reserved_bucket_name.  */
static const fake_bucket_t fake_bucket_list[] = {
	{ "bucket_factory",	"_new" },
	{ "provider_list",	"_providers" },
};

static ssize_t
root_blob_generator (void *ctx, uint64_t pos, char *buf, size_t max)
{
	my_state	*ms	= ctx;
	const fake_bucket_t *fb;
	size_t		 len;
	const char	*accept_hdr;
	const char	*host;
	char		*bucket;
	char		*key;

	(void)pos;

	accept_hdr = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,
		"Accept");
	host = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,"Host");

	if (!ms->gen_ctx) {
		ms->gen_ctx = tmpl_get_ctx(accept_hdr);
		if (!ms->gen_ctx) {
			return -1;
		}
		ms->gen_ctx->base = host;
		len = tmpl_root_header(ms->gen_ctx,"image_warehouse",VERSION);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	if (ms->gen_ctx == TMPL_CTX_DONE) {
		return -1;
	}

	if (ms->gen_ctx->index < ARRAY_SIZE(fake_bucket_list)) {
		fb = fake_bucket_list + ms->gen_ctx->index;
		len = tmpl_root_entry(ms->gen_ctx,fb->rel,fb->link);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	if (meta_query_next(ms->query,&bucket,&key)) {
		len = tmpl_root_entry(ms->gen_ctx,"bucket",bucket);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	len = tmpl_root_footer(ms->gen_ctx);
	if (!len) {
		return -1;
	}
	if (len > max) {
		len = max;
	}
	memcpy(buf,ms->gen_ctx->buf,len);
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

static int
proxy_api_root (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp	= NULL;
	unsigned int		 rc	= MHD_HTTP_OK;
	my_state		*ms	= *rctx;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;

	DPRINTF("PROXY API ROOT (%s, %zu)\n",url,*data_size);

	ms->query = meta_query_new(NULL,"_default",NULL);
	if (!ms->query) {
		return MHD_NO;
	}
	resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		65536, root_blob_generator, ms, simple_closer);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;

}

static int
post_iterator (void *ctx, enum MHD_ValueKind kind, const char *key,
	       const char *filename, const char *content_type,
	       const char *transfer_encoding, const char *data,
	       uint64_t off, size_t size)
{
	char		*old_val;
	size_t		 old_len;
	char		*new_val;

	(void)kind;
	(void)filename;
	(void)content_type;
	(void)transfer_encoding;
	(void)off;

	printf("adding %s, size=%zu\n",key,size);

	// TBD: don't assume that values are null-terminated strings
	old_val = g_hash_table_lookup(ctx,key);
	if (old_val) {
		old_len = strlen(old_val);
		new_val = malloc(old_len+size+1);
		if (!new_val) {
			return MHD_NO;
		}
		memcpy(new_val,old_val,old_len);
		memcpy(new_val+old_len,data,size);
		new_val[old_len+size] = '\0';
	}
	else {
		new_val = malloc(size+1);
		if (!new_val) {
			return MHD_NO;
		}
		memcpy(new_val,data,size);
		new_val[size] = '\0';
	}

	char *k = strdup (key);
	if (!k) {
		free (new_val);
		return MHD_NO;
	}

	g_hash_table_insert(ctx,k,new_val);

	return MHD_YES;
}

/* Returns TRUE if we found an *invalid* key. */
static gboolean
post_find (gpointer key, gpointer value, gpointer ctx)
{
	(void)value;
	(void)ctx;

	if (!is_reserved(key,reserved_attr)) {
		return FALSE;
	}

	DPRINTF("bad attr %s\n", (char *)key);
	return TRUE;
}

static void
post_foreach (gpointer key, gpointer value, gpointer ctx)
{
	my_state	*ms	= ctx;

	DPRINTF("setting %s = %s for %s/%s\n",(char *)key, (char *)value,
		ms->bucket,ms->key);
	meta_set_value(ms->bucket,ms->key,key,value);
}

static int
create_bucket (char *name, my_state *ms)
{
	int	rc;

	if (is_reserved(name, reserved_name)
	    || is_reserved(name, reserved_bucket_name)) {
		return MHD_HTTP_BAD_REQUEST;
	}

	provider_t *main_prov = get_main_provider();
	rc = main_prov->func_tbl->bcreate_func(main_prov,name);
	if (rc == MHD_HTTP_OK) {
		if (meta_set_value(name,"_default", "_policy","0") != 0) {
			DPRINTF("default-policy " "create failed\n");
			/* Non-fatal. */
		}
		DPRINTF("created bucket %s\n",name);
		/*
		 * There's not a whole lot to do about bucket-creation
		 * failures on replicas, other than to report them, unless
		 * we adopt an "all or nothing" approach and unwind the
		 * create on the primary as well.  Then what if that fails?
		 * It's just one example of the general "fewer replicas
		 * than desired" distributed-system problem, not worth a
		 * point solution here/now.  Revisit when we have a more
		 * general replica-repair policy/system in place.
		 */
		replicate_bcreate(name,ms);
	}

	return rc;
}

static int
control_api_root (void *cctx, struct MHD_Connection *conn, const char *url,
		  const char *method, const char *version, const char *data,
		  size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc;
	char			*op;
	char			 buf[80];
	int			 len;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("ROOT POST (%s, %zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,NULL,NULL);
		ms->post = MHD_create_post_processor(conn,4096,
			post_iterator,ms->dict);
		return MHD_YES;
	}

	if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
		return MHD_YES;
	}

	rc = MHD_HTTP_BAD_REQUEST;

	op = g_hash_table_lookup(ms->dict,"op");
	if (op) {
		if (!strcmp(op,"rep_status")) {
			len = snprintf(buf,sizeof(buf),"%d requests\n",
				get_rep_count());
			rc = MHD_HTTP_OK;
		}
		else {
			len = snprintf(buf,sizeof(buf),"unknown op");
		}
	}
	else {
		len = snprintf(buf,sizeof(buf),"missing op");
	}

	if (len >= (int)sizeof(buf)) {
		len = 0;
		rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* NB The last arg tells MHD to copy the arg and free it later. */
	resp = MHD_create_response_from_data(len,buf,MHD_NO,MHD_YES);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
proxy_bucket_post (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc;
	char			*key;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("PROXY POST (%s, %zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,NULL,NULL);
		ms->post = MHD_create_post_processor(conn,4096,
			post_iterator,ms->dict);
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
	}
	else {
		rc = MHD_HTTP_BAD_REQUEST;
		key = g_hash_table_lookup(ms->dict,"_key");
		if (key) {
			strncpy(ms->key,key,MAX_FIELD_LEN-1);
			g_hash_table_remove(ms->dict,"_key");
			if (!g_hash_table_find(ms->dict,post_find,ms)) {
				g_hash_table_foreach(ms->dict,post_foreach,ms);
				DPRINTF("rereplicate (bucket POST)\n");
				recheck_replication(ms,NULL);
				rc = MHD_HTTP_OK;
			}
		}
		else if (!strcmp(ms->bucket,"_new")) {
			key = g_hash_table_lookup(ms->dict,"name");
			if (key != NULL) {
				rc = create_bucket(key,ms);
			}
		}
		else  {
			DPRINTF("A parameter is MISSING (fail)\n");
		}
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			fprintf(stderr,"MHD_crfd failed\n");
			return MHD_NO;
		}
		MHD_queue_response(conn,rc,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

static int
check_location (my_state *ms)
{
	char	*loc	= g_hash_table_lookup(ms->dict,"depot");

	if (!loc) {
		DPRINTF("missing loc on check for %s/%s\n",ms->bucket,ms->key);
		return MHD_HTTP_BAD_REQUEST;
	}

	if (!meta_has_copy(ms->bucket,ms->key,loc)) {
		DPRINTF("did not find %s/%s at %s\n",ms->bucket,ms->key,loc);
		return MHD_HTTP_NOT_FOUND;
	}

	/* TBD: meta_has_copy returns an etag which we should check */
	DPRINTF("found %s/%s at %s\n",ms->bucket,ms->key,loc);
	return MHD_HTTP_OK;
}

static int
register_image (my_state *ms)
{
	const char		*site;
	const provider_t	*prov;
	char			*next;

	site = g_hash_table_lookup(ms->dict,"site");
	if (!site) {
		printf("site MISSING\n");
		return MHD_HTTP_BAD_REQUEST;
	}

	next = strchr(site,':');
	if (next) {
		*(next++) = '\0';
	}

	prov = get_provider(site);
	if (!prov) {
		DPRINTF("site %s not found\n",site);
		return MHD_HTTP_BAD_REQUEST;
	}

	return prov->func_tbl->register_func(ms,prov,next,ms->dict);

}

static ssize_t
parts_callback (void *ctx, uint64_t pos, char *buf, size_t max)
{
	my_state	*ms	= ctx;
	size_t		 len;
	const char	*accept_hdr;
	const char	*name;
	const char	*value;
	const char	*host;

	(void)pos;

	accept_hdr = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,
		"Accept");
	host = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,"Host");

	if (!ms->gen_ctx) {
		ms->gen_ctx = tmpl_get_ctx(accept_hdr);
		if (!ms->gen_ctx) {
			return -1;
		}
		ms->gen_ctx->base = host;
		len = tmpl_obj_header(ms->gen_ctx,ms->bucket,ms->key);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	if (ms->gen_ctx == TMPL_CTX_DONE) {
		return -1;
	}


	// Set up and use query for what attributes exist.
	for(;;) {
		if (!meta_attr_next(ms->aquery,&name,&value)) {
			break;
		}
		if (is_reserved(name,reserved_attr)) {
			continue;
		}
		len = tmpl_obj_entry(ms->gen_ctx,ms->bucket,ms->key,name);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	len = tmpl_obj_footer(ms->gen_ctx);
	if (!len) {
		return -1;
	}
	if (len > max) {
		len = max;
	}
	memcpy(buf,ms->gen_ctx->buf,len);
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

static int
show_parts (struct MHD_Connection *conn, my_state *ms)
{
	struct MHD_Response	*resp;

	ms->aquery = meta_get_attrs(ms->bucket,ms->key);
	if (!ms->aquery) {
		return MHD_HTTP_NOT_FOUND;
	}

	resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		65536, parts_callback, ms, simple_closer);
	if (!resp) {
		fprintf(stderr,"MHD_crfc failed\n");
		simple_closer(ms);
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_OK,resp);
	MHD_destroy_response(resp);
	return MHD_HTTP_PROCESSING;
}

static int
proxy_object_post (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc;
	char			*op;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("PROXY POST obj (%s, %zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,NULL,NULL);
		ms->post = MHD_create_post_processor(conn,4096,
			post_iterator,ms->dict);
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
	}
	else {
		rc = MHD_HTTP_BAD_REQUEST;
		if (!g_hash_table_find(ms->dict,post_find,ms)) {
			op = g_hash_table_lookup(ms->dict,"op");
			if (op) {
				if (!strcmp(op,"push")) {
					DPRINTF("rereplicate (obj POST)\n");
					recheck_replication(ms,NULL);
					rc = MHD_HTTP_OK;
				}
				else if (!strcmp(op,"check")) {
					rc = check_location(ms);
				}
				else if (!strcmp(op,"register")) {
					rc = register_image(ms);
				}
				else if (!strcmp(op,"parts")) {
					rc = show_parts(conn,ms);
				}
				else {
					DPRINTF("unknown op %s for %s/%s\n",
						op, ms->bucket, ms->key);
				}
			}
			else  {
				DPRINTF("op is MISSING (fail)\n");
			}
		}
		if (rc != MHD_HTTP_PROCESSING) {
			/*
			 * MHD_HTTP_PROCESSING is a special response that
			 * means a request-specific routine (e.g. show_parts)
			 * created its own response.  Therefore we shouldn't.
			 */
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			if (!resp) {
				fprintf(stderr,"MHD_crfd failed\n");
				return MHD_NO;
			}
			MHD_queue_response(conn,rc,resp);
			MHD_destroy_response(resp);
		}
	}

	return MHD_YES;

}


static ssize_t
prov_list_generator (void *ctx, uint64_t pos, char *buf, size_t max)
{
	my_state		*ms	= ctx;
	size_t			 len;
	const char		*accept_hdr;

	(void)pos;

	accept_hdr = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,
		"Accept");

	if (!ms->gen_ctx) {
		ms->gen_ctx = tmpl_get_ctx(accept_hdr);
		if (!ms->gen_ctx) {
			return -1;
		}
		ms->prov_iter = hash_get_first_prov ();
		len = tmpl_prov_header(ms->gen_ctx);
		if (!len) {
			return -1;
		}
		if (len > max) {
			/* FIXME: don't truncate.  Doing that would
			   result in syntactically invalid output.  */
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	if (ms->gen_ctx == TMPL_CTX_DONE) {
		return -1;
	}

	const provider_t *prov = ms->prov_iter;
	if (prov) {
		ms->prov_iter = hash_get_next_prov (ms->prov_iter);
		if (prov->deleted)
			return 0;
		len = tmpl_prov_entry(ms->gen_ctx,prov->name,prov->type,
			prov->host, prov->port, prov->username, prov->password);
		if (!len) {
			return -1;
		}
		if (len > max) {
			len = max;
		}
		memcpy(buf,ms->gen_ctx->buf,len);
		return len;
	}

	len = tmpl_prov_footer(ms->gen_ctx);
	if (!len) {
		return -1;
	}
	if (len > max) {
		len = max;
	}
	memcpy(buf,ms->gen_ctx->buf,len);
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

static int
proxy_list_provs (void *cctx, struct MHD_Connection *conn, const char *url,
		  const char *method, const char *version, const char *data,
		  size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;

	(void)cctx;
	(void)url;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		65536, prov_list_generator, ms, simple_closer);
	if (!resp) {
		fprintf(stderr,"MHD_crfd failed\n");
		simple_closer(ms);
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_OK,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
prov_iterator (void *ctx, enum MHD_ValueKind kind, const char *key,
	       const char *filename, const char *content_type,
	       const char *transfer_encoding, const char *data,
	       uint64_t off, size_t size)
{
	(void)kind;
	(void)filename;
	(void)content_type;
	(void)transfer_encoding;
	(void)off;

	g_hash_table_insert(ctx,strdup(key),strndup(data,size));
	/* TBD: check return value for strdups (none avail for insert) */
	return MHD_YES;
}

static char *
url_to_provider_name (const char *url)
{
  char *p = strdup (url);
  if (p == NULL)
    return NULL;

  /* Ensure we handle trailing slashes (i.e., remove them).  */
  strip_trailing_slashes (p);

  char *prov_name = strdup (last_component (p));
  return prov_name;
}

static int
proxy_primary_prov (void *cctx, struct MHD_Connection *conn, const char *url,
		    const char *method, const char *version, const char *data,
		    size_t *data_size, void **rctx)
{
	(void)cctx;
	(void)method;
	(void)version;
	(void)data;

	DPRINTF("PROXY GET PRIMARY PROVIDER (%s)\n", url);

	my_state *ms = *rctx;

	// "/_providers/_primary" is the only one we accept for now.
	bool valid = strcmp (url, "/_providers/_primary") == 0;
	unsigned int rc = (valid ? MHD_HTTP_OK : MHD_HTTP_BAD_REQUEST);
	if (!valid)
		error (0, 0, "invalid request: %s", url);

	const char *name = get_main_provider()->name;
	struct MHD_Response *resp;
	resp = MHD_create_response_from_data(valid ? strlen (name) : 0,
					     valid ? (void *) name : NULL,
					     MHD_NO, MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
proxy_set_primary (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	(void)cctx;
	(void)method;
	(void)version;
	(void)data;

	DPRINTF("PROXY SET PRIMARY PROVIDER (%s)\n", url);

	my_state *ms = *rctx;
	char *name = NULL;
	unsigned int rc = MHD_HTTP_BAD_REQUEST;

	/* URL is guaranteed to be of the form "/_providers/NAME/_primary"
	   Extract NAME:  */
	bool valid = memcmp (url, "/_providers/", strlen("/_providers/")) == 0;
	if (!valid) {
		error (0, 0, "invalid request: %s", url);
		goto bad_set;
	}
	const char *start = url + strlen("/_providers/");
	const char *slash = strchr (start, '/');
	if (slash == NULL) {
		error (0, 0, "invalid request: %s", url);
		goto bad_set;
	}
	name = strndup (start, slash - start);
	if (name == NULL) {
		error (0, errno, "failed to extract provider name: %s", url);
		goto bad_set;
	}

	/* If it's not a provider name, you lose.  */
	provider_t *prov = find_provider (name);
	if (prov) {
		rc = MHD_HTTP_OK;
		set_main_provider (prov);
	}

 bad_set:;

	struct MHD_Response *resp;
	resp = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
proxy_delete_prov (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	DPRINTF("PROXY DELETE PROVIDER %s\n",url);
	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	my_state *ms = *rctx;
	struct MHD_Response *resp
	  = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}

	char *prov_name = url_to_provider_name (url);
	provider_t *prov = find_provider (prov_name);

	// don't allow removal of current main provider.
	if (prov == get_main_provider())
		prov = NULL;

	int rc = prov ? MHD_HTTP_OK : MHD_HTTP_NOT_FOUND;

	DPRINTF("PROXY DELETE PROVIDER prov=%s rc=%d\n", prov_name, rc);

	if (prov) {
		prov->deleted = 1;
	}

	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static int
proxy_add_prov (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	DPRINTF("PROXY ADD PROVIDER %s\n",url);
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;

	(void)cctx;
	(void)method;
	(void)version;

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,NULL,NULL);
		ms->post = MHD_create_post_processor(conn,4096,
			prov_iterator,ms->dict);
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
	}
	else {
		int rc = MHD_HTTP_BAD_REQUEST;
		char *prov_name = url_to_provider_name (url);
		/* We're about to insert "name -> $prov_name".
		   Ensure there is no "name" key already there.  */
		const char *name = g_hash_table_lookup (ms->dict, "name");
		if (name) {
			fprintf(stderr,
				"add_provider: do not specify name: name=%s\n",
				name);
			goto add_fail;
		}

		// another reserved word: provider name
		// FIXME: don't hard-code it here
		if (strcmp (prov_name, "_primary") == 0) {
			fprintf(stderr,
				"add_provider: %s is a reserved name\n",
				prov_name);
			goto add_fail;
		}

		// FIXME: unchecked strdup
		g_hash_table_insert(ms->dict,strdup("name"),prov_name);

		if (validate_provider (ms->dict)) {
			if (!add_provider (ms->dict)) {
			      DPRINTF("add provider failed\n");
			} else {
			      rc = MHD_HTTP_OK;
			}
		}
		else {
			DPRINTF("invalid provider\n");
		}

	add_fail:
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			fprintf(stderr,"MHD_crfd failed\n");
			return MHD_NO;
		}
		MHD_queue_response(conn,rc,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

static int
proxy_create_bucket (void *cctx, struct MHD_Connection *conn, const char *url,
		     const char *method, const char *version, const char *data,
		     size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;
	(void)url;

	/* curl -T moo.empty http://localhost:9090/_new   by accident */
	rc = create_bucket(ms->bucket,ms);

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		fprintf(stderr,"MHD_crfd failed\n");
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

static const rule my_rules[] = {
	{ /* get bucket list */
	  "GET",	URL_ROOT,	proxy_api_root  	},
	{ /* perform a control operation on the API root */
	  "POST",	URL_ROOT,	control_api_root	},
	{ /* get object list */
	  "GET",	URL_BUCKET,	proxy_list_objs		},
	{ /* create bucket */
	  "PUT",	URL_BUCKET,	proxy_create_bucket	},
	{ /* get object data */
	  "GET",	URL_OBJECT,	proxy_get_data		},
	{ /* get attribute data */
	  "GET",	URL_ATTR,	proxy_get_attr		},
	{ /* put object data */
	  "PUT",	URL_OBJECT,	proxy_put_data		},
	{ /* put attribute data */
	  "PUT",	URL_ATTR,	proxy_put_attr		},
	{ /* create object and/or modify attributes */
	  "POST",	URL_BUCKET,	proxy_bucket_post	},
	{ /* perform control operations on an object */
	  "POST",	URL_OBJECT,	proxy_object_post	},
	{ /* query */
	  "POST",	URL_QUERY,	proxy_query		},
	{ /* delete object */
	  "DELETE",	URL_OBJECT,	proxy_delete		},
	{ /* delete attribute (TBD) */
	  "DELETE",	URL_ATTR,	NULL			},
	{ /* get provider list */
	  "GET",	URL_PROVLIST,	proxy_list_provs	},
	{ /* get the primary provider */
	  "GET",	URL_PROVIDER,	proxy_primary_prov	},
	{ /* create a provider */
	  "POST",	URL_PROVIDER,	proxy_add_prov		},
	{ /* delete a provider */
	  "DELETE",	URL_PROVIDER,	proxy_delete_prov	},
	{ /* set the primary provider */
	  "PUT",	URL_PROVIDER_SET_PRIMARY, proxy_set_primary },
	{ NULL, 0, NULL }
};

static url_type
parse_url (const char *url, my_state *ms)
{
	unsigned short	esize;
	unsigned short	eindex;
	char *parts[URL_INVAL];

	if (strstr(url,"../")) {
		/* Naughty, naughty.  Never a good reason to allow this. */
		DPRINTF("Rejecting ../ in path.\n");
		return URL_INVAL;
	}

	eindex = URL_ROOT;
	parts[URL_BUCKET] = ms->bucket;
	parts[URL_OBJECT] = ms->key;
	parts[URL_ATTR] = ms->attr;

	for (;;) {
		while (*url == '/') {
			++url;
		}

		if (!*url) {
			if (eindex == URL_BUCKET) {
				if (!strcmp(ms->bucket,"_providers")) {
					eindex = URL_PROVLIST;
				}
			}
			else if (eindex == URL_OBJECT) {
				if (!strcmp(ms->key,"_query")) {
					eindex = URL_QUERY;
				}
			}
			break;
		}

		if (++eindex >= URL_INVAL) {
			return URL_INVAL;
		}
		esize = 0;

		while (*url && (*url != '/')) {
			parts[eindex][esize++] = *(url++);
			if (esize >= MAX_FIELD_LEN) {
				return URL_INVAL;
			}
		}
	}

	if (eindex == URL_OBJECT
	    && !strcmp (parts[URL_BUCKET], "_providers"))
	  eindex = URL_PROVIDER;
	else if (eindex == URL_ATTR
		 && !strcmp (parts[URL_BUCKET], "_providers")
		 && !strcmp (parts[URL_ATTR], "_primary"))
	  eindex = URL_PROVIDER_SET_PRIMARY;

	DPRINTF("parse_url: %d: %s %s %s", eindex, parts[URL_BUCKET],
		parts[URL_OBJECT], parts[URL_ATTR]);
	return eindex;
}

static int
access_handler (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	unsigned int		 i;
	url_type		 utype;
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;

	if (ms) {
		return ms->handler(cctx,conn,url,method,version,
			data,data_size,rctx);
	}

	ms = calloc(sizeof(*ms), 1);
	if (!ms) {
		return MHD_NO;
	}

	utype = parse_url(url,ms);

	for (i = 0; my_rules[i].method; ++i) {
		if (utype != my_rules[i].utype) {
			continue;
		}
		if (strcmp(method,my_rules[i].method)) {
			continue;
		}
		if (!my_rules[i].handler) {
			break;
		}
		ms->handler	= my_rules[i].handler;
		ms->state	= MS_NEW;
		ms->url		= NULL;
		ms->post	= NULL;
		ms->conn	= conn;
		*rctx = ms;
		return ms->handler(cctx,conn,url,method,version,
			data,data_size,rctx);
	}

	if (!strcmp(method,"QUIT")) {
		(void)sem_post((sem_t *)cctx);
		return MHD_NO;
	}

	fprintf(stderr,"bad request m=%s u=%s\n",method,url);

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_NOT_FOUND,resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

/* These enum values cannot possibly conflict with the option values
   ordinarily used by commands, including CHAR_MAX + 1, etc.  Avoid
   CHAR_MIN - 1, as it may equal -1, the getopt end-of-options value.  */
enum
{
  GETOPT_HELP_CHAR = (CHAR_MIN - 2),
  GETOPT_VERSION_CHAR = (CHAR_MIN - 3)
};

static const struct option my_options[] = {
	{ "autostart", no_argument,     NULL, 'a' },
	{ "config",  required_argument, NULL, 'c' },
	{ "db",      required_argument, NULL, 'd' },
	{ "master",  required_argument, NULL, 'm' },
	{ "port",    required_argument, NULL, 'p' },
	{ "verbose", no_argument,       NULL, 'v' },
	{ "version", no_argument,       NULL, GETOPT_VERSION_CHAR },
	{ "help", no_argument,          NULL, GETOPT_HELP_CHAR },
	{ NULL, 0, NULL, '\0' }
};

static void ATTRIBUTE_NORETURN
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      printf (_("\
Usage: %s [OPTION]\n\
"),
	      program_name);
      fputs (_("\
Deltacloud image-warehouse daemon.\n\
A configuration file must be specified.\n\
\n\
  -a, --autostart         start necessary back-end services\n\
  -c, --config=FILE       config file [required]\n\
  -d, --db=HOST_PORT      database server as ip[:port]\n\
  -m, --master=HOST_PORT  master (upstream) server as ip[:port]\n\
  -p, --port=PORT         alternate listen port (default 9090)\n\
  -v, --verbose           verbose/debug output\n\
\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n\
"), stdout);
      printf (_("\
\n\
Report %s bugs to %s.\n\
"),
	      program_name, PACKAGE_BUGREPORT);
    }
  exit (status);
}


int
main (int argc, char **argv)
{
	struct MHD_Daemon	*the_daemon;
	sem_t			 the_sem;
	char			*stctx = NULL;
	char			*port_tmp;
	bool			 autostart = false;

	set_program_name (argv[0]);
	atexit (close_stdout);
	GC_INIT ();

	for (;;) switch (getopt_long(argc,argv,"ac:d:m:p:v",my_options,NULL)) {
	case 'a':
		autostart = true;
		break;
	case 'c':
		cfg_file = optarg;
		break;
	case 'd':
		assert (optarg);
		db_host = strtok_r(optarg,":",&stctx);
		port_tmp = strtok_r(NULL,":",&stctx);
		if (port_tmp) {
			db_port = (unsigned short)strtoul(port_tmp,NULL,10);
		}
		break;
	case 'm':
		assert (optarg);
		master_host = strtok_r(optarg,":",&stctx);
		port_tmp = strtok_r(NULL,":",&stctx);
		if (port_tmp) {
			master_port = (unsigned short)strtoul(port_tmp,NULL,10);
		}
		break;
	case 'p':
		my_port = (unsigned short)strtoul(optarg,NULL,10);
		break;
	case 'v':
		++verbose;
		break;
	case GETOPT_HELP_CHAR:
		usage(EXIT_SUCCESS);
		break;
	case GETOPT_VERSION_CHAR:
		printf ("%s version %s\n", program_name, PACKAGE_VERSION);
		exit (EXIT_SUCCESS);
		break;

	case -1:
		goto args_done;
	default:
		usage(EXIT_FAILURE);
		break;
	}
args_done:

	if (!db_port) {
		db_port = autostart ? AUTO_MONGOD_PORT : 27017;
	}

	if (autostart && cfg_file) {
		error(0,0,"do not use -c and -a simultaneously");
		return !0;
	}
	else if (autostart && !cfg_file) {
		me = auto_config();
		if (!me) {
			/* error printed */
			return !0;
		}
	}
	else if (!autostart && cfg_file) {
		me = parse_config(cfg_file);
		if (!me) {
			error(0,0,"could not parse %s",cfg_file);
			return !0;
		}
	}
	else {
		error(0,0,"specify at least -c or -a");
		usage (EXIT_FAILURE);
	}

	sem_init(&the_sem,0,0);

	if (verbose) {
		provider_t *main_prov = get_main_provider();
		printf("primary store type is %s\n",main_prov->type);
		if (master_host) {
			printf("operating as slave to %s:%u\n",
				master_host, master_port);
		}
		printf("db is at %s:%u\n",db_host,db_port);
		printf("will listen on port %u\n",my_port);
		printf("my location is \"%s\"\n",me);
		if (fflush(stdout) || ferror(stdout))
			error(EXIT_FAILURE, 0, "write failed");
	}

	backend_init();
	meta_init();
	repl_init();

	/*
	 * Gotcha: if we don't set the connection memory limit explicitly,
	 * the per-connection buffer for MHD will be smaller than that used
	 * by CURL, so proxy_writefunc will never be able to do its job.
	 */
	the_daemon = MHD_start_daemon(MY_MHD_FLAGS,
		my_port, NULL, NULL, &access_handler, &the_sem,
		MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t)1048576,
		MHD_OPTION_END);
	if (!the_daemon) {
		fprintf(stderr,"Could not create daemon.\n");
		return !0;
	}

	sem_wait(&the_sem);
	return 0;
}
