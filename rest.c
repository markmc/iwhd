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
#include <assert.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>
#include <glib.h>

#include "repo.h"
#include "meta.h"
#include "proxy.h"
#include "template.h"
#include "mpipe.h"
#include "backend.h"
#include "state_defs.h"

#if defined(DEBUG)
#define MY_MHD_FLAGS MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG
//#define MY_MHD_FLAGS MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG
#else
#define MY_MHD_FLAGS MHD_USE_THREAD_PER_CONNECTION
#endif

extern backend_func_tbl	bad_func_tbl;
extern backend_func_tbl	s3_func_tbl;
extern backend_func_tbl	curl_func_tbl;

typedef enum {
	URL_ROOT=0, URL_BUCKET, URL_OBJECT, URL_ATTR, URL_INVAL,
	URL_QUERY, URL_PROVLIST
} url_type;

typedef struct {
	char				*method;
	url_type			 utype;
	MHD_AccessHandlerCallback	 handler;
} rule;

int			 fs_mode	= 0;
struct hstor_client	*hstor		= NULL;
unsigned short		 my_port	= MY_PORT;

/*
 * These values refer to a front end, but it's a fallback rather than a
 * primary front end.  Unlike the primary, which may use any of FS/S3/repod
 * mode, the master is always repod mode so it doesn't needs a key/secret.
 */
const char 		*master_host	= NULL;
unsigned short		 master_port	= MY_PORT;

char *(reserved_name[]) = { "_default", "_query", "_new", NULL };
char *(reserved_attr[]) = { "bucket", "key", "date", "etag", "loc", NULL };

backend_func_tbl *main_func_tbl = &bad_func_tbl;

void
free_ms (my_state *ms)
{
	if (ms->cleanup & CLEANUP_CURL) {
		curl_easy_cleanup(ms->curl);
	}

	if (ms->cleanup & CLEANUP_BUF_PTR) {
		free(ms->pipe.data_ptr);
	}

	if (ms->cleanup & CLEANUP_POST) {
		MHD_destroy_post_processor(ms->post);
	}

	if (ms->cleanup & CLEANUP_DICT) {
		g_hash_table_destroy(ms->dict);
	}

	if (ms->cleanup & CLEANUP_QUERY) {
		meta_query_stop(ms->query);
	}

	if (ms->cleanup & CLEANUP_TMPL) {
		free(ms->gen_ctx);
	}

	if (ms->cleanup & CLEANUP_URL) {
		free(ms->url);
	}

	free(ms);
}

int
validate_put (struct MHD_Connection *conn)
{
	const char	*mhdr;

	if (!master_host) {
		/* We're not a slave, so we don't care. */
		return 1;
	}

	mhdr = MHD_lookup_connection_value(conn,MHD_HEADER_KIND,
		"X-redhat-role");
	return (mhdr && !strcmp(mhdr,"master"));
}

int
is_reserved (char *cand, char **resv_list)
{
	int	i;

	for (i = 0; resv_list[i]; ++i) {
		if (!strcmp(cand,resv_list[i])) {
			return TRUE;
		}
	}

	return FALSE;
}

int
validate_url (const char *url)
{
	char	*slash	= rindex(url,'/');

	if (!slash) {
		/* There should be at least one betwixt bucket and key. */
		return 0;
	}

	return !is_reserved(slash+1,reserved_name);
}

/**********
 * The local server is intended mostly for testing.  Therefore, it supports
 * only basic get/put of files in the simplest possible way.  If you want to
 * create/delete buckets, use bash.  If you want to do anything with
 * metadata, use the mongo shell.  The only thing that should be talking to
 * a local server is a proxy server based on this same code.
 **********/

/*
 * We're reading from the perspective of MHD, which is calling us.  Return
 * -1 for EOF, other values (including zero) to indicate how much data we
 * filled.
 */
int
local_reader (void *ctx, uint64_t pos, char *buf, int max)
{
	int nb;

	(void)pos;

	nb = read(P2I(ctx),buf,max);
	DPRINTF("got %d from %d\n",nb,P2I(ctx));

	return (nb > 0) ? nb : (-1);
}

void
local_closer (void *ctx)
{
	fsync(P2I(ctx));
	close(P2I(ctx));
}

int
local_get_data (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	int			 fd;
	struct stat		 sb;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;
	(void)rctx;

	DPRINTF("LOCAL GET DATA %s\n",url);

	fd = open(url+1,O_RDONLY);
	if (fd >= 0) {
		/* Clients like to know size, but it's not required. */
		if (fstat(fd,&sb) < 0) {
			sb.st_size = MHD_SIZE_UNKNOWN;
		}
		/* Hack for testing. */
		if (!S_ISREG(sb.st_mode)) {
			sb.st_size = MHD_SIZE_UNKNOWN;
		}
		resp = MHD_create_response_from_callback(
			sb.st_size, 65536, &local_reader, I2P(fd),
			&local_closer);
		if (!resp) {
			return MHD_NO;
		}
		MHD_queue_response(conn,MHD_HTTP_OK,resp);
	}
	else {
		perror(url+1);
		resp = MHD_create_response_from_data(
			0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			return MHD_NO;
		}
		MHD_queue_response(conn,MHD_HTTP_NOT_FOUND,resp);
	}
	MHD_destroy_response(resp);

	return MHD_YES;
}

int
local_put_data (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response		*resp;
	my_state			*ms;
	int				 nb;
	int				 rc = MHD_HTTP_INTERNAL_SERVER_ERROR;

	(void)cctx;
	(void)method;
	(void)version;

	DPRINTF("LOCAL PUT DATA %s (%zu)\n",url,*data_size);

	ms = *rctx;
	if (ms->state == MS_NEW) {
		if (!validate_put(conn) || !validate_url(url)) {
			rc = MHD_HTTP_FORBIDDEN;
			goto free_it;
		}
		ms->state = MS_NORMAL;
		ms->fd = open(url+1,O_CREAT|O_TRUNC|O_WRONLY,0666);
		if (ms->fd < 0) {
			perror(url+1);
			goto free_it;
		}
		return MHD_YES;
	}

	if (*data_size == 0) {
		rc = MHD_HTTP_CREATED;
		goto close_it;
	}

	nb = write(ms->fd,data,*data_size);
	if (nb < 0) {
		perror(url+1);
		goto close_it;
	}

	*data_size -= nb;
	return MHD_YES;

close_it:
	close(ms->fd);
free_it:
	free_ms(ms);
	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

int
local_delete (void *cctx, struct MHD_Connection *conn, const char *url,
	      const char *method, const char *version, const char *data,
	      size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;
	(void)rctx;

	DPRINTF("LOCAL DELETE %s\n",url);
	if (unlink(url+1) < 0) {
		perror("unlink");
	}

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_OK,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

rule local_rules[] = {
	{ /* get bucket list */
	  "GET",	URL_ROOT,	NULL		},
	{ /* get object list */
	  "GET",	URL_BUCKET,	NULL		},
	{ /* get object data */
	  "GET",	URL_OBJECT,	local_get_data	},
	{ /* get attribute data */
	  "GET",	URL_ATTR,	NULL		},
	{ /* create bucket */
	  "PUT",	URL_BUCKET,	NULL		},
	{ /* put object data */
	  "PUT",	URL_OBJECT,	local_put_data	},
	{ /* put attribute data */
	  "PUT",	URL_ATTR,	NULL		},
	{ /* query */
	  "POST",	URL_ROOT,	NULL		},
	{ /* delete bucket */
	  "DELETE",	URL_BUCKET,	NULL		},
	{ /* delete object */
	  "DELETE",	URL_OBJECT,	local_delete	},
	{ /* delete attribute */
	  "DELETE",	URL_ATTR,	NULL		},
	{ NULL, 0, NULL }
};

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

void
simple_closer (void *ctx)
{
	my_state	*ms	= ctx;

	DPRINTF("%s: cleaning up\n",__func__);
	free_ms(ms);
}

void
child_closer (void * ctx)
{
	pipe_private	*pp	= ctx;

	DPRINTF("in %s\n",__func__);

	free(pp);
}

/* Invoked from MHD. */
int
proxy_get_cons (void *ctx, uint64_t pos, char *buf, int max)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	int		 done;
	void		*child_res;

	(void)pos;

	DPRINTF("consumer asked to read %d\n",max);

	if (pipe_cons_wait(pp)) {
		DPRINTF("consumer offset %zu into %zu\n",
			pp->offset, ps->data_len);
		done = ps->data_len - pp->offset;
		if (done > max) {
			done = max;
		}
		memcpy(buf,ps->data_ptr+pp->offset,done);
		pp->offset += done;
		DPRINTF("consumer copied %d, new offset %zu\n",
			done, pp->offset);
		if (pp->offset == ps->data_len) {
			DPRINTF("consumer finished chunk\n");
			pipe_cons_signal(pp);
		}
	}
	else {
		done = -1;
	}

	if (done == (-1)) {
		child_res = NULL;
		pthread_join(ms->backend_th,&child_res);
		if (child_res == THREAD_FAILED) {
			ms->rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
		if (master_host) {
			pthread_join(ms->cache_th,NULL);
			/* TBD: do something about cache failure? */
		}
	}

	return done;
}

int
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
	ms->cleanup |= CLEANUP_URL;

	my_etag = meta_has_copy(ms->bucket,ms->key,me);
	if (my_etag) {
		user_etag = MHD_lookup_connection_value(
			conn, MHD_HEADER_KIND, "If-None-Match");
		if (user_etag && !strcmp(user_etag,my_etag)) {
			DPRINTF("ETag match!\n");
			free(my_etag);
			resp = MHD_create_response_from_data(0,NULL,
				MHD_NO,MHD_NO);
			MHD_queue_response(conn,MHD_HTTP_NOT_MODIFIED,resp);
			MHD_destroy_response(resp);
			return MHD_YES;
		}
		free(my_etag);
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
	pthread_create(&ms->backend_th,NULL,main_func_tbl->get_child_func,ms);
	/* TBD: check return value */

	if (ms->from_master) {
		pp2 = pipe_init_private(&ms->pipe);
		if (!pp2) {
			return MHD_NO;
		}
		pthread_create(&ms->cache_th,NULL,
			main_func_tbl->cache_child_func,pp2);
		/* TBD: check return value */
	}
	else {
		pp2 = NULL;
	}

	resp = MHD_create_response_from_callback(
		MHD_SIZE_UNKNOWN, 65536, proxy_get_cons, pp, child_closer);
	if (!resp) {
		fprintf(stderr,"MHD_crfc failed\n");
		if (pp2) {
			/* TBD: terminate thread */
			free(pp2);
		}
		child_closer(pp);
		return MHD_NO;
	}
	MHD_queue_response(conn,ms->rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

void
recheck_replication (my_state * ms, char *policy)
{
	int	rc;
	int	free_it	= FALSE;
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
		/* If we get a policy here or below, we have to free it. */
		free_it = TRUE;
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
		replicate(fixed,0,policy);
		if (free_it) {
			free(policy);
		}
	}
	else {
		DPRINTF("  could not find a policy anywhere!\n");
	}
}

int
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
		ms->cleanup |= CLEANUP_URL;
		ms->size = 0;
		pipe_init_shared(&ms->pipe,ms,1);
		pp = pipe_init_private(&ms->pipe);
		if (!pp) {
			return MHD_NO;
		}
		pthread_create(&ms->backend_th,NULL,
			main_func_tbl->put_child_func,pp);
		/* TBD: check return value */
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
		free_ms(ms);
		resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
		if (!resp) {
			if (etag) {
				free(etag);
			}
			return MHD_NO;
		}
		if (etag) {
			MHD_add_response_header(resp,"ETag",etag);
			free(etag);
		}
		MHD_queue_response(conn,rc,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

int
proxy_get_attr (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	char			*fixed;
	my_state		*ms	= *rctx;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	DPRINTF("PROXY GET ATTR %s\n",url);

	meta_get_value(ms->bucket,ms->key,ms->attr,&fixed);

	resp = MHD_create_response_from_data(strlen(fixed),fixed,
		MHD_YES,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_CREATED,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

int
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
		ms->cleanup |= CLEANUP_URL;
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
			ms->cleanup |= CLEANUP_BUF_PTR;
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
			free_ms(ms);
			return MHD_YES;
		}
		meta_set_value(ms->bucket,ms->key,ms->attr,ms->pipe.data_ptr);
		/*
		 * We should always re-replicate, because the replication
		 * policy might refer to this attr.
		 */
		DPRINTF("rereplicate (attr PUT)\n");
		recheck_replication(ms,NULL);
		free_ms(ms);
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

int
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
int
proxy_query_func (void *ctx, uint64_t pos, char *buf, int max)
{
	my_state	*ms	= ctx;
	int		 len;
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
		ms->cleanup |= CLEANUP_TMPL;
		len = tmpl_obj_header(ms->gen_ctx);
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
		len = tmpl_obj_entry(ms->gen_ctx,bucket,key);
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
	free(ms->gen_ctx);
	ms->cleanup &= ~CLEANUP_TMPL;
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

int
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
		ms->cleanup |= CLEANUP_POST;
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
			ms->cleanup |= CLEANUP_BUF_PTR;
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
		ms->cleanup |= CLEANUP_QUERY;
		resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
			65536, proxy_query_func, ms, simple_closer);
		if (!resp) {
			fprintf(stderr,"MHD_crfc failed\n");
			simple_closer(ms);
			return MHD_NO;
		}
		MHD_add_response_header(resp,"Content-Type","text/xml");
		MHD_queue_response(conn,MHD_HTTP_OK,resp);
		MHD_destroy_response(resp);
	}

	return MHD_YES;
}

int
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
	ms->cleanup |= CLEANUP_QUERY;

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

int
proxy_delete (void *cctx, struct MHD_Connection *conn, const char *url,
	      const char *method, const char *version, const char *data,
	      size_t *data_size, void **rctx)
{
	my_state		*ms	= *rctx;
	struct MHD_Response	*resp;
	CURL			*curl;
	char			 fixed[1024];
	char			*copied_url;
	char			*bucket;
	char			*key;
	char			*stctx = NULL;

	(void)cctx;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	DPRINTF("PROXY DELETE %s\n",url);

	if (s3mode) {
		hstor_del(hstor,ms->bucket,ms->key);
		/* TBD: check return value */
	}
	else {
		curl = curl_easy_init();
		if (!curl) {
			return MHD_NO;
		}
		sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,url);
		curl_easy_setopt(curl,CURLOPT_URL,fixed);
		curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	copied_url = strdup(url);
	assert (copied_url);
	bucket = strtok_r(copied_url,"/",&stctx);
	key = strtok_r(NULL,"/",&stctx);
	meta_delete(bucket,key);
	free(copied_url);

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_add_response_header(resp,"Content-Type","text/xml");
	MHD_queue_response(conn,MHD_HTTP_OK,resp);
	MHD_destroy_response(resp);

	replicate_delete((char *)url);
	return MHD_YES;
}

/* TBD: get actual bucket list */
typedef struct {
	char *rel;
	char *link;
} fake_bucket_t;

fake_bucket_t fake_bucket_list[] = {
	{ "bucket_factory",	"_new" }
};

int
root_blob_generator (void *ctx, uint64_t pos, char *buf, int max)
{
	my_state	*ms	= ctx;
	fake_bucket_t *	 fb;
	int		 len;
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
		ms->cleanup |= CLEANUP_TMPL;
		ms->gen_ctx->base = host;
		len = tmpl_root_header(ms->gen_ctx,"image_warehouse","1.0");
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
	free(ms->gen_ctx);
	ms->cleanup &= ~CLEANUP_TMPL;
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

int
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
		free_ms(ms);
		return MHD_NO;
	}
	ms->cleanup |= CLEANUP_QUERY;

	resp = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		65536, root_blob_generator, ms, simple_closer);
	if (!resp) {
		return MHD_NO;
	}
	MHD_add_response_header(resp,"Content-Type","text/xml");
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;

}

int
post_iterator (void *ctx, enum MHD_ValueKind kind, const char *key,
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

/* Returns TRUE if we found an *invalid* key. */
gboolean
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

void
post_foreach (gpointer key, gpointer value, gpointer ctx)
{
	my_state	*ms	= ctx;

	DPRINTF("setting %s = %s for %s/%s\n",(char *)key, (char *)value,
		ms->bucket,ms->key);
	meta_set_value(ms->bucket,ms->key,key,value);
}

int
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
			g_str_hash,g_str_equal,free,free);
		ms->cleanup |= CLEANUP_DICT;
		ms->post = MHD_create_post_processor(conn,4096,
			post_iterator,ms->dict);
		ms->cleanup |= CLEANUP_POST;
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
	}
	else {
		rc = MHD_HTTP_BAD_REQUEST;
		key = g_hash_table_lookup(ms->dict,"key");
		if (key) {
			strncpy(ms->key,key,MAX_FIELD_LEN-1);
			g_hash_table_remove(ms->dict,"key");
			if (!g_hash_table_find(ms->dict,post_find,ms)) {
				g_hash_table_foreach(ms->dict,post_foreach,ms);
				DPRINTF("rereplicate (bucket POST)\n");
				recheck_replication(ms,NULL);
				rc = MHD_HTTP_OK;
			}
		}
		else  {
			DPRINTF("key is MISSING (fail)\n");
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

int
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

int
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

	DPRINTF("PROXY POST (%s, %zu)\n",url,*data_size);

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,free,free);
		ms->cleanup |= CLEANUP_DICT;
		ms->post = MHD_create_post_processor(conn,4096,
			post_iterator,ms->dict);
		ms->cleanup |= CLEANUP_POST;
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
				else {
					DPRINTF("unknown op %s for %s/%s\n",
						op, ms->bucket, ms->key);
				}
			}
			else  {
				DPRINTF("op is MISSING (fail)\n");
			}
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


int
prov_list_generator (void *ctx, uint64_t pos, char *buf, int max)
{
	my_state	*ms	= ctx;
	int		 len;
	provider_t	 prov;
	const char	*accept_hdr;

	(void)pos;

	accept_hdr = MHD_lookup_connection_value(ms->conn,MHD_HEADER_KIND,
		"Accept");

	if (!ms->gen_ctx) {
		ms->gen_ctx = tmpl_get_ctx(accept_hdr);
		if (!ms->gen_ctx) {
			return -1;
		}
		ms->cleanup |= CLEANUP_TMPL;
		len = tmpl_prov_header(ms->gen_ctx);
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

	if (get_provider(ms->gen_ctx->index,&prov)) {
		len = tmpl_prov_entry(ms->gen_ctx,prov.name,prov.type,
			prov.host, prov.port, prov.username, prov.password);
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
	free(ms->gen_ctx);
	ms->cleanup &= ~CLEANUP_TMPL;
	ms->gen_ctx = TMPL_CTX_DONE;
	return len;
}

int
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

int
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


int
proxy_update_prov (void *cctx, struct MHD_Connection *conn, const char *url,
		   const char *method, const char *version, const char *data,
		   size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc;
	char			*provider;
	char			*username;
	char			*password;

	(void)cctx;
	(void)method;
	(void)version;

	if (ms->state == MS_NEW) {
		ms->state = MS_NORMAL;
		ms->url = (char *)url;
		ms->dict = g_hash_table_new_full(
			g_str_hash,g_str_equal,free,free);
		ms->cleanup |= CLEANUP_DICT;
		ms->post = MHD_create_post_processor(conn,4096,
			prov_iterator,ms->dict);
		ms->cleanup |= CLEANUP_POST;
	}
	else if (*data_size) {
		MHD_post_process(ms->post,data,*data_size);
		*data_size = 0;
	}
	else {
		rc = MHD_HTTP_BAD_REQUEST;
		provider = g_hash_table_lookup(ms->dict,"provider");
		username = g_hash_table_lookup(ms->dict,"username");
		password = g_hash_table_lookup(ms->dict,"password");
		if (provider && username && password) {
			update_provider(provider,username,password);
			rc = MHD_HTTP_OK;
		}
		else {
			DPRINTF("provider/username/password MISSING\n");
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

int
proxy_create_bucket (void *cctx, struct MHD_Connection *conn, const char *url,
		     const char *method, const char *version, const char *data,
		     size_t *data_size, void **rctx)
{
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	int			 rc 	= MHD_HTTP_OK;

	(void)cctx;
	(void)url;
	(void)method;
	(void)version;
	(void)data;
	(void)data_size;

	if (s3mode) {
		DPRINTF("creating bucket %s\n",ms->bucket);
		if (!hstor_add_bucket(hstor,ms->bucket)) {
			DPRINTF("  bucket create failed\n");
			rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else {
		DPRINTF("cannot create bucket in non-S3 mode\n");
		//rc = MHD_HTTP_NOT_IMPLEMENTED;
	}

	if (rc == MHD_HTTP_OK) {
		if (meta_set_value(ms->bucket,"_default","_policy","1") != 0) {
			DPRINTF("default-policy create failed\n");
			/* Non-fatal. */
		}
	}

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		fprintf(stderr,"MHD_crfd failed\n");
		return MHD_NO;
	}
	MHD_queue_response(conn,rc,resp);
	MHD_destroy_response(resp);

	return MHD_YES;
}

rule proxy_rules[] = {
	{ /* get bucket list */
	  "GET",	URL_ROOT,	proxy_api_root  	},
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
	{ /* update a provider */
	  "POST",	URL_PROVLIST,	proxy_update_prov	},
	{ NULL, 0, NULL }
};

url_type
parse_url (const char *url, my_state *ms)
{
	unsigned short	esize;
	unsigned short	eindex;
	char *parts[URL_INVAL];

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

	return eindex;
}

int
access_handler (void *cctx, struct MHD_Connection *conn, const char *url,
		const char *method, const char *version, const char *data,
		size_t *data_size, void **rctx)
{
	unsigned int		 i;
	url_type		 utype;
	struct MHD_Response	*resp;
	my_state		*ms	= *rctx;
	rule		        *my_rules;

	if (ms) {
		return ms->handler(cctx,conn,url,method,version,
			data,data_size,rctx);
	}

	ms = malloc(sizeof(my_state));
	if (!ms) {
		return MHD_NO;
	}
	memset(ms,0,sizeof(*ms));

	my_rules = proxy_host ? proxy_rules : local_rules;
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
		ms->fd		= (-1);
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
	free_ms(ms);

	resp = MHD_create_response_from_data(0,NULL,MHD_NO,MHD_NO);
	if (!resp) {
		return MHD_NO;
	}
	MHD_queue_response(conn,MHD_HTTP_NOT_FOUND,resp);
	MHD_destroy_response(resp);
	return MHD_YES;
}

struct option my_options[] = {
	{ "config",  required_argument, NULL, 'c' },
	{ "db",      required_argument, NULL, 'd' },
	{ "fsmode",  no_argument,       NULL, 'f' },
	{ "master",  required_argument, NULL, 'm' },
	{ "port",    required_argument, NULL, 'p' },
	{ "verbose", no_argument,       NULL, 'v' },
	{ NULL, 0, NULL, '\0' }
};

void
exit_with_usage (char *prog)
{
	fprintf(stderr,"Usage: %s [options] [loc_id]\n",prog);
	fprintf(stderr,"  -c file  config file (default repo.json)\n");
	fprintf(stderr,"  -d db    database server as ip[:port]\n");
	fprintf(stderr,"  -f       local-filesystem mode for testing\n");
	fprintf(stderr,"  -m addr  master (upstream) server as ip[:port]\n");
	fprintf(stderr,"  -p port  alternate listen port (default 9090)\n");
	fprintf(stderr,"  -v       verbose/debug output\n");
	fprintf(stderr,"loc_id should be a unique string per location\n");
	exit(!0);
}

int
main (int argc, char **argv)
{
	struct MHD_Daemon	*the_daemon;
	sem_t			 the_sem;
	char			*stctx = NULL;
	char			*port_tmp;

	for (;;) switch (getopt_long(argc,argv,"c:d:fm:p:v",my_options,NULL)) {
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
	case 'f':
		cfg_file = NULL;
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
	case -1:
		goto args_done;
	default:
		exit_with_usage(argv[0]);
		break;
	}
args_done:

	if (cfg_file) {
		me = parse_config();
		if (!me) {
			fprintf(stderr,"could not parse %s\n",cfg_file);
			return !0;
		}
	}

	if (optind < argc) {
		DPRINTF("overriding name %s with %s\n",me,argv[optind]);
		me = argv[optind];
	}

	if (verbose) {
		if (proxy_host) {
			printf("primary storage in %s:%u as %s:%s (%s)\n",
				proxy_host,proxy_port,proxy_key,proxy_secret,
				s3mode ? "S3" : "HTTP");
		}
		if (master_host) {
			printf("operating as slave to %s:%u\n",
				master_host, master_port);
		}
		printf("db is at %s:%u\n",db_host,db_port);
		printf("will listen on port %u\n",my_port);
		printf("my location is \"%s\"\n",me);
		fflush(stdout);
	}

	sem_init(&the_sem,0,0);
	if (proxy_host) {
		if (s3mode) {
			char svc_acc[128];
			snprintf(svc_acc,sizeof(svc_acc),"%s:%u",
				proxy_host,proxy_port);
			hstor = hstor_new(svc_acc,proxy_host,
					     proxy_key,proxy_secret);
			/* TBD: check return value */
			if (verbose) {
				hstor->verbose = 1;
			}
			main_func_tbl = &s3_func_tbl;
		}
		else {
			main_func_tbl = &curl_func_tbl;
		}
	}
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
