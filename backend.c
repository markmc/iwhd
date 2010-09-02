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

#define GLOBALS_IMPL
#include "repo.h"
#include "meta.h"
#include "proxy.h"
#include "template.h"
#include "mpipe.h"
#include "backend.h"
#include "state_defs.h"

struct hstor_client	*hstor;

/***** Stub functions for unimplemented stuff. *****/

void
bad_init (void)
{
	DPRINTF("*** bad call to %s\n",__func__);
}

void *
bad_get_child (void * ctx)
{
	(void)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	return NULL;
}

void *
bad_put_child (void * ctx)
{
	(void)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	return NULL;
}

void *
bad_cache_child (void * ctx)
{
	(void)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	return NULL;
}

int
bad_delete (char *bucket, char *key, char *url)
{
	(void)bucket;
	(void)key;
	(void)url;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_NO;
}

int
bad_bcreate (char *bucket)
{
	(void)bucket;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_HTTP_NOT_IMPLEMENTED;
}

/***** Generic functions shared by the HTTP back ends. */

/* Invoked from S3/CURL/CF. */
size_t
http_get_prod (void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t		 total	= size * nmemb;
	pipe_shared	*ps	= stream;

	DPRINTF("producer posting %zu bytes as %ld\n",total,ps->sequence+1);
	pipe_prod_signal(ps,ptr,total);

	DPRINTF("producer chunk finished\n");
	return total;
}

/* Invoked from S3/CURL/CF. */
size_t
http_put_cons (void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t		 total	= size * nmemb;
	pipe_private	*pp	= stream;
	pipe_shared	*ps	= pp->shared;
	size_t		 done;

	DPRINTF("consumer asked to read %zu\n",total);

	if (!pipe_cons_wait(pp)) {
		return 0;
	}

	DPRINTF("consumer offset %zu into %zu\n",
		pp->offset, ps->data_len);
	done = ps->data_len - pp->offset;
	if (done > total) {
		done = total;
	}
	memcpy(ptr,ps->data_ptr+pp->offset,done);
	pp->offset += done;
	DPRINTF("consumer copied %zu, new offset %zu\n",
		done, pp->offset);
	if (pp->offset == ps->data_len) {
		DPRINTF("consumer finished chunk\n");
		pipe_cons_signal(pp);
	}

	return done;
}

/***** S3-specific functions *****/

void
s3_init (void)
{
	char svc_acc[128];

	snprintf(svc_acc,sizeof(svc_acc),"%s:%u",
		proxy_host,proxy_port);
	hstor = hstor_new(svc_acc,proxy_host,proxy_key,proxy_secret);
	/* TBD: check return value */
	if (verbose) {
		hstor->verbose = 1;
	}
}

/* Start an S3 _producer_. */
void *
s3_get_child (void * ctx)
{
	my_state	*ms	= ctx;

	hstor_get(hstor,ms->bucket,ms->key,http_get_prod,&ms->pipe,0);
	/* TBD: check return value */

	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	return NULL;
}

/* Start an S3 _consumer_. */
void *
s3_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	curl_off_t	 llen;
	char		 fixed[1024];
	CURL		*curl;
	const char	*clen;

	clen = MHD_lookup_connection_value(
		ms->conn, MHD_HEADER_KIND, "Content-Length");
	if (clen) {
		llen = strtoll(clen,NULL,10);
	}
	else {
		fprintf(stderr,"missing Content-Length\n");
		llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	}

	if (s3mode) {
		hstor_put(hstor,ms->bucket,ms->key,
			     http_put_cons,llen,pp,NULL);
		/* TBD: check return value */
	}
	else {
		curl = curl_easy_init();
		if (!curl) {
			return THREAD_FAILED;
		}
		sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,
			ms->url);
		curl_easy_setopt(curl,CURLOPT_URL,fixed);
		curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
		curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,llen);
		curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
		curl_easy_setopt(curl,CURLOPT_READDATA,pp);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

int
s3_delete (char *bucket, char *key, char *url)
{
	(void)url;

	hstor_del(hstor,bucket,key);
	/* TBD: check return value */
	
	return MHD_YES;
}

int
s3_bcreate (char *bucket)
{
	DPRINTF("creating bucket %s\n",bucket);

	if (!hstor_add_bucket(hstor,bucket)) {
		DPRINTF("  bucket create failed\n");
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	return MHD_HTTP_OK;
}

/***** CURL-specific functions *****/

void
curl_init (void)
{
}

/* Start a CURL _producer_. */
void *
curl_get_child (void * ctx)
{
	char		 fixed[1024];
	my_state	*ms	= ctx;

	ms->curl = curl_easy_init();
	if (!ms->curl) {
		return NULL;	/* TBD: flag error somehow */
	}
	ms->cleanup |= CLEANUP_CURL;
	if (ms->from_master) {
		sprintf(fixed,"http://%s:%u%s",
			master_host, master_port, ms->url);
	}
	else {
		sprintf(fixed,"http://%s:%u%s",
			proxy_host, proxy_port, ms->url);
	}
	curl_easy_setopt(ms->curl,CURLOPT_URL,fixed);
	curl_easy_setopt(ms->curl,CURLOPT_WRITEFUNCTION,
			 http_get_prod);
	curl_easy_setopt(ms->curl,CURLOPT_WRITEDATA,&ms->pipe);
	curl_easy_perform(ms->curl);
	curl_easy_getinfo(ms->curl,CURLINFO_RESPONSE_CODE,&ms->rc);

	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	return NULL;
}

/* Start a CURL _consumer_. */
void *
curl_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	curl_off_t	 llen;
	char		 fixed[1024];
	CURL		*curl;
	const char	*clen;

	clen = MHD_lookup_connection_value(
		ms->conn, MHD_HEADER_KIND, "Content-Length");
	if (clen) {
		llen = strtoll(clen,NULL,10);
	}
	else {
		fprintf(stderr,"missing Content-Length\n");
		llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	}

	curl = curl_easy_init();
	if (!curl) {
		return THREAD_FAILED;
	}
	sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,
		ms->url);
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,llen);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
	curl_easy_setopt(curl,CURLOPT_READDATA,pp);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

/* Start a CURL cache consumer. */
void *
curl_cache_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	char		 fixed[1024];
	CURL		*curl;
	char		*slash;
	char		*my_url = strdup(ms->url);

	if (!my_url) {
		return THREAD_FAILED;
	}

	curl = curl_easy_init();
	if (!curl) {
		free(my_url);
		return THREAD_FAILED;
	}
	sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,
		ms->url);
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,
		(curl_off_t)MHD_SIZE_UNKNOWN);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
	curl_easy_setopt(curl,CURLOPT_READDATA,pp);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	slash = index(my_url+1,'/');
	if (slash) {
		*slash = '\0';
		meta_got_copy(my_url+1,slash+1,me);
	}

	free(my_url);
	return NULL;
}

int
curl_delete (char *bucket, char *key, char *url)
{
	CURL			*curl;
	char			 fixed[1024];

	(void)bucket;
	(void)key;

	curl = curl_easy_init();
	if (!curl) {
		return MHD_NO;
	}

	sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,url);
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return MHD_YES;
}

int
curl_bcreate (char *bucket)
{
	(void)bucket;

	DPRINTF("cannot create bucket in non-S3 mode\n");
	/* TBD: pretend this works for testing, fix for release
	rc = MHD_HTTP_NOT_IMPLEMENTED;
	*/
	return MHD_HTTP_OK;
}


/***** CF-specific functions (TBD) *****/

/***** FS-specific functions (TBD) *****/

/***** Function tables. ****/

backend_func_tbl bad_func_tbl = {
	bad_init,
	bad_get_child,
	bad_put_child,
	bad_cache_child,
	bad_delete,
	bad_bcreate,
};

backend_func_tbl s3_func_tbl = {
	s3_init,
	s3_get_child,
	s3_put_child,
	bad_cache_child,
	s3_delete,
	s3_bcreate,
};

backend_func_tbl curl_func_tbl = {
	curl_init,
	curl_get_child,
	curl_put_child,
	curl_cache_child,
	curl_delete,
	curl_bcreate,
};

