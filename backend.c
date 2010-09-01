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

/* TBD: find proper locations for these */
extern struct hstor_client	*hstor;
extern const char 		*master_host;
extern unsigned short		 master_port;

/***** Stub functions for unimplemented stuff. *****/

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

/* Start an S3 _producer_. */
void *
s3_get_child (void * ctx)
{
	my_state	*ms	= ctx;

	hstor_get(hstor,ms->bucket,ms->key,http_get_prod,&ms->pipe,0);
	/* TBD: check return value */

	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	free_ms(ms);
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

/***** CURL-specific functions *****/

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
	curl_easy_setopt(ms->curl,CURLOPT_WRITEDATA,ms);
	curl_easy_perform(ms->curl);
	curl_easy_getinfo(ms->curl,CURLINFO_RESPONSE_CODE,&ms->rc);

	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	free_ms(ms);
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


/***** CF-specific functions (TBD) *****/

/***** FS-specific functions (TBD) *****/

/***** Function tables. ****/

backend_func_tbl bad_func_tbl = {
	bad_get_child,
	bad_put_child,
	bad_cache_child,
};

backend_func_tbl s3_func_tbl = {
	s3_get_child,
	s3_put_child,
	curl_cache_child,
};

backend_func_tbl curl_func_tbl = {
	curl_get_child,
	curl_put_child,
	curl_cache_child
};

