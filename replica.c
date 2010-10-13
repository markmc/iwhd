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

#include <config.h>

#include <errno.h>
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
#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>

#include "iwh.h"
#include "setup.h"
#include "query.h"
#include "meta.h"

/* Sizes for internal string buffers. */
#define ADDR_SIZE	1024
#define SVC_ACC_SIZE	128
#define HEADER_SIZE	64

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
static int		 rep_count	= 0;

static size_t
junk_writer (/* const */ void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t	n;

	n = fwrite(ptr,size,nmemb,stream);
	if (n != nmemb)
		error(0, 0, "warning: write failed");
	if (fflush(stream))
		error(0, 0, "warning: write failed");
	DPRINTF("in %s(%zu,%zu) => %zu\n",__func__,size,nmemb,n);

	return n;
}

static void *
proxy_repl_prod_fs (void *ctx)
{
	repl_item		*item	= ctx;
	int		 	 ifd;
	int			 ofd;
	char		 	 buf[1<<16];
	ssize_t		 	 ibytes;
	ssize_t		 	 obytes;
	ssize_t			 offset;

	DPRINTF("replicating from %s (FS)\n",item->path);

	ifd = open(item->path,O_RDONLY);
	if (ifd < 0) {
		error(0,errno,"ifd open");
		return THREAD_FAILED;
	}
	ofd = item->pipes[1];

	for (;;) {
		ibytes = read(ifd,buf,sizeof(buf));
		if (ibytes <= 0) {
			if (ibytes < 0) {
				error(0,errno,"%s: read failed", item->path);
			}
			else {
				DPRINTF("EOF on ifd\n");
			}
			break;
		}
		offset = 0;
		do {
			obytes = write(ofd,buf+offset,ibytes);
			if (obytes <= 0) {
				if (obytes < 0) {
					error(0,errno,"ofd write");
				}
				else {
					DPRINTF("zero-length write on ofd\n");
				}
				break;
			}
			ibytes -= obytes;
			offset += obytes;
		} while (ibytes > 0);
	}

	close(ifd);
	close(ofd);

	DPRINTF("%s returning\n",__func__);
	close(item->pipes[1]);
	return NULL;
}

static void *
proxy_repl_prod (void *ctx)
{
	repl_item		*item	= ctx;
	FILE			*fp	= fdopen(item->pipes[1],"w");
	char			 addr[ADDR_SIZE];
	CURL			*curl;
	char			 svc_acc[SVC_ACC_SIZE];
	struct hstor_client	*hstor;
	char			*bucket;
	char			*key;
	char			*stctx;
	char			*myurl;
	int			 chars;

	if (fp == NULL) {
		error(0, errno, "%s: fdopen failed", __func__);
		return NULL;
	}

	chars = snprintf(addr,ADDR_SIZE,
		"http://%s:%u/%s",proxy_host,proxy_port,item->path);
	if (chars >= ADDR_SIZE) {
		error(0,0,"path too long in %s",__func__);
		goto done;
	}
	DPRINTF("replicating from %s\n",addr);

	if (s3mode) {
		chars = snprintf(svc_acc,SVC_ACC_SIZE,"%s:%u",
			proxy_host,proxy_port);
		if (chars >= SVC_ACC_SIZE) {
			error(0,0,"svc_acc too long in %s",__func__);
			goto done;
		}
		hstor = hstor_new(svc_acc,proxy_host,
				     proxy_key,proxy_secret);
		/* Blech.  Can't conflict with consumer, though. */
		myurl = strdup(item->path);
		assert (myurl);
		bucket = strtok_r(myurl,"/",&stctx);
		key = strtok_r(NULL,"/",&stctx);
		hstor_get(hstor,bucket,key,
			     junk_writer,fp,0);
		hstor_free(hstor);
		free(myurl);
	}
	else {
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,junk_writer);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,fp);
		DPRINTF("%s calling curl_easy_perform\n",__func__);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

done:
	DPRINTF("%s returning\n",__func__);
	/* Closing should signal to the consumer that we're finished. */
	fclose(fp);
	return NULL;
}

static size_t
junk_reader (void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t	n;

	n = fread(ptr,size,nmemb,stream);
	printf("in %s(%zu,%zu) => %zu\n",__func__,size,nmemb,n);
	return n;
}

static size_t
cf_writer (void *ptr ATTRIBUTE_UNUSED, size_t size, size_t nmemb,
	   void *stream ATTRIBUTE_UNUSED)
{
	return size * nmemb;
}

static size_t
cf_header (void *ptr, size_t size, size_t nmemb, void *stream)
{
	char		*next;
	char		*sctx;
	provider_t	*server	= (provider_t *)stream;

	next = strtok_r(ptr,":",&sctx);
	if (next) {
		if (!strcasecmp(next,"X-Storage-Url")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF URL %s\n",next);
				/* NB: after this, original "host" is gone. */
				free((char *)server->host);
				server->host = strdup(next);
			}
		}
		else if (!strcasecmp(next,"X-Storage-Token")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF token %s\n",next);
				server->token = strdup(next);
			}
		}
	}
	return size * nmemb;
}

static const char *
get_cloudfiles_token (provider_t *server, const char *host, unsigned int port,
	const char * user, const char * key)
{
	CURL			*curl;
	char	 		 addr[ADDR_SIZE];
	char	 		 auth_user[HEADER_SIZE];
	char	 		 auth_key[HEADER_SIZE];
	char			*token;
	struct curl_slist	*slist;
	int			 chars;

	token = server->token;
	if (token) {
		return token;
	}

	chars = snprintf(addr,ADDR_SIZE,"https://%s:%u/v1.0",host,port);
	if (chars >= ADDR_SIZE) {
		error(0,0,"API URL too long in %s",__func__);
		return NULL;
	}

	chars = snprintf(auth_user,HEADER_SIZE,"X-Auth-User: %s",user);
	if (chars >= HEADER_SIZE) {
		error(0,0,"auth_user too long in %s",__func__);
		return NULL;
	}

	chars = snprintf(auth_key,HEADER_SIZE,"X-Auth-Key: %s",key);
	if (chars >= HEADER_SIZE) {
		error(0,0,"auth_key too long in %s",__func__);
		return NULL;
	}

	curl = curl_easy_init();
	curl_easy_setopt(curl,CURLOPT_URL,addr);
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,cf_writer);
	curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,cf_header);
	curl_easy_setopt(curl,CURLOPT_WRITEHEADER,server);
	slist = curl_slist_append(NULL,auth_user);
	slist = curl_slist_append(slist,auth_key);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);

	return server->token;
}

static void *
proxy_repl_cons (void *ctx)
{
	repl_item		*item	= ctx;
	FILE			*fp	= fdopen(item->pipes[0],"r");
	char			 addr[ADDR_SIZE];
	CURL			*curl;
	provider_t		*server;
	char			 svc_acc[SVC_ACC_SIZE];
	char			 auth_hdr[HEADER_SIZE];
	struct hstor_client	*hstor;
	char			*bucket;
	char			*key;
	char			*stctx;
	const char		*s_host;
	unsigned int		 s_port;
	const char		*s_key;
	const char		*s_secret;
	const char		*s_type;
	const char		*s_name;
	struct curl_slist	*slist;
	char			*myurl;
	int			 chars;

	if (fp == NULL) {
		error(0, errno, "%s: fdopen failed", __func__);
		return THREAD_FAILED;
	}

	server = item->server;
	s_host = server->host;
	s_port = server->port;
	s_key = server->username;
	s_secret = server->password;
	s_type = server->type;
	s_name = server->name;

	myurl = strdup(item->path);
	assert (myurl);
	bucket = strtok_r(myurl,"/",&stctx);
	key = strtok_r(NULL,"/",&stctx);

	if (!strcasecmp(s_type,"s3")) {
		DPRINTF("replicating %zu to %s/%s (S3)\n",item->size,s_host,
			item->path);
		chars = snprintf(svc_acc,SVC_ACC_SIZE,"%s:%u",s_host,s_port);
		if (chars >= SVC_ACC_SIZE) {
			error(0,0,"svc_acc too long in %s",__func__);
			return THREAD_FAILED;
		}
		hstor = hstor_new(svc_acc,s_host,s_key,s_secret);
		/* Blech.  Can't conflict with producer, though. */
		hstor_put(hstor,bucket,key,
			     junk_reader,item->size,fp,NULL);
		hstor_free(hstor);
	}
	else {
		const char *token_str = NULL;
		if (!strcasecmp(s_type,"cf")) {
			token_str = get_cloudfiles_token(server,s_host,s_port,
				s_key, s_secret);
			if (!token_str) {
				DPRINTF("could not get CF token\n");
				return THREAD_FAILED;
			}
			/* Re-fetch as this might have changed. */
			s_host = server->host;
			chars = snprintf(addr,ADDR_SIZE,"%s/%s",
				s_host,item->path);
			if (chars >= ADDR_SIZE) {
				error(0,0,"CF path too long in %s",__func__);
				return THREAD_FAILED;
			}
			DPRINTF("replicating %zu to %s (CF)\n",item->size,
				addr);
		}
		else {
			chars = snprintf(addr,ADDR_SIZE,"http://%s:%u/%s",
				s_host,s_port,item->path);
			if (chars >= ADDR_SIZE) {
				error(0,0,"HTTP path too long in %s",
					__func__);
				return THREAD_FAILED;
			}
			DPRINTF("replicating %zu to %s (repod)\n",item->size,
				addr);
		}
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
		curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,
			(curl_off_t)item->size);
		curl_easy_setopt(curl,CURLOPT_READFUNCTION,junk_reader);
		if (!strcasecmp(s_type,"cf")) {
			chars = snprintf(auth_hdr,HEADER_SIZE,
				"X-Auth-Token: %s",token_str);
			if (chars >= HEADER_SIZE) {
				error(0,0,"auth_token too long in %s",
					__func__);
				return THREAD_FAILED;
			}
			slist = curl_slist_append(NULL,auth_hdr);
			/*
			 * Rackspace doesn't clearly document that you'll get
			 * 412 (Precondition Failed) if you omit this.
			 */
			slist = curl_slist_append(slist,
				"Content-Type: binary/octet-stream");
		}
		else {
			slist = curl_slist_append(NULL,"X-redhat-role: master");
		}
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
		curl_easy_setopt(curl,CURLOPT_READDATA,fp);
		DPRINTF("%s calling curl_easy_perform\n",__func__);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl_slist_free_all(slist);
	}

	DPRINTF("%s returning\n",__func__);
	fclose(fp);
	meta_got_copy(bucket,key,s_name);
	free(myurl);
	return NULL;
}

static void
repl_worker_del (const repl_item *item)
{
	provider_t		*server;
	const char		*s_host;
	unsigned int		 s_port;
	const char		*s_key;
	const char		*s_secret;
	const char		*s_type;
	char			 svc_acc[SVC_ACC_SIZE];
	struct hstor_client	*hstor;
	char			 addr[ADDR_SIZE];
	CURL			*curl;
	char			*bucket;
	char			*key;
	char			*stctx;
	int			 chars;

	server = item->server;
	s_host = server->host;
	s_port = server->port;
	s_key = server->username;
	s_secret = server->password;
	s_type = server->type;

	if (!strcasecmp(s_type,"s3")) {
		DPRINTF("%s replicating delete of %s on %s:%u (S3)\n",__func__,
			item->path, s_host, s_port);
		chars = snprintf(svc_acc,SVC_ACC_SIZE,"%s:%u",s_host,s_port);
		if (chars >= SVC_ACC_SIZE) {
			error(0,0,"svc_acc too long in %s",__func__);
			return;
		}
		/* TBD: check return */
		hstor = hstor_new(svc_acc,s_host,s_key,s_secret);
		assert (item->path);
		bucket = strtok_r(item->path,"/",&stctx);
		key = strtok_r(NULL,"/",&stctx);
		(void)hstor_del(hstor,bucket,key);
		hstor_free(hstor);
	}
	else {
		DPRINTF("%s replicating delete of %s on %s:%u (HTTP)\n",
			__func__, item->path, s_host, s_port);
		chars = snprintf(addr,ADDR_SIZE,"http://%s:%d%s",
			s_host,s_port,item->path);
		if (chars >= ADDR_SIZE) {
			error(0,0,"path too long in %s",__func__);
			return;
		}
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	DPRINTF("%s returning\n",__func__);
}

static void
repl_worker_bcreate (repl_item *item)
{
	provider_t		*server;
	const char		*s_host;
	unsigned int		 s_port;
	const char		*s_key;
	const char		*s_secret;
	const char		*s_type;
	char			 svc_acc[SVC_ACC_SIZE];
	struct hstor_client	*hstor;
	char			 addr[ADDR_SIZE];
	CURL			*curl;
	int			 chars;

	server = item->server;
	s_host = server->host;
	s_port = server->port;
	s_key = server->username;
	s_secret = server->password;
	s_type = server->type;

	if (!strcasecmp(s_type,"s3")) {
		DPRINTF("%s replicating create of bucket %s on %s:%u (S3)\n",
			__func__, item->path, s_host, s_port);
		chars = snprintf(svc_acc,SVC_ACC_SIZE,"%s:%u",s_host,s_port);
		if (chars >= SVC_ACC_SIZE) {
			error(0,0,"svc_acc too long in %s",__func__);
			return;
		}
		/* TBD: check return */
		hstor = hstor_new(svc_acc,s_host,s_key,s_secret);
		assert (item->path);
		if (!hstor_add_bucket(hstor,item->path)) {
			error(0,0,"bucket create failed for %s",
				item->path);
		}
		hstor_free(hstor);
	}
	else {
		DPRINTF("%s replicating create of bucket %s on %s:%u (HTTP)\n",
			__func__, item->path, s_host, s_port);
		chars = snprintf(addr,ADDR_SIZE,"http://%s:%d/%s",
			s_host,s_port,item->path);
		if (chars >= ADDR_SIZE) {
			error(0,0,"path too long in %s",__func__);
			return;
		}
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"PUT");
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	DPRINTF("%s returning\n",__func__);
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

	for (;;) {
		sem_wait(&queue_sema);
		pthread_mutex_lock(&queue_lock);
		item = queue_head;
		queue_head = item->next;
		if (!queue_head) {
			queue_tail = NULL;
		}
		pthread_mutex_unlock(&queue_lock);

		switch (item->type) {
		case REPL_PUT:
			if (pipe(item->pipes) >= 0) {
				xpthread_create(&prod, (proxy_host
							? proxy_repl_prod
							: proxy_repl_prod_fs),
						item,
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
replicate (const char *url, size_t size, const char *policy)
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

	if (expr) {
		free_value(expr);
	}
	free(url2);
}

static void
replicate_namespace_action (const char *name, repl_t action)
{
	unsigned int	 i;
	repl_item	*item;
	GHashTableIter	 iter;
	gpointer	 key;
	gpointer	 value;

	init_prov_iter(&iter);
	while (g_hash_table_iter_next(&iter,&key,&value)) {
		if (!strcmp(key,me)) {
			continue;
		}
		DPRINTF("replicating delete(%s) on %u\n",name,i);
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
replicate_delete (const char *name)
{
	replicate_namespace_action(name,REPL_ODELETE);
}

void
replicate_bcreate (const char *name)
{
	replicate_namespace_action(name,REPL_BCREATE);
}

/* Part of our API to the query module. */
char *
follow_link (char *object, char *key)
{
	(void)object;
	(void)key;

	return "no_such_object";
}

int
get_rep_count (void)
{
	return g_atomic_int_get(&rep_count);
}
