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

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>
#include <jansson.h>

#include "repo.h"
#include "proxy.h"
#include "query.h"

/*
 * A config consists of a JSON array of objects, where each object includes:
 *
 * 	name	string
 * 	type	string		"s3" or "cf" or "http" (case insensitive)
 * 	host	string
 * 	port	integer
 * 	key	string		S3 key or (optional TBD) HTTP user
 * 	secret	string		S3 secret or (optional TBD) HTTP password
 *
 * The above fields are all used to implement replication once we've decided to
 * do it.  There may be other fields as well, to help us make that decision.
 * For example, there might be one or more fields to describe geographic
 * location, an array of supported image-format names, etc.  This information
 * is deliberately left "schema-free" so that users may add whatever fields
 * they like to both the config and to replication attributes on objects.
 */

typedef enum { REPL_PUT, REPL_DEL } repl_t;

typedef struct _repl_item {
	struct _repl_item	*next;
	repl_t			 type;
	char			*url;
	unsigned int		 server;
	size_t			 size;
	int			 pipes[2];
} repl_item;

repl_item	*queue_head	= NULL;
repl_item	*queue_tail	= NULL;
pthread_mutex_t	 queue_lock;
sem_t		 queue_sema;
json_t		*config		= NULL;

/* TBD: ick again.  More reasons to update the parser interface. */
char		*cur_bucket;
char		*cur_key;
json_t		*cur_server;

int
validate_server (unsigned int i)
{
	json_t		*server;
	json_t		*elem;
	const char	*name;
	const char	*type;

	server = json_array_get(config,i);
	if (!json_is_object(server)) {
		fprintf(stderr,"config elem %u: missing object\n",i);
		return 0;
	}

	elem = json_object_get(server,"name");
	if (!json_is_string(elem)) {
		fprintf(stderr,"config elem %u: missing name\n",i);
		return 0;
	}
	name = json_string_value(elem);

	elem = json_object_get(server,"type");
	if (!json_is_string(elem)) {
		fprintf(stderr,"config elem %u (%s): missing type\n",i,name);
		return 0;
	}
	type = json_string_value(elem);

	if (!strcasecmp(type,"s3") || !strcasecmp(type,"cf")) {
		elem = json_object_get(server,"key");
		if (!json_is_string(elem)) {
			fprintf(stderr,"config elem %u (%s): missing S3 key\n",
				i, name);
			return 0;
		}
		elem = json_object_get(server,"secret");
		if (!json_is_string(elem)) {
			fprintf(stderr,
				"config elem %u (%s): missing S3 secret\n",
				i, name);
			return 0;
		}
	}
	else if (strcasecmp(type,"http")) {
		fprintf(stderr,"config elem %u (%s): bad type\n",i,name);
		return 0;
	}

	elem = json_object_get(server,"host");
	if (!json_is_string(elem)) {
		fprintf(stderr,"config elem %u (%s): missing host\n",i,name);
		return 0;
	}

	elem = json_object_get(server,"port");
	if (!json_is_integer(elem)) {
		fprintf(stderr,"config elem %u (%s): missing port\n",i,name);
		return 0;
	}

	return 1;
}

/* We've already validated, so minimal checking here. */
void
set_config (void)
{
	json_t		*server;
	const char	*type;

	server = json_array_get(config,0);
	proxy_host = json_string_value(json_object_get(server,"host"));
	proxy_port = json_integer_value(json_object_get(server,"port"));
	type = json_string_value(json_object_get(server,"type"));
	if (!strcasecmp(type,"s3")) {
		s3mode = 1;
		proxy_key = json_string_value(json_object_get(server,"key"));
		proxy_secret = json_string_value(json_object_get(
			server,"secret"));
	}
	else {
		s3mode = 0;
	}
}

int
parse_config (void)
{
	json_error_t	 err;
	unsigned int	 nservers;
	unsigned int	 i;

	config = json_load_file(cfg_file,&err);
	if (!config) {
		fprintf(stderr,"JSON error on line %d: %s\n",err.line,err.text);
		return 0;
	}

	if (json_typeof(config) != JSON_ARRAY) {
		fprintf(stderr,"config should be a JSON array\n");
		goto err;
	}

	nservers = json_array_size(config);
	if (!nservers) {
		goto err;
	}

	for (i = 0; i < nservers; ++i) {
		if (!validate_server(i)) {
			goto err;
		}
	}

	/* Everything looks OK. */
	printf("%u replication servers defined\n",nservers);
	set_config();
	return 1;

err:
	json_decref(config);
	config = NULL;
	return 0;
}

size_t
junk_writer (void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t	n;

	n = fwrite(ptr,size,nmemb,stream);
	fflush(stream);
	printf("in %s(%llu,%llu) => %llu\n",__func__,size,nmemb,n);

	return n;
}

void *
proxy_repl_prod (void *ctx)
{
	repl_item		*item	= ctx;
	FILE			*fp	= fdopen(item->pipes[1],"w");
	char			 addr[1024];
	CURL			*curl;
	char			 svc_acc[128];
	struct hstor_client	*hstor;
	char			*bucket;
	char			*key;
	char			*stctx;
	char			*myurl;

	sprintf(addr,"http://%s:%u%s",proxy_host,proxy_port,item->url);
	DPRINTF("replicating from %s\n",addr);

	if (s3mode) {
		snprintf(svc_acc,sizeof(svc_acc),"%s:%lu",
			proxy_host,proxy_port);
		hstor = hstor_new(svc_acc,proxy_host,
				     proxy_key,proxy_secret);
		/* Blech.  Can't conflict with consumer, though. */
		myurl = strdup(item->url);
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

	DPRINTF("%s returning\n",__func__);
	close(item->pipes[1]);
	return NULL;
}

size_t
junk_reader (void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t	n;

	n = fread(ptr,size,nmemb,stream);
	printf("in %s(%llu,%llu) => %llu\n",__func__,size,nmemb,n);
	return n;
}

size_t
cf_writer (void *ptr, size_t size, size_t nmemb, void *stream)
{
	return size * nmemb;
}

size_t
cf_header (void *ptr, size_t size, size_t nmemb, void *stream)
{
	char	*next;
	char	*sctx;
	json_t	*server	= (json_t *)stream;

	next = strtok_r(ptr,":",&sctx);
	if (next) {
		if (!strcasecmp(next,"X-Storage-Url")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF URL %s\n",next);
				/* NB: after this, original "host" is gone. */
				json_object_set_new(server,"host",
					json_string(next));
			}
		}
		else if (!strcasecmp(next,"X-Storage-Token")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF token %s\n",next);
				json_object_set_new(server,"token",
					json_string(next));
			}
		}
	}
	return size * nmemb;
}

const char *
get_cloudfiles_token (json_t *server, const char *host, unsigned int port,
	const char * user, const char * key)
{
	CURL			*curl;
	char	 		 addr[1024];
	char	 		 auth_user[64];
	char	 		 auth_key[64];
	json_t			*token_obj;
	struct curl_slist	*slist;

	token_obj = json_object_get(server,"token");
	if (token_obj) {
		return json_string_value(token_obj);
	}

	sprintf(addr,"https://%s:%u/v1.0",host,port);
	sprintf(auth_user,"X-Auth-User: %s",user);
	sprintf(auth_key,"X-Auth-Key: %s",key);

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

	token_obj = json_object_get(server,"token");
	return token_obj ? json_string_value(token_obj) : NULL;
}

void *
proxy_repl_cons (void *ctx)
{
	repl_item		*item	= ctx;
	FILE			*fp	= fdopen(item->pipes[0],"r");
	char			 addr[1024];
	CURL			*curl;
	json_t			*server;
	char			 svc_acc[128];
	struct hstor_client	*hstor;
	char			*bucket;
	char			*key;
	char			*stctx;
	const char		*s_host;
	unsigned int		 s_port;
	const char		*s_key;
	const char		*s_secret;
	const char		*s_type;
	const char		*token_str;
	struct curl_slist	*slist;
	char			*myurl;

	server = json_array_get(config,item->server);
	s_host = json_string_value(json_object_get(server,"host"));
	s_port = json_integer_value(json_object_get(server,"port"));
	s_key = json_string_value(json_object_get(server,"key"));
	s_secret = json_string_value(json_object_get(server,"secret"));
	s_type = json_string_value(json_object_get(server,"type"));

	if (!strcasecmp(s_type,"s3")) {
		DPRINTF("replicating %llu to %s%s (s3)\n",item->size,addr,
			item->url);
		snprintf(svc_acc,sizeof(svc_acc),"%s:%lu",s_host,s_port);
		hstor = hstor_new(svc_acc,s_host,s_key,s_secret);
		/* Blech.  Can't conflict with producer, though. */
		myurl = strdup(item->url);
		bucket = strtok_r(myurl,"/",&stctx);
		key = strtok_r(NULL,"/",&stctx);
		hstor_put(hstor,bucket,key,
			     junk_reader,item->size,fp,NULL);
		hstor_free(hstor);
		free(myurl);
	}
	else {
		if (!strcasecmp(s_type,"cf")) {
			token_str = get_cloudfiles_token(server,s_host,s_port,
				s_key, s_secret);
			if (!token_str) {
				DPRINTF("could not get CF token\n");
				return NULL;
			}
			/* Re-fetch as this might have changed. */
			s_host = json_string_value(json_object_get(server,
				"host"));
			sprintf(addr,"%s%s",s_host,item->url);
			DPRINTF("replicating %llu to %s (CF)\n",item->size,
				addr);
		}
		else {
			sprintf(addr,"http://%s:%u%s",s_host,s_port,item->url);
			DPRINTF("replicating %llu to %s (repod)\n",item->size,
				addr);
		}
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
		curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,
			(curl_off_t)item->size);
		curl_easy_setopt(curl,CURLOPT_READFUNCTION,junk_reader);
		if (!strcasecmp(s_type,"cf")) {
			sprintf(svc_acc,"X-Auth-Token: %s",token_str);
			slist = curl_slist_append(NULL,svc_acc);
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
	close(item->pipes[0]);
	return NULL;
}

void
repl_worker_del (repl_item *item)
{
	json_t			*server;
	const char		*s_host;
	unsigned int		 s_port;
	const char		*s_key;
	const char		*s_secret;
	const char		*s_type;
	char			 svc_acc[128];
	struct hstor_client	*hstor;
	char			 addr[1024];
	CURL			*curl;
	char			*bucket;
	char			*key;
	char			*stctx;

	server = json_array_get(config,item->server);
	s_host = json_string_value(json_object_get(server,"host"));
	s_port = json_integer_value(json_object_get(server,"port"));
	s_key = json_string_value(json_object_get(server,"key"));
	s_secret = json_string_value(json_object_get(server,"secret"));
	s_type = json_string_value(json_object_get(server,"type"));

	if (!strcasecmp(s_type,"s3")) {
		DPRINTF("%s replicating delete of %s on %s:%u (S3)\n",__func__,
			item->url, s_host, s_port);
		snprintf(svc_acc,sizeof(svc_acc),"%s:%lu",s_host,s_port);
		/* TBD: check return */
		hstor = hstor_new(svc_acc,s_host,s_key,s_secret);
		bucket = strtok_r(item->url,"/",&stctx);
		key = strtok_r(NULL,"/",&stctx);
		DPRINTF("%s calling hstor_del\n",__func__);
		(void)hstor_del(hstor,bucket,key);
		hstor_free(hstor);
	}
	else {
		DPRINTF("%s replicating delete of %s on %s:%u (HTTP)\n",__func__,
			item->url, s_host, s_port);
		curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,addr);
		curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
		DPRINTF("%s calling curl_easy_perform\n",__func__);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	DPRINTF("%s returning\n",__func__);
}

void *
repl_worker (void *notused)
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
				pthread_create(&prod,NULL,proxy_repl_prod,item);
				pthread_create(&cons,NULL,proxy_repl_cons,item);
				pthread_join(prod,NULL);
				pthread_join(cons,NULL);
			}
			else {
				perror("pipe");
			}
			break;
		case REPL_DEL:
			repl_worker_del(item);
			break;
		default:
			fprintf(stderr,"bad repl type %d (url=%s) skipped\n",
				item->type, item->url);
		}
		free(item->url);
		free(item);
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

char *
repl_oget (char *id)
{
	char *cur_value;

	(void)meta_get_value(cur_bucket,cur_key,id,&cur_value);

	return cur_value;
}

char *
repl_sget (char *id)
{
	json_t *elem = json_object_get(cur_server,id);

	return elem ? (char *)json_string_value(elem) : NULL;
}

void
replicate (char *url, size_t size, char *policy)
{
	unsigned int	 i;
	repl_item	*item;
	value_t		*expr;
	int		 res;
	char		*url2;
	char		*stctx;

	if (policy) {
		DPRINTF("--- policy = %s\n",policy);
		expr = parse(policy);
		url2 = strdup(url);
		if (!url2) {
			fprintf(stderr,"could not parse url %s\n",url);
			return;
		}
		cur_bucket = strtok_r(url2,"/",&stctx);
		cur_key = strtok_r(NULL,"/",&stctx);
	}
	else {
		expr = NULL;
		url2 = NULL;
	}

	for (i = 1; i < json_array_size(config); ++i) {
		if (expr) {
			cur_server = json_array_get(config,i);
			res = eval(expr,repl_oget,repl_sget);
		}
		else {
			res = 0;
		}
		if (res <= 0) {
			DPRINTF("skipping %u for %s\n",i,url);
			continue;
		}
		DPRINTF("REPLICATING %s to %u\n",url,i);
		item = malloc(sizeof(*item));
		if (!item) {
			fprintf(stderr,"could not create repl_item for %s\n",
				url);
			break;
		}
		item->type = REPL_PUT;
		item->url = strdup(url);
		item->server = i;
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
		sem_post(&queue_sema);
	}
	
	if (expr) {
		free_value(expr);
	}
	if (url2) {
		free(url2);
	}
}

void
replicate_delete (char *url)
{
	unsigned int	 i;
	repl_item	*item;

	for (i = 1; i < json_array_size(config); ++i) {
		DPRINTF("replicating delete(%s) on %u\n",url,i);
		item = malloc(sizeof(*item));
		if (!item) {
			fprintf(stderr,"could not create repl_item for %s\n",
				url);
			return;
		}
		item->type = REPL_DEL;
		item->url = strdup(url);
		if (!item->url) {
			free(item);
			return;
		}
		item->server = i;
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
		sem_post(&queue_sema);
	}
}

