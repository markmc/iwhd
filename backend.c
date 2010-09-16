#include <config.h>

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
#include <sys/wait.h>
#include <assert.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>
#include <glib.h>

#define GLOBALS_IMPL
#include "iwh.h"
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

int
bad_register (my_state *ms, provider_t *prov, char *next, GHashTable *args)
{
	(void)ms;
	(void)prov;
	(void)next;
	(void)args;

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

	hstor_put(hstor,ms->bucket,ms->key,
		     http_put_cons,llen,pp,NULL);
	/* TBD: check return value */

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

char *
init_tmpfile (char *value)
{
	char	*path;
	int	 fd;
	size_t	 len;
	ssize_t	 written;

	path = strdup("/tmp/iwtmp.XXXXXX");
	if (!path) {
		return NULL;
	}

	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		free(path);
		return NULL;
	}

	len = strlen(value);
	if (len > 0) {
		written = write(fd,value,len);
		close(fd);
		if (written != (ssize_t)len) {
			if (written < 0) {
				perror("init_tmpfile write");
			}
			else {
				fprintf(stderr,"bad write length %zd in %s\n",
					written, __func__);
			}
			unlink(path);
			return NULL;
		}
	}

	return path;
}

int
s3_register (my_state *ms, provider_t *prov, char *next, GHashTable *args)
{
	char		*kernel		= g_hash_table_lookup(args,"kernel");
	char		*ramdisk	= g_hash_table_lookup(args,"ramdisk");
	char		*api_key;
	char		*api_secret;
	char		*ami_cert;
	char		*ami_key;
	char		*ami_uid;
	const char	*argv[11];
	int	 	 argc = 0;
	pid_t	 	 pid;
	int		 organ[2];
	FILE		*fp;
	char		 buf[80];
	char		*p;
	char		*ami_id	= NULL;
	char		*cval	= NULL;
	char		*kval	= NULL;
	int		 rc	= MHD_HTTP_BAD_REQUEST;

	if (next) {
		DPRINTF("S3 register with next!=NULL\n");
		goto cleanup;
	}

	DPRINTF("*** register %s/%s via %s (%s:%d)\n",
		ms->bucket, ms->key, prov->name, prov->host, prov->port);
	if (kernel) {
		DPRINTF("    (using kernel %s)\n",kernel);
	}
	if (ramdisk) {
		DPRINTF("    (using ramdisk %s)\n",ramdisk);
	}

	api_key = g_hash_table_lookup(args,"api-key");
	if (!api_key) {
		api_key = (char *)prov->username;
		if (!api_key) {
			printf("missing EC2 API key\n");
			goto cleanup;
		}
	}

	api_secret = g_hash_table_lookup(args,"api-secret");
	if (!api_secret) {
		api_secret = (char *)prov->password;
		if (!prov->password) {
			printf("missing EC2 API key\n");
			goto cleanup;
		}
	}

	cval = g_hash_table_lookup(args,"ami-cert");
	if (cval) {
		ami_cert = init_tmpfile(cval);
	}
	else {
		ami_cert = NULL;
	}
	if (!ami_cert) {
		ami_cert = get_provider_value(prov->index,"ami-cert");
		if (!ami_cert) {
			printf("missing EC2 AMI cert\n");
			goto cleanup;
		}
	}

	kval = g_hash_table_lookup(args,"ami-key");
	if (kval) {
		ami_key = init_tmpfile(kval);
	}
	else {
		ami_key = NULL;
	}
	if (!ami_key) {
		ami_key = get_provider_value(prov->index,"ami-key");
		if (!ami_key) {
			printf("missing EC2 AMI key\n");
			goto cleanup;
		}
	}

	ami_uid = g_hash_table_lookup(args,"ami-uid");
	if (!ami_uid) {
		ami_uid = get_provider_value(prov->index,"ami-uid");
		if (!ami_uid) {
			printf("missing EC2 AMI uid\n");
			goto cleanup;
		}
	}

	rc = MHD_HTTP_INTERNAL_SERVER_ERROR;

	argv[argc++] = "dc-register-image";
	argv[argc++] = ms->bucket;
	argv[argc++] = ms->key;
	argv[argc++] = api_key;
	argv[argc++] = api_secret;
	argv[argc++] = ami_cert;
	argv[argc++] = ami_key;
	argv[argc++] = ami_uid;
	argv[argc++] = kernel ? kernel : "_default_";
	argv[argc++] = ramdisk ? ramdisk : "_default_";
	argv[argc] = NULL;

	DPRINTF("api-key = %s\n",api_key);
	DPRINTF("api-secret = %s\n",api_secret);
	DPRINTF("ami-cert = %s\n",ami_cert);
	DPRINTF("ami-key = %s\n",ami_key);
	DPRINTF("ami-uid = %s\n",ami_uid);

	if (pipe(organ) < 0) {
		perror("pipe");
		goto cleanup;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(organ[0]);
		close(organ[1]);
		goto cleanup;
	}

	if (pid == 0) {
		(void)dup2(organ[1],STDOUT_FILENO);
		(void)dup2(organ[1],STDERR_FILENO);
		if (execvp("dc-register-image",(char* const*)argv) < 0) {
			perror("execvp");
		}
		/* Just in case... */
		exit(!0);
	}
	else {
		DPRINTF("waiting for child...\n");
		if (waitpid(pid,NULL,0) < 0) {
			perror("waitpid");
		}
		/* TBD: check identity/status from waitpid */
		DPRINTF("...child exited\n");
		close(organ[1]);
		fp = fdopen(organ[0],"r");
		if (!fp) {
			DPRINTF("could not open parent pipe\n");
			close(organ[0]);
			goto cleanup;
		}
		while (fgets(buf,sizeof(buf)-1,fp)) {
			buf[sizeof(buf)-1] = '\0';
			if (!strncmp(buf,"IMAGE ",6)) {
				for (p = buf+6; *p; ++p) {
					if ((*p == '\n') || (*p == '\r')) {
						*p = '\0';
						break;
					}
				}
				if (ami_id) {
					free(ami_id);
				}
				ami_id = strdup(buf+6);
				break;
			}
		}
		fclose(fp);
		if (ami_id) {
			DPRINTF("found AMI ID <%s>\n",buf+6);
			(void)meta_set_value(ms->bucket,ms->key,
				"ami-id",ami_id);
			free(ami_id);
		}
	}

	rc = MHD_HTTP_OK;

cleanup:
	if (ami_cert) {
		//unlink(ami_cert);
		free(ami_cert);
	}
	if (ami_key) {
		//unlink(ami_key);
		free(ami_key);
	}
	return rc;
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

/*
 * We can proxy through any number of CURL/HTTP warehouses, but the chain
 * eventually has to terminate at an S3 back end.
 */

int
curl_register (my_state *ms, provider_t *prov, char *next, GHashTable *args)
{
	char			 fixed[1024];
	CURL			*curl;
	struct curl_httppost	*first	= NULL;
	struct curl_httppost	*last	= NULL;
	char	*kernel		= g_hash_table_lookup(args,"kernel");
	char	*ramdisk	= g_hash_table_lookup(args,"ramdisk");

	if (!next) {
		DPRINTF("CURL register with next==NULL\n");
		return MHD_HTTP_BAD_REQUEST;
	}

	DPRINTF("*** PROXY registration request for %s/%s to %s (%s:%d)\n",
		ms->bucket, ms->key, prov->name, prov->host, prov->port);

	curl = curl_easy_init();
	if (!curl) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	sprintf(fixed,"http://%s:%d/%s/%s",
		prov->host,prov->port, ms->bucket, ms->key);
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_formadd(&first,&last,
		CURLFORM_COPYNAME, "op",
		CURLFORM_COPYCONTENTS, "register",
		CURLFORM_END);
	curl_formadd(&first,&last,
		CURLFORM_COPYNAME, "site",
		CURLFORM_COPYCONTENTS, next,
		CURLFORM_END);
	if (kernel) {
		curl_formadd(&first,&last,
			CURLFORM_COPYNAME, "kernel",
			CURLFORM_COPYCONTENTS, kernel,
			CURLFORM_END);
	}
	if (ramdisk) {
		curl_formadd(&first,&last,
			CURLFORM_COPYNAME, "ramdisk",
			CURLFORM_COPYCONTENTS, ramdisk,
			CURLFORM_END);
	}
	curl_easy_setopt(curl,CURLOPT_HTTPPOST,first);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return MHD_HTTP_OK;
}

/***** CF-specific functions (TBD) *****/

/***** FS-specific functions *****/

void
fs_init (void)
{
}

/* Start an FS _producer_. */
void *
fs_get_child (void * ctx)
{
	my_state	*ms	= ctx;
	int		 fd;
	char		 buf[1<<16];
	ssize_t		 bytes;

	fd = open(ms->url+1,O_RDONLY);
	if (fd < 0) {
		return THREAD_FAILED;
	}

	for (;;) {
		bytes = read(fd,buf,sizeof(buf));
		if (bytes <= 0) {
			if (bytes < 0) {
				perror("read");
			}
			break;
		}
		pipe_prod_signal(&ms->pipe,buf,bytes);
	}

	close(fd);
	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	return NULL;
}

/* Start an FS _consumer_. */
void *
fs_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	int		 fd;
	ssize_t		 bytes;
	size_t		 offset;

	fd = open(ms->url+1,O_WRONLY|O_CREAT,0666);
	if (fd < 0) {
		return THREAD_FAILED;
	}

	while (pipe_cons_wait(pp)) {
		offset = 0;
		do {
			bytes = write(fd,
				ps->data_ptr+offset,ps->data_len-offset);
			if (bytes <= 0) {
				if (bytes < 0) {
					perror("write");
				}
				goto done;
			}
			offset += bytes;
		} while (offset < ps->data_len);
		pipe_cons_signal(pp);
	}

done:
	close(fd);

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

int
fs_delete (char *bucket, char *key, char *url)
{
	(void)bucket;
	(void)key;

	if (unlink(url+1) < 0) {
		perror("unlink");
		return MHD_NO;
	}

	return MHD_YES;
}

int
fs_bcreate (char *bucket)
{
	DPRINTF("creating bucket %s\n",bucket);

	if (mkdir(bucket,0777) < 0) {
		perror("mkdir");
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	return MHD_HTTP_OK;
}


/***** Function tables. ****/

backend_func_tbl bad_func_tbl = {
	"uninitialized",
	bad_init,
	bad_get_child,
	bad_put_child,
	bad_cache_child,
	bad_delete,
	bad_bcreate,
	bad_register,
};

backend_func_tbl s3_func_tbl = {
	"S3",
	s3_init,
	s3_get_child,
	s3_put_child,
	bad_cache_child,
	s3_delete,
	s3_bcreate,
	s3_register,
};

backend_func_tbl curl_func_tbl = {
	"HTTP",
	curl_init,
	curl_get_child,
	curl_put_child,
	curl_cache_child,
	curl_delete,
	curl_bcreate,
	curl_register,
};

backend_func_tbl fs_func_tbl = {
	"FS",
	fs_init,
	fs_get_child,
	fs_put_child,
	bad_cache_child,
	fs_delete,
	fs_bcreate,
	bad_register,
};
