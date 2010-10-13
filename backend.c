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

#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
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
#include <errno.h>
#include <error.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>
#include <glib.h>

#define GLOBALS_IMPL
#include "iwh.h"
#include "meta.h"
#include "setup.h"
#include "template.h"
#include "mpipe.h"
#include "backend.h"
#include "state_defs.h"

struct hstor_client	*hstor;

/***** Generic module stuff, not specific to one back end *****/

#define S3_IMAGE_PATTERN "^IMAGE[[:blank:]]+([^[:space:]]+)"
#define S3_ERROR_PATTERN "^ERROR[[:blank:]]+([^[:space:]]+)"

regex_t s3_success_pat;
regex_t s3_failure_pat;
int	regex_ok = FALSE;

void
backend_init (void)
{
	regex_ok = TRUE;

	if (regcomp(&s3_success_pat,S3_IMAGE_PATTERN,REG_EXTENDED) != 0){
		DPRINTF("could not compile S3 success pattern\n");
		regex_ok = FALSE;
	}

	if (regcomp(&s3_failure_pat,S3_ERROR_PATTERN,REG_EXTENDED) != 0){
		DPRINTF("could not compile S3 failure pattern\n");
		regex_ok = FALSE;
	}
}


/***** Stub functions for unimplemented stuff. *****/

void
bad_init (void)
{
	DPRINTF("*** bad call to %s\n",__func__);
}

void *
bad_get_child (void * ctx)
{
	my_state        *ms     = (my_state *)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	pipe_prod_siginit(&ms->pipe,-1);
	return NULL;
}

void *
bad_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;

	DPRINTF("*** bad call to %s\n",__func__);
	pipe_cons_siginit(ps, -1);
	free(pp);
	return THREAD_FAILED;
}

void *
bad_cache_child (void * ctx)
{
	(void)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	return NULL;
}

int
bad_delete (const char *bucket, const char *key, const char *url)
{
	(void)bucket;
	(void)key;
	(void)url;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_HTTP_BAD_REQUEST;
}

int
bad_bcreate (const char *bucket)
{
	(void)bucket;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_HTTP_NOT_IMPLEMENTED;
}

int
bad_register (my_state *ms, const provider_t *prov, const char *next,
	      GHashTable *args)
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

	DPRINTF("producer finished chunk\n");
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

	pipe_cons_siginit(ps, 0);

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
		pipe_cons_signal(pp, 0);
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
	if (hstor) {
		if (verbose) {
			hstor->verbose = 1;
		}
	}
	else {
		DPRINTF("could not create S3 client\n");
	}
}

/* Start an S3 _producer_. */
void *
s3_get_child (void * ctx)
{
	my_state	*ms	= ctx;

	/* TBD: check existence before calling siginit */
	pipe_prod_siginit(&ms->pipe,0);

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
	bool		 rcb;

	clen = MHD_lookup_connection_value(
		ms->conn, MHD_HEADER_KIND, "Content-Length");
	if (clen) {
		llen = strtoll(clen,NULL,10);
	}
	else {
		error (0, 0, "missing Content-Length");
		llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	}

	rcb = hstor_put(hstor,ms->bucket,ms->key,http_put_cons,llen,pp,NULL);
	if (!rcb) {
		DPRINTF("%s returning with error\n",__func__);
		pipe_cons_siginit(ps, -1);
		free(pp);
		return THREAD_FAILED;
	}

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

int
s3_delete (const char *bucket, const char *key, const char *url)
{
	(void)url;

	hstor_del(hstor,bucket,key);
	/* TBD: check return value */

	return MHD_HTTP_OK;
}

int
s3_bcreate (const char *bucket)
{
	DPRINTF("creating bucket %s\n",bucket);

	if (!hstor_add_bucket(hstor,bucket)) {
		DPRINTF("  bucket create failed\n");
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	return MHD_HTTP_OK;
}

static const char *
s3_init_tmpfile (char *value)
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
		error (0, errno, "%s: failed to create file from template", path);
		free(path);
		return NULL;
	}

	len = strlen(value);
	if (len > 0) {
		written = write(fd,value,len);
		close(fd);
		if (written != (ssize_t)len) {
			if (written < 0) {
				error (0, errno, "failed to write to %s", path);
			}
			else {
				error (0, errno,
				       "invalid write length %zd in %s",
				       written, __func__);
			}
			unlink(path);
			free(path);
			return NULL;
		}
	}

	return path;
}

int
s3_register (my_state *ms, const provider_t *prov, const char *next,
	     GHashTable *args)
{
	char		*kernel		= g_hash_table_lookup(args,"kernel");
	char		*ramdisk	= g_hash_table_lookup(args,"ramdisk");
	char		*api_key;
	char		*api_secret;
	const char	*ami_cert;
	const char	*ami_key;
	const char	*ami_uid;
	const char	*argv[12];
	int	 	 argc = 0;
	pid_t	 	 pid;
	int		 organ[2];
	FILE		*fp;
	char		 buf[1024];
	char		*cval	= NULL;
	char		*kval	= NULL;
	int		 rc	= MHD_HTTP_BAD_REQUEST;
	char		*ami_bkt;
	char		 ami_id_buf[64];
	regmatch_t	 match[2];

	if (!regex_ok) {
		return MHD_HTTP_BAD_REQUEST;
	}

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
			error (0, 0, "missing EC2 API key");
			goto cleanup;
		}
	}

	api_secret = g_hash_table_lookup(args,"api-secret");
	if (!api_secret) {
		api_secret = (char *)prov->password;
		if (!prov->password) {
			error (0, 0, "missing EC2 API key");
			goto cleanup;
		}
	}

	cval = g_hash_table_lookup(args,"ami-cert");
	if (cval) {
		ami_cert = s3_init_tmpfile(cval);
		if (!ami_cert) {
			goto cleanup;
		}
	}
	else {
		ami_cert = get_provider_value(prov,"ami-cert");
		if (!ami_cert) {
			error (0, 0, "missing EC2 AMI cert");
			goto cleanup;
		}
	}

	kval = g_hash_table_lookup(args,"ami-key");
	if (kval) {
		ami_key = s3_init_tmpfile(kval);
		if (!ami_cert) {
			goto cleanup;
		}
	}
	else {
		ami_key = get_provider_value(prov,"ami-key");
		if (!ami_key) {
			error (0, 0, "missing EC2 AMI key");
			goto cleanup;
		}
	}

	ami_uid = g_hash_table_lookup(args,"ami-uid");
	if (!ami_uid) {
		ami_uid = get_provider_value(prov,"ami-uid");
		if (!ami_uid) {
			error (0, 0, "missing EC2 AMI uid");
			goto cleanup;
		}
	}

	ami_bkt = g_hash_table_lookup(args,"ami-bkt");
	if (!ami_bkt) {
		ami_bkt = ms->bucket;
	}

	/*
	 * This is the point where we go from validation to execution.  If we
	 * were double-forking so this could all be asynchronous, or for that
	 * matter to return an early 100-continue, this would probably be the
	 * place to do it.  Even without that, we set the ami-id here so that
	 * the caller can know things are actually in progress.
	 */
	sprintf(ami_id_buf,"pending %lld",(long long)time(NULL));
	DPRINTF("temporary ami-id = \"%s\"\n",ami_id_buf);
	(void)meta_set_value(ms->bucket,ms->key,"ami-id",ami_id_buf);
	rc = MHD_HTTP_INTERNAL_SERVER_ERROR;

	const char *cmd = "dc-register-image";
	argv[argc++] = cmd;
	argv[argc++] = ms->bucket;
	argv[argc++] = ms->key;
	argv[argc++] = api_key;
	argv[argc++] = api_secret;
	argv[argc++] = ami_cert;
	argv[argc++] = ami_key;
	argv[argc++] = ami_uid;
	argv[argc++] = ami_bkt;
	argv[argc++] = kernel ? kernel : "_default_";
	argv[argc++] = ramdisk ? ramdisk : "_default_";
	argv[argc] = NULL;

	DPRINTF("api-key = %s\n",api_key);
	DPRINTF("api-secret = %s\n",api_secret);
	DPRINTF("ami-cert = %s\n",ami_cert);
	DPRINTF("ami-key = %s\n",ami_key);
	DPRINTF("ami-uid = %s\n",ami_uid);
	DPRINTF("ami-bkt = %s\n",ami_bkt);

	if (pipe(organ) < 0) {
		error (0, errno, "pipe creation failed");
		goto cleanup;
	}

	pid = fork();
	if (pid < 0) {
		error (0, errno, "fork failed");
		close(organ[0]);
		close(organ[1]);
		goto cleanup;
	}

	if (pid == 0) {
		(void)dup2(organ[1],STDOUT_FILENO);
		(void)dup2(organ[1],STDERR_FILENO);
		execvp(cmd, (char* const*)argv);
		error (EXIT_FAILURE, errno, "failed run command %s", cmd);
	}

	DPRINTF("waiting for child...\n");
	if (waitpid(pid,NULL,0) < 0) {
		error (0, errno, "waitpid failed");
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
		if (regexec(&s3_success_pat,buf,2,match,0) == 0) {
			buf[match[1].rm_eo] = '\0';
			DPRINTF("found AMI ID: %s\n",buf+match[1].rm_so);
			sprintf(ami_id_buf,"OK %.60s",buf+match[1].rm_so);
			rc = MHD_HTTP_OK;
		}
		else if (regexec(&s3_failure_pat,buf,2,match,0) == 0) {
			buf[match[1].rm_eo] = '\0';
			DPRINTF("found error marker: %s\n",buf+match[1].rm_so);
			sprintf(ami_id_buf,"failed %.56s",buf+match[1].rm_so);
			rc = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			DPRINTF("ignoring line: <%s>\n",buf);
		}
	}
	fclose(fp);

cleanup:
	/*
	 * This is a bit tricky.  If we found the cert in the HTTP request and
	 * succeeded in creating a temp file, then this condition will succeed.
	 * If we failed to create the temp file, or never found a cert
	 * anywhere, there will be no ami_cert to clean up.  If we got a cert
	 * from the config, then ami_cert will be set but we'll (correctly)
	 * skip cleanup because cval is null.
	 */
	if (cval && ami_cert) {
		unlink(ami_cert);
		free((char *)ami_cert);
	}
	/* Same reasoning as above, with kval/ami_key. */
	if (kval && ami_key) {
		unlink(ami_key);
		free((char *)ami_key);
	}
	(void)meta_set_value(ms->bucket,ms->key,"ami-id",ami_id_buf);

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
		pipe_prod_siginit(&ms->pipe,-1);
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
	pipe_prod_siginit(&ms->pipe,0);
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
		error (0, 0, "missing Content-Length");
		llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	}

	curl = curl_easy_init();
	if (!curl) {
		pipe_cons_siginit(ps, -1);
		free(pp);
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
curl_delete (const char *bucket, const char *key, const char *url)
{
	CURL			*curl;
	char			 fixed[1024];

	(void)bucket;
	(void)key;

	curl = curl_easy_init();
	if (!curl) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	sprintf(fixed,"http://%s:%u%s",proxy_host,proxy_port,url);
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return MHD_HTTP_OK;
}

int
curl_bcreate (const char *bucket)
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
curl_register (my_state *ms, const provider_t *prov, const char *next,
	       GHashTable *args)
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
	DPRINTF("changing directory to %s\n",local_path);
	if (chdir(local_path) < 0) {
		error(0,errno,"chdir failed, unsafe to continue");
		exit(!0); /* Value doesn't matter, as long as it's not zero. */
	}
}

/* Start an FS _producer_. */
void *
fs_get_child (void * ctx)
{
	my_state	*ms	= ctx;
	int		 fd;
	char		 buf[1<<16];
	ssize_t		 bytes;
	char		*file = ms->url+1;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		pipe_prod_siginit(&ms->pipe,-1);
		pipe_prod_finish(&ms->pipe);
		return THREAD_FAILED;
	}

	pipe_prod_siginit(&ms->pipe,0);

	for (;;) {
		bytes = read(fd,buf,sizeof(buf));
		if (bytes <= 0) {
			if (bytes < 0) {
				error (0, errno, "%s: read failed", file);
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
	char		*file = ms->url+1;

	fd = open(file,O_WRONLY|O_CREAT,0666);
	if (fd < 0) {
		pipe_cons_siginit(ps, errno);
		free(pp);
		return THREAD_FAILED;
	}

	pipe_cons_siginit(ps, 0);

	while (pipe_cons_wait(pp)) {
		offset = 0;
		do {
			bytes = write(fd,
				ps->data_ptr+offset,ps->data_len-offset);
			if (bytes <= 0) {
				if (bytes < 0) {
					error (0, errno, "%s: write failed",
					       file);
				}
				pipe_cons_signal(pp, errno);
				goto done;
			}
			offset += bytes;
		} while (offset < ps->data_len);
		pipe_cons_signal(pp, 0);
	}

done:
	close(fd);

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

int
fs_delete (const char *bucket, const char *key, const char *url)
{
	(void)bucket;
	(void)key;

	if (unlink(url+1) < 0) {
		error (0, errno, "%s: failed to unlink", url+1);
		return MHD_HTTP_NOT_FOUND;
	}

	return MHD_HTTP_OK;
}

int
fs_bcreate (const char *bucket)
{
	DPRINTF("creating bucket %s\n",bucket);

	if (mkdir(bucket,0700) < 0) {
		error (0, errno, "%s: failed to create directory", bucket);
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
