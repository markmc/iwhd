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

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <error.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <hstor.h>

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

/*
 * Sizes for internal string buffers.  In general, ADDR_SIZE needs to be
 * big enough to hold a hostname, a port number, a bucket and key (each
 * MAX_FIELD_LEN=64) and some punctuation.  Header size needs to be big
 * enough to hold the header name plus a CF token (32 bytes).
 */
#define ADDR_SIZE	256
#define HEADER_SIZE	64

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

static void
bad_init (provider_t *prov)
{
	(void)prov;

	DPRINTF("*** bad call to %s\n",__func__);
}

static void *
bad_get_child (void * ctx)
{
	backend_thunk_t	*tp	= (backend_thunk_t *)ctx;
	my_state        *ms     = tp->parent;

	DPRINTF("*** bad call to %s\n",__func__);
	pipe_prod_siginit(&ms->pipe,-1);
	return NULL;
}

static void *
bad_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;

	DPRINTF("*** bad call to %s\n",__func__);
	pipe_cons_siginit(ps, -1);
	free(pp);
	return THREAD_FAILED;
}

static void *
bad_cache_child (void * ctx)
{
	(void)ctx;

	DPRINTF("*** bad call to %s\n",__func__);
	return NULL;
}

static int
bad_delete (const provider_t *prov, const char *bucket, const char *key,
	    const char *url)
{
	(void)prov;
	(void)bucket;
	(void)key;
	(void)url;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_HTTP_BAD_REQUEST;
}

static int
bad_bcreate (const provider_t *prov, const char *bucket)
{
	(void)prov;
	(void)bucket;

	DPRINTF("*** bad call to %s\n",__func__);
	return MHD_HTTP_NOT_IMPLEMENTED;
}

static int
bad_register (my_state *ms, const provider_t *prov, const char *next,
	      Hash_table *args)
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
static size_t
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
static size_t
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
	memcpy(ptr,(char *)(ps->data_ptr)+pp->offset,done);
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

static void
s3_init (provider_t *prov)
{
	char	svc_acc[128];
	int	chars;

	chars = snprintf(svc_acc,sizeof(svc_acc),"%s:%u",prov->host,prov->port);
	if (chars >= (int)sizeof(svc_acc)) {
		error(0,0,"hostname %s too long in %s",prov->host,__func__);
		return;
	}
	hstor = hstor_new(svc_acc,prov->host,prov->username,prov->password);
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
static void *
s3_get_child (void * ctx)
{
	backend_thunk_t	*tp	= (backend_thunk_t *)ctx;
	my_state        *ms     = tp->parent;

	/* TBD: check existence before calling siginit */
	pipe_prod_siginit(&ms->pipe,0);

	hstor_get(hstor,ms->bucket,ms->key,http_get_prod,&ms->pipe,0);
	/* TBD: check return value */

	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	return NULL;
}

/* Start an S3 _consumer_. */
static void *
s3_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	curl_off_t	 llen;
	const char	*clen;
	bool		 rcb;

	llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	if (ms->be_flags & BACKEND_GET_SIZE) {
		clen = MHD_lookup_connection_value(
			ms->conn, MHD_HEADER_KIND, "Content-Length");
		if (clen) {
			llen = strtoll(clen,NULL,10);
		}
		else {
			error (0, 0, "missing Content-Length");
		}
	}

	pipe_cons_siginit(ps, 0);
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

static int
s3_delete (const provider_t *prov, const char *bucket, const char *key,
	   const char *url)
{
	(void)prov;
	(void)url;

	hstor_del(hstor,bucket,key);
	/* TBD: check return value */

	return MHD_HTTP_OK;
}

static int
s3_bcreate (const provider_t *prov, const char *bucket)
{
	(void)prov;

	DPRINTF("creating bucket %s\n",bucket);

	if (!hstor_add_bucket(hstor,bucket)) {
		DPRINTF("  bucket create failed\n");
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	return MHD_HTTP_OK;
}

static const char *
s3_init_tmpfile (const char *value)
{
	char	*path;
	int	 fd;
	size_t	 len;
	ssize_t	 written;

	/* FIXME: do not hard-code /tmp.  */
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

static int
s3_register (my_state *ms, const provider_t *prov, const char *next,
	     Hash_table *args)
{
	char		*kernel		= kv_hash_lookup(args,"kernel");
	char		*ramdisk	= kv_hash_lookup(args,"ramdisk");
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
	char		 buf[ADDR_SIZE];
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

	api_key = kv_hash_lookup(args,"api-key");
	if (!api_key) {
		api_key = (char *)prov->username;
		if (!api_key) {
			error (0, 0, "missing EC2 API key");
			goto cleanup;
		}
	}

	api_secret = kv_hash_lookup(args,"api-secret");
	if (!api_secret) {
		api_secret = (char *)prov->password;
		if (!prov->password) {
			error (0, 0, "missing EC2 API secret");
			goto cleanup;
		}
	}

	cval = kv_hash_lookup(args,"ami-cert");
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

	kval = kv_hash_lookup(args,"ami-key");
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

	ami_uid = kv_hash_lookup(args,"ami-uid");
	if (!ami_uid) {
		ami_uid = get_provider_value(prov,"ami-uid");
		if (!ami_uid) {
			error (0, 0, "missing EC2 AMI uid");
			goto cleanup;
		}
	}

	ami_bkt = kv_hash_lookup(args,"ami-bkt");
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
		error (EXIT_FAILURE, errno, "failed to run command %s", cmd);
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

static void
curl_init (provider_t *prov)
{
	(void)prov;
}

/* Start a CURL _producer_. */
static void *
curl_get_child (void * ctx)
{
	char		 fixed[ADDR_SIZE];
	backend_thunk_t	*tp	= (backend_thunk_t *)ctx;
	my_state        *ms     = tp->parent;
	provider_t	*prov	= tp->prov;
	CURL		*curl;
	int		 chars;

	curl = curl_easy_init();
	if (!curl) {
		pipe_prod_siginit(&ms->pipe,-1);
		return NULL;	/* TBD: flag error somehow */
	}
	if (ms->from_master) {
		chars = snprintf(fixed,sizeof(fixed),"http://%s:%u%s",
			master_host, master_port, ms->url);
	}
	else {
		chars = snprintf(fixed,sizeof(fixed),"http://%s:%u%s",
			prov->host, prov->port, ms->url);
	}
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, http_get_prod);
	curl_easy_setopt(curl,CURLOPT_WRITEDATA,&ms->pipe);
	pipe_prod_siginit(&ms->pipe,0);

	curl_easy_perform(curl);
	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&ms->rc);
	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	curl_easy_cleanup(curl);
	return NULL;
}

/* Start a CURL _consumer_. */
static void *
curl_put_child (void * ctx)
{
	pipe_private		*pp	= ctx;
	pipe_shared		*ps	= pp->shared;
	my_state		*ms	= ps->owner;
	provider_t		*prov	= pp->prov;
	curl_off_t		 llen;
	char			 fixed[ADDR_SIZE];
	CURL			*curl;
	const char		*clen;
	struct curl_slist	*slist	= NULL;
	int			 chars;

	llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	if (ms->be_flags & BACKEND_GET_SIZE) {
		clen = MHD_lookup_connection_value(
			ms->conn, MHD_HEADER_KIND, "Content-Length");
		if (clen) {
			llen = strtoll(clen,NULL,10);
		}
		else {
			error (0, 0, "missing Content-Length");
		}
	}

	/*
	 * This is how the iwhd at the other end knows this is a replication
	 * request and not just a PUT from some random user.
	 * TBD: add some auth* for this.
	 */
	slist = curl_slist_append(slist,"X-redhat-role: master");

	curl = curl_easy_init();
	if (!curl) {
		pipe_cons_siginit(ps, -1);
		free(pp);
		return THREAD_FAILED;
	}
	chars = snprintf(fixed,sizeof(fixed),
		"http://%s:%u/%s/%s",prov->host,prov->port,ms->bucket,ms->key);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,llen);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
	curl_easy_setopt(curl,CURLOPT_READDATA,pp);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
	pipe_cons_siginit(ps, 0);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

/* Start a CURL cache consumer. */
static void *
curl_cache_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	provider_t	*prov	= pp->prov;
	char		 fixed[ADDR_SIZE];
	CURL		*curl;
	char		*slash;
	char		*my_url = strdup(ms->url);
	int		 chars;

	if (!my_url) {
		return THREAD_FAILED;
	}

	curl = curl_easy_init();
	if (!curl) {
		free(my_url);
		pipe_cons_siginit(ps,-1);
		return THREAD_FAILED;
	}
	chars = snprintf(fixed,sizeof(fixed),
		"http://%s:%u%s",prov->host,prov->port,ms->url);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,
		(curl_off_t)MHD_SIZE_UNKNOWN);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
	curl_easy_setopt(curl,CURLOPT_READDATA,pp);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	slash = strchr(my_url+1,'/');
	if (slash) {
		*slash = '\0';
		meta_got_copy(my_url+1,slash+1,me);
	}

	free(my_url);
	return NULL;
}

static int
curl_delete (const provider_t *prov, const char *bucket, const char *key,
	     const char *url)
{
	CURL			*curl;
	char			 fixed[ADDR_SIZE];
	int			 chars;

	(void)bucket;
	(void)key;

	curl = curl_easy_init();
	if (!curl) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	chars = snprintf(fixed,sizeof(fixed),
		"http://%s:%u%s",prov->host,prov->port,url);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return MHD_HTTP_OK;
}

static int
curl_bcreate (const provider_t *prov, const char *bucket)
{
	char	 addr[ADDR_SIZE];
	int	 chars;
	CURL	*curl;

	chars = snprintf(addr,sizeof(addr),"http://%s:%d/%s",
		prov->host,prov->port,bucket);
	if (chars >= (int)sizeof(addr)) {
		error(0,0,"path too long in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	curl = curl_easy_init();
	if (!curl) {
		error(0,errno,"no memory in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	curl_easy_setopt(curl,CURLOPT_URL,addr);
	curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"PUT");
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return MHD_HTTP_OK;
}

/*
 * We can proxy through any number of CURL/HTTP warehouses, but the chain
 * eventually has to terminate at an S3 back end.
 */

static int
curl_register (my_state *ms, const provider_t *prov, const char *next,
	       Hash_table *args)
{
	char			 fixed[ADDR_SIZE];
	CURL			*curl;
	struct curl_httppost	*first	= NULL;
	struct curl_httppost	*last	= NULL;
	char	*kernel		= kv_hash_lookup(args,"kernel");
	char	*ramdisk	= kv_hash_lookup(args,"ramdisk");
	int	 chars;

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
	chars = snprintf(fixed,sizeof(fixed),"http://%s:%d/%s/%s",
		prov->host,prov->port, ms->bucket, ms->key);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
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

/***** CF-specific functions *****/

/*
 * TBD: refactor to maximize common code.  Despite the de-duplication between
 * this module and replica.c, there's still a lot more that could be done to
 * combine xxx_yyy_child for xxx={http,cf} and yyy={put,cache}.  A rough
 * outline might be:
 *
 * 	if xxx=cf, call CF-specific routine to add CF auth header
 * 	do common curl setup and execution
 * 	if yyy=cache, call meta_got_copy
 *
 * There might even be an opportunity to combine code for put and bucket
 * create in some cases, since the only difference is the URL and the
 * lack of a data transfer in the bucket-create case.
 */

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
	provider_t	*prov	= (provider_t *)stream;

	next = strtok_r(ptr,":",&sctx);
	if (next) {
		if (!strcasecmp(next,"X-Storage-Url")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF URL %s\n",next);
				/* NB: after this, original "host" is gone. */
				free((char *)prov->host);
				prov->host = strdup(next);
			}
		}
		else if (!strcasecmp(next,"X-Storage-Token")) {
			next = strtok_r(NULL," \n\r",&sctx);
			if (next) {
				DPRINTF("got CF token %s\n",next);
				prov->token = strdup(next);
			}
		}
	}
	return size * nmemb;
}

static struct curl_slist *
cf_add_token (struct curl_slist *in_slist, const char *token)
{
	int		 	chars;
	char		 	auth_hdr[HEADER_SIZE];

	if (!token) {
		return in_slist;
	}

	chars = snprintf(auth_hdr,sizeof(auth_hdr),"X-Auth-Token: %s",token);
	if (chars >= (int)sizeof(auth_hdr)) {
		error(0,0,"auth_hdr too long");
		return in_slist;
	}

	return curl_slist_append(NULL,auth_hdr);
}

static void
cf_init (provider_t *prov)
{
	CURL			*curl;
	char			 addr[ADDR_SIZE];
	char			 auth_user[HEADER_SIZE];
	char			 auth_key[HEADER_SIZE];
	struct curl_slist	*slist;
	int			 chars;

	if (prov->token) {
		return;
	}

	chars = snprintf(addr,sizeof(addr),"https://%s:%u/v1.0",
		prov->host, prov->port);
	if (chars >= (int)sizeof(addr)) {
		error(0,0,"API URL too long in %s",__func__);
		return;
	}

	chars = snprintf(auth_user,sizeof(auth_user),"X-Auth-User: %s",
		prov->username);
	if (chars >= (int)sizeof(auth_user)) {
		error(0,0,"auth_user too long in %s",__func__);
		return;
	}

	chars = snprintf(auth_key,sizeof(auth_key),"X-Auth-Key: %s",
		prov->password);
	if (chars >= (int)sizeof(auth_key)) {
		error(0,0,"auth_key too long in %s",__func__);
		return;
	}

	curl = curl_easy_init();
	curl_easy_setopt(curl,CURLOPT_URL,addr);
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,cf_writer);
	curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,cf_header);
	curl_easy_setopt(curl,CURLOPT_WRITEHEADER,prov);
	slist = curl_slist_append(NULL,auth_user);
	slist = curl_slist_append(slist,auth_key);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);

	DPRINTF("CF token = %s\n",prov->token);
}

/* Start a CloudFiles _producer_. */
static void *
cf_get_child (void * ctx)
{
	char		 	 fixed[ADDR_SIZE];
	backend_thunk_t		*tp	= (backend_thunk_t *)ctx;
	my_state        	*ms     = tp->parent;
	provider_t		*prov	= tp->prov;
	CURL			*curl;
	struct curl_slist	*slist	= NULL;
	int			 chars;

	slist = cf_add_token(slist,prov->token);
	if (!slist) {
		return THREAD_FAILED;
	}
	/*
	 * Rackspace doesn't clearly document that you'll get
	 * 412 (Precondition Failed) if you omit this.
	 */
	slist = curl_slist_append(slist,
		"Content-Type: binary/octet-stream");

	curl = curl_easy_init();
	if (!curl) {
		pipe_prod_siginit(&ms->pipe,-1);
		curl_slist_free_all(slist);
		return NULL;	/* TBD: flag error somehow */
	}
	chars = snprintf(fixed,sizeof(fixed),"%s%s", prov->host, ms->url);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, http_get_prod);
	curl_easy_setopt(curl,CURLOPT_WRITEDATA,&ms->pipe);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
	pipe_prod_siginit(&ms->pipe,0);

	curl_easy_perform(curl);
	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&ms->rc);
	pipe_prod_finish(&ms->pipe);

	DPRINTF("producer exiting\n");
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);
	return NULL;
}

/* Start a CloudFiles _consumer_. */
static void *
cf_put_child (void * ctx)
{
	pipe_private		*pp	= ctx;
	pipe_shared		*ps	= pp->shared;
	my_state		*ms	= ps->owner;
	provider_t		*prov	= pp->prov;
	curl_off_t		 llen;
	char			 fixed[ADDR_SIZE];
	CURL			*curl;
	const char		*clen;
	struct curl_slist	*slist	= NULL;
	int			 chars;

	slist = cf_add_token(slist,prov->token);
	if (!slist) {
		return THREAD_FAILED;
	}

	llen = (curl_off_t)MHD_SIZE_UNKNOWN;
	if (ms->be_flags & BACKEND_GET_SIZE) {
		clen = MHD_lookup_connection_value(
			ms->conn, MHD_HEADER_KIND, "Content-Length");
		if (clen) {
			llen = strtoll(clen,NULL,10);
		}
		else {
			error (0, 0, "missing Content-Length");
		}
	}

	curl = curl_easy_init();
	if (!curl) {
		pipe_cons_siginit(ps, -1);
		free(pp);
		curl_slist_free_all(slist);
		return THREAD_FAILED;
	}
	chars = snprintf(fixed,sizeof(fixed),
		"%s/%s/%s",prov->host,ms->bucket,ms->key);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,llen);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,http_put_cons);
	curl_easy_setopt(curl,CURLOPT_READDATA,pp);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);
	pipe_cons_siginit(ps, 0);

	curl_easy_perform(curl);
	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&ms->rc);

	DPRINTF("%s returning\n",__func__);
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);
	free(pp);
	return NULL;
}

static int
cf_delete (const provider_t *prov,
	   const char *bucket ATTRIBUTE_UNUSED,
	   const char *key ATTRIBUTE_UNUSED,
	   const char *url)
{
	CURL			*curl;
	char			 fixed[ADDR_SIZE];
	long			 rc;
	struct curl_slist	*slist	= NULL;
	int			 chars;

	slist = cf_add_token(slist,prov->token);
	if (!slist) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	curl = curl_easy_init();
	if (!curl) {
		curl_slist_free_all(slist);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	chars = snprintf(fixed,sizeof(fixed),"%s%s",prov->host,url);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,"DELETE");
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);

	curl_easy_perform(curl);
	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&rc);
	DPRINTF("%s: rc = %ld\n",__func__,rc);

	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);

	return MHD_HTTP_OK;
}

static size_t
cf_null_reader (void *ptr ATTRIBUTE_UNUSED,
		size_t size ATTRIBUTE_UNUSED,
		size_t nmemb ATTRIBUTE_UNUSED,
		void *stream ATTRIBUTE_UNUSED)
{
	return 0;
}

static int
cf_bcreate (const provider_t *prov, const char *bucket)
{
	char			 fixed[ADDR_SIZE];
	CURL			*curl;
	long			 rc;
	struct curl_slist	*slist	= NULL;
	int			 chars;

	slist = cf_add_token(slist,prov->token);
	if (!slist) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	curl = curl_easy_init();
	if (!curl) {
		curl_slist_free_all(slist);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	chars = snprintf(fixed,sizeof(fixed),"%s/%s",prov->host,bucket);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
	curl_easy_setopt(curl,CURLOPT_URL,fixed);
	curl_easy_setopt(curl,CURLOPT_UPLOAD,1);
	curl_easy_setopt(curl,CURLOPT_INFILESIZE_LARGE,
		(curl_off_t)MHD_SIZE_UNKNOWN);
	curl_easy_setopt(curl,CURLOPT_READFUNCTION,cf_null_reader);
	curl_easy_setopt(curl,CURLOPT_HTTPHEADER,slist);

	curl_easy_perform(curl);
	curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&rc);
	DPRINTF("%s: rc = %ld\n",__func__,rc);

	DPRINTF("%s returning\n",__func__);
	curl_easy_cleanup(curl);
	curl_slist_free_all(slist);
	return MHD_HTTP_OK;
}

/***** FS-specific functions *****/

static void
fs_init (provider_t *prov)
{
	DPRINTF("changing directory to %s\n",prov->path);
	if (chdir(prov->path) < 0) {
		error(0,errno,"chdir failed, unsafe to continue");
		exit(!0); /* Value doesn't matter, as long as it's not zero. */
	}
}

/* Start an FS _producer_. */
static void *
fs_get_child (void * ctx)
{
	backend_thunk_t	*tp	= (backend_thunk_t *)ctx;
	my_state        *ms     = tp->parent;
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
static void *
fs_put_child (void * ctx)
{
	pipe_private	*pp	= ctx;
	pipe_shared	*ps	= pp->shared;
	my_state	*ms	= ps->owner;
	int		 fd;
	ssize_t		 bytes;
	size_t		 offset;
	char		 fixed[ADDR_SIZE];
	int		 chars;

	chars = snprintf(fixed,sizeof(fixed),"%s/%s",ms->bucket,ms->key);
	if (chars >= (int)sizeof(fixed)) {
		error(0,0,"path too long in %s",__func__);
		return NULL;
	}
	if (unlink(fixed) < 0) {
		error(0,errno,"unlink failed for %s (non-fatal)",fixed);
	}
	fd = open(fixed,O_WRONLY|O_CREAT|O_EXCL,0666);
	if (fd < 0) {
		pipe_cons_siginit(ps, errno);
		free(pp);
		return THREAD_FAILED;
	}

	pipe_cons_siginit(ps, 0);

	while (pipe_cons_wait(pp)) {
		for (offset = 0; offset < ps->data_len; offset += bytes) {
			bytes = write(fd,
				      (char *)(ps->data_ptr)+offset,
				      ps->data_len-offset);
			if (bytes <= 0) {
				if (bytes < 0) {
					error (0, errno, "%s: write failed",
					       fixed);
					pipe_cons_signal(pp, errno);
				}
				else {
					pipe_cons_signal(pp, ENOSPC);
				}
				break;
			}
		}
		pipe_cons_signal(pp, 0);
	}

	close(fd);

	DPRINTF("%s returning\n",__func__);
	free(pp);
	return NULL;
}

static int
fs_delete (const provider_t *prov, const char *bucket, const char *key,
	   const char *url)
{
	(void)prov;
	(void)bucket;
	(void)key;

	if (unlink(url+1) < 0) {
		error (0, errno, "%s: failed to unlink", url+1);
		return MHD_HTTP_NOT_FOUND;
	}

	return MHD_HTTP_OK;
}

static int
fs_bcreate (const provider_t *prov, const char *bucket)
{
	(void)prov;

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

backend_func_tbl cf_func_tbl = {
	"CF",
	cf_init,
	cf_get_child,
	cf_put_child,
	bad_cache_child,
	cf_delete,
	cf_bcreate,
	bad_register,
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
