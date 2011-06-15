/*
 * dc-rhev-image: register an image in RHEV
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * The URL parser is taken from GNet (by way of tabled):
 *
 * GNet - Networking library
 * Copyright (C) 2000-2003  David Helder, David Bolcsfoldi, Eric Williams
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <curl/curl.h>
#include <jansson.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <uuid/uuid.h>

#include "base64.h"
#include "close-stream.h"
#include "closeout.h"
#include "copy-file.h"
#include "progname.h"
#include "dirname.h"
#include "xalloc.h"
#include "c-strcase.h"

/*
 * Note that we almost never prefix with TAG due to compatibility with EC2.
 */
#define TAG "dc-rhev-image"

#define NFSUID 36
#define NFSGID 36

static const char NULID[] = "00000000-0000-0000-0000-000000000000";

struct config {
	char *image;
	char *apiurl;
	char *apiuser;
	char *apipass;
	char *nfshost;
	char *nfspath;
	char *nfsdir;
	char *cluster;
};

struct http_uri {
	const char	*scheme;
	unsigned int	scheme_len;
	const char	*userinfo;
	unsigned int	userinfo_len;
	const char	*hostname;
	unsigned int	hostname_len;

	unsigned int	port;

	const char	*path;
	unsigned int	path_len;
	const char	*query;
	unsigned int	query_len;
	const char	*fragment;
	unsigned int	fragment_len;	/* see FIXME in huri_parse */
};

struct id_pack {
	/* char exp_dom[37];	-- kept in stor_dom */
	char volume[37];
	char image[37];
	char template[37];
};

struct stor_dom {
	char *uuid;
	char *address;
	char *path;
	bool toptpl;
};

struct api_buf {
	char *buf;
	size_t alloc;
	size_t used;
};

struct api_conn {
	struct curl_slist *hdrs;
	CURL *curl;
	char *base;	/* "https://rhevm.host.corp.com:8543/" */
	char *path;	/* "/rhevm-api" or "/rhevm-api-powershell" */
};

static void Usage(void)
{
	fprintf(stderr, "ERROR Usage: " TAG " [" TAG ".conf]\n");
	exit(EXIT_FAILURE);
}

static char **env_p;

/* our own ISSPACE.  ANSI isspace is locale dependent */
#define ISSPACE(C) (((C) >= 9 && (C) <= 13) || (C) == ' ')
/* oh what the heck, use this too */
#define ISDIGIT(C) (((C) >= '0' && (C) <= '9'))

#define ASSIGN(token, ptr, len)			\
	do {					\
		uri->token = (ptr);		\
		uri->token##_len = (len);	\
	} while (0)

static struct http_uri *huri_parse(struct http_uri *uri, const char *uri_text)
{
	const char *p, *temp;

	memset(uri, 0, sizeof(*uri));

	/* Skip initial whitespace */
	p = uri_text;
	while (*p && ISSPACE((int)*p))
		++p;
	if (!*p)		/* Error if it's just a string of space */
		return NULL;

	/* Scheme */
	temp = p;
	while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#')
		++p;
	if (*p == ':') {
		ASSIGN(scheme, temp, p - temp);
		++p;
	} else			/* This char is NUL, /, ?, or # */
		p = temp;

	/* Authority */
	if (*p == '/' && p[1] == '/') {
		p += 2;

		/* Userinfo */
		temp = p;
		while (*p && *p != '@' && *p != '/')	/* Look for @ or / */
			++p;
		if (*p == '@') {	/* Found userinfo */
			ASSIGN(userinfo, temp, p - temp);
			++p;
		} else
			p = temp;

		/* Hostname */

		/* Check for no hostname at all (e.g. file:// URIs) */
		if (*p == '/')
			goto path;

		/* Check for IPv6 canonical hostname in brackets */
		if (*p == '[') {
			p++;	/* Skip [ */
			temp = p;
			while (*p && *p != ']')
				++p;
			if ((p - temp) == 0)
				goto error;
			ASSIGN(hostname, temp, p - temp);
			if (*p)
				p++;	/* Skip ] (if there) */
		} else {
			temp = p;
			while (*p && *p != '/' && *p != '?' && *p != '#'
			       && *p != ':')
				++p;
			if ((p - temp) == 0)
				goto error;
			ASSIGN(hostname, temp, p - temp);
		}

		/* Port */
		if (*p == ':') {
			for (++p; ISDIGIT((int)*p); ++p)
				uri->port = uri->port * 10 + (*p - '0');
		}

	}

	/* Path (we are liberal and won't check if it starts with /) */

path:
	temp = p;
	while (*p && *p != '?' && *p != '#')
		++p;
	if (p != temp)
		ASSIGN(path, temp, p - temp);

	/* Query */
	if (*p == '?') {
		temp = p + 1;
		while (*p && *p != '#')
			++p;
		ASSIGN(query, temp, p - temp);
	}

	/* Fragment */
	if (*p == '#') {
		++p;
		uri->fragment = p;
		/* FIXME: assign uri->fragment_len! */
	}

	return uri;

error:
	return NULL;
}

static xmlChar *xmlGetRel(xmlNode *etparent, const char *relname)
{
	xmlNode *et;
	xmlChar *rel, *href;

	for (et = etparent->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, "link") != 0)
			continue;
		rel = xmlGetProp(et, (xmlChar *)"rel");
		if (!rel)
			continue;
		if (strcmp((const char *)rel, relname) == 0) {
			xmlFree(rel);
			break;
		}
		xmlFree(rel);
	}

	if (!et)
		return NULL;

	href = xmlGetProp(et, (xmlChar *)"href");
	if (!href)
		goto err_href;

	return href;

 err_href:
	fprintf(stderr, "ERROR link in %s without href\n", etparent->name);
	exit(EXIT_FAILURE);
}

static int path_exists(const char *path)
{
	return access(path, R_OK) == 0;
}

static const char *image_name(const char *path)
{
	const char *b = last_component(path);
	return *b ? b : "-";
}

static void
cfg_veripick(char **cfgval, const char *cfgname, json_t *jcfg,
	     const char *cfgtag)
{
	json_t *elem;
	const char *name;
	char *tmp;

	elem = json_object_get(jcfg, cfgtag);
	if (!json_is_string(elem)) {
		fprintf(stderr,
		    "ERROR configuration %s: tag `%s' is not a string\n",
		    cfgname, cfgtag);
		exit(EXIT_FAILURE);
	}
	name = json_string_value(elem);
	if (!name) {
		fprintf(stderr,
		    "ERROR configuration %s: tag `%s' has no value\n",
		    cfgname, cfgtag);
		exit(EXIT_FAILURE);
	}
	tmp = strdup(name);
	if (!tmp) {
		fprintf(stderr, "ERROR no core\n");
		exit(EXIT_FAILURE);
	}
	*cfgval = tmp;
}

static void ensure_path(const char *filename)
{
	char *s;
	char *path = xstrdup(filename);
	for (s = path; ; s++) {
		if (!*s)
			break;
		if (*s == '/')
			continue;
		s = strchr(s, '/');
		if (!s)
			break;
		*s = 0;
		if (mkdir(path, 0770) < 0 && errno != EEXIST) {
			fprintf(stderr, "ERROR mkdir(%s): %s\n",
				path, strerror(errno));
			exit(EXIT_FAILURE);
		}
		*s = '/';
	}
	free(path);
}

static size_t api_wcb(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct api_buf *bp = arg;
	char *mem;
	size_t len;

	if (bp->alloc - bp->used < nmemb) {
		len = (((bp->used + nmemb) / 2000) + 1) * 2000;
		mem = realloc(bp->buf, len);
		if (!mem)
			return 0;
		bp->buf = mem;
		bp->alloc = len;
	}
	memcpy(bp->buf + bp->used, ptr, nmemb);
	bp->used += nmemb;
	return nmemb;
}

static size_t api_rcb(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct api_buf *bp = arg;
	size_t count;

	count = bp->alloc - bp->used;
	if (count > nmemb)
		count = nmemb;
	if (count) {
		memcpy(ptr, bp->buf + bp->used, count);
		bp->used += count;
	}
	return count;
}

static void require_api_root(const xmlChar *actual, const char *required)
{
	if (strcmp((const char *)actual, required) != 0) {
		fprintf(stderr,
			"ERROR invalid API root: `%s' (expected `%s')\n",
			actual, required);
		exit(EXIT_FAILURE);
	}
}

static void apipaths(struct api_conn *connection,
    char **psd, char **pdc, char **pcl)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlChar *pathsd, *pathdc, *pathcl;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s/", connection->base, connection->path);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "api");

	pathsd = xmlGetRel(etroot, "storagedomains");
	if (!pathsd) {
		fprintf(stderr, "ERROR API has no `rel=storagedomains'\n");
		exit(EXIT_FAILURE);
	}
	pathdc = xmlGetRel(etroot, "datacenters");
	if (!pathdc) {
		fprintf(stderr, "ERROR API has no `rel=datacenters'\n");
		exit(EXIT_FAILURE);
	}
	pathcl = xmlGetRel(etroot, "clusters");
	if (!pathcl) {
		fprintf(stderr, "ERROR API has no `rel=clusters'\n");
		exit(EXIT_FAILURE);
	}

	*psd = strdup((const char *)pathsd);
	if (!*psd)
		goto err_alloc;
	*pdc = strdup((const char *)pathdc);
	if (!*pdc)
		goto err_alloc;
	*pcl = strdup((const char *)pathcl);
	if (!*pcl)
		goto err_alloc;

	xmlFree(pathsd);
	xmlFree(pathdc);
	xmlFree(pathcl);

	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static xmlNode *xmlGetChild(xmlNode *node, const char *name)
{
	xmlNode *et;

	for (et = node->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, name) != 0)
			continue;
		return et;
	}
	return NULL;
}

static bool check_stor(struct config *cfg, xmlNode *etstor)
{
	xmlNode *ettext, *etaddr, *etpath;

	etaddr = xmlGetChild(etstor, "address");
	if (!etaddr) {
		fprintf(stderr,
		    "WARNIING NFS storage domain without address\n");
		return false;
	}
	etpath = xmlGetChild(etstor, "path");
	if (!etpath) {
		fprintf(stderr,
		    "WARNIING NFS storage domain without path\n");
		return false;
	}

	/*
	 * FIXME canonicalize host in case of e.g. raw IPv4/IPv6 address.
	 */
	ettext = etaddr->children;	/* mysterious indirection */
	if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
		return NULL;
	if (strcmp((char *)ettext->content, cfg->nfshost) != 0) {
#if 0 /* XXX really find a better way */
		/*
		 * Why even print this message? Because we want to do at least
		 * something if configuration is ham-fisted. However, this
		 * will pop up for every server that has 2 NFS storage domains.
		 * For now we cop-out by tagging it "INFO".
		 */
		fprintf(stderr, "INFO Host `%s' does not match cfg `%s'\n",
		    (char *)ettext->content, cfg->nfshost);
#endif
		return false;
	}
	ettext = etpath->children;
	if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
		return false;
	if (strcmp((char *)ettext->content, cfg->nfspath) != 0) {
#if 0 /* XXX really find a better way */
		fprintf(stderr, "INFO Path `%s' does not match cfg `%s'\n",
		    (char *)ettext->content, cfg->nfspath);
#endif
		return false;
	}
	return true;
}

static struct stor_dom *stordom_new(struct config *cfg, xmlChar *uuidsd,
    bool has_templates_on_top_level)
{
	struct stor_dom *sd;

	if (!(sd = malloc(sizeof(struct stor_dom)))) {
		fprintf(stderr, "ERROR No core\n");
		exit(EXIT_FAILURE);
	}
	memset(sd, 0, sizeof(struct stor_dom));
	sd->uuid = strdup((char *)uuidsd);
	if (!sd->uuid) {
		fprintf(stderr, "ERROR No core\n");
		exit(EXIT_FAILURE);
	}
	sd->address = cfg->nfshost;
	sd->path = cfg->nfspath;
	sd->toptpl = has_templates_on_top_level;
	return sd;
}

static struct stor_dom *apistordom(struct config *cfg,
    struct api_conn *connection, char *pathsd)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	struct stor_dom *sd;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *et;
	xmlNode *ettype, *etstor, *ettext;
	xmlChar *href;
	bool has_templates;
	xmlChar *uuidsd;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, pathsd);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "storage_domains");

	sd = NULL;
	for (et = etroot->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, "storage_domain") != 0)
			continue;

		ettype = xmlGetChild(et, "type");
		if (!ettype)
			continue;
		ettext = ettype->children;	/* mysterious indirection */
		if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
			continue;
		if (c_strcasecmp((char *)ettext->content, "EXPORT") != 0)
			continue;

		etstor = xmlGetChild(et, "storage");
		if (!etstor)
			continue;

		ettype = xmlGetChild(etstor, "type");
		if (!ettype)
			continue;
		ettext = ettype->children;	/* mysterious indirection */
		if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
			continue;
		if (c_strcasecmp((char *)ettext->content, "NFS") != 0)
			continue;

		if (!check_stor(cfg, etstor))
			continue;

		href = xmlGetRel(et, "templates");
		if (href) {
			has_templates = true;
			xmlFree(href);
		} else {
			has_templates = false;
		}

		uuidsd = xmlGetProp(et, (xmlChar *)"id");
		if (!uuidsd) {
			fprintf(stderr,
			    "WARNING NFS storage domain without UUID\n");
			continue;
		}
		sd = stordom_new(cfg, uuidsd, has_templates);
		xmlFree(uuidsd);
		if (sd)
			break;
	}

	if (!sd) {
		fprintf(stderr,
		    "ERROR NFS storage domain for `%s:%s' not found\n",
		    cfg->nfshost, cfg->nfspath);
		exit(EXIT_FAILURE);
	}

	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return sd;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static int apipoolid(struct config *cfg, struct api_conn *connection,
    xmlChar *pathsds, char *sd_uuid)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	xmlDocPtr doc;
	xmlNode *etsd;
	xmlNode *etroot;
	xmlChar *xid;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, pathsds);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "storage_domains");

	for (etsd = etroot->children; etsd; etsd = etsd->next) {
		if (etsd->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)etsd->name, "storage_domain") != 0)
			continue;

		xid = xmlGetProp(etsd, (xmlChar *)"id");
		if (!xid) {
			fprintf(stderr,
			    "WARNING storage domain without UUID\n");
			continue;
		}
		if (strcmp((char *)xid, sd_uuid) == 0) {
			xmlFree(xid);
			rc = 1;
			goto ret;
		}
		xmlFree(xid);
	}

	rc = 0;
ret:
	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return rc;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *apipool(struct config *cfg, struct api_conn *connection,
    char *pathdc, char *sd_uuid)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	char *ret;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *etdc;
	xmlChar *uuiddc;
	xmlChar *href;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, pathdc);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	/* <--- cleanup curl connection here if needed */

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api-dc.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "data_centers");

	uuiddc = NULL;
	for (etdc = etroot->children; etdc; etdc = etdc->next) {
		if (etdc->type != XML_ELEMENT_NODE)
			continue;
		uuiddc = xmlGetProp(etdc, (xmlChar *)"id");
		if (!uuiddc) {
			fprintf(stderr, "WARNING Datacenter without UUID\n");
			continue;
		}
		/* XXX Check for <status>UP</status> */
		href = xmlGetRel(etdc, "storagedomains");
		if (!href)
			continue;

		/* StoragePoolId is Data Center's UUID */
		if (apipoolid(cfg, connection, href, sd_uuid)) {
			xmlFree(href);
			break;
		}

		xmlFree(href);
		xmlFree(uuiddc);
	}

	if (!uuiddc) {
		fprintf(stderr,
		     "ERROR pool not found for storage domain %s\n", sd_uuid);
		exit(EXIT_FAILURE);
	}

	ret = strdup((char *)uuiddc);
	if (!ret)
		goto err_alloc;

	xmlFree(uuiddc);
	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return ret;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *apimasterid(const struct config *cfg, struct api_conn *connection,
    xmlChar *pathsds)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *etsd;
	xmlNode *et;
	xmlNode *ettext;
	xmlChar *xid;
	char *master;
	char *ret;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, pathsds);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "storage_domains");

	for (etsd = etroot->children; etsd; etsd = etsd->next) {
		if (etsd->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)etsd->name, "storage_domain") != 0)
			continue;

		xid = xmlGetProp(etsd, (xmlChar *)"id");
		if (!xid) {
			fprintf(stderr,
			    "WARNING storage domain without UUID\n");
			continue;
		}

		master = NULL;
		for (et = etsd->children; et; et = et->next) {
			if (et->type != XML_ELEMENT_NODE)
				continue;
			if (strcmp((const char *)et->name, "master") == 0) {
				ettext = et->children;
				if (!ettext ||
				    ettext->type != XML_TEXT_NODE ||
				    !ettext->content)
					continue;
				master = (char *)ettext->content;
				break;
			}
		}

		if (!master) {
			fprintf(stderr,
			    "WARNING storage domain without <master>\n");
			xmlFree(xid);
			continue;
		}
		if (strcmp(master, "true") == 0) {
			ret = strdup((char *)xid);
			if (!ret)
				goto err_alloc;
			xmlFree(xid);
			goto out;
		}
		xmlFree(xid);
	}

	ret = NULL;
out:
	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return ret;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *apimaster(const struct config *cfg, struct api_conn *connection,
    const char *pathdc, const char *dc_uuid)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	char *ret;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *etdc;
	xmlChar *uuiddc;
	xmlChar *href;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, pathdc);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api-dc.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "data_centers");

	for (etdc = etroot->children; etdc; etdc = etdc->next) {
		if (etdc->type != XML_ELEMENT_NODE)
			continue;
		uuiddc = xmlGetProp(etdc, (xmlChar *)"id");
		if (!uuiddc) {
			fprintf(stderr, "WARNING Datacenter without UUID\n");
			continue;
		}
		/* No need to check <status>UP</status>, we've got UUID. */
		if (strcmp((char *)uuiddc, dc_uuid) == 0) {
			xmlFree(uuiddc);
			break;
		}
		xmlFree(uuiddc);
	}
	if (!etdc) {
		/* impossible, but... */
		fprintf(stderr, "ERROR Datacenter `%s' not found\n", dc_uuid);
		exit(EXIT_FAILURE);
	}

	href = xmlGetRel(etdc, "storagedomains");
	if (!href) {
		fprintf(stderr,
		    "ERROR Storagedomains not found for datacenter `%s'\n",
		    dc_uuid);
		exit(EXIT_FAILURE);
	}

	ret = apimasterid(cfg, connection, href);
	if (!ret) {
		fprintf(stderr, "ERROR "
		    "Master storage domain not found for datacenter `%s'\n",
		    dc_uuid);
		exit(EXIT_FAILURE);
	}

	xmlFree(href);

	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return ret;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *apiclust_by_dc(xmlNode *etroot, const char *dcid)
{
	xmlNode *et, *etcl;
	xmlChar *id, *id1;
	xmlChar *uuidcl;
	char *ret;

	for (etcl = etroot->children; etcl; etcl = etcl->next) {
		if (etcl->type != XML_ELEMENT_NODE)
			continue;
		uuidcl = xmlGetProp(etcl, (xmlChar *)"id");
		if (!uuidcl) {
			fprintf(stderr, "WARNING Cluster without UUID\n");
			continue;
		}
		id = NULL;
		for (et = etcl->children; et; et = et->next) {
			if (et->type != XML_ELEMENT_NODE)
				continue;
			if (strcmp((const char *)et->name,"data_center") == 0) {
				id1 = xmlGetProp(et, (xmlChar *)"id");
				if (!id1)
					continue;
				if (id)
					xmlFree(id);
				id = id1;
			}
		}

		if (id) {
			if (strcmp((const char *)id, dcid) == 0) {
				ret = strdup((char *)uuidcl);
				if (!ret)
					goto err_alloc;
				xmlFree(id);
				xmlFree(uuidcl);
				return ret;
			}
			xmlFree(id);
		}
		xmlFree(uuidcl);
	}

	fprintf(stderr, "ERROR No cluster for DC `%s'\n", dcid);
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *apiclust_by_name(xmlNode *etroot, const char *clname)
{
	xmlNode *et, *ettext, *etcl;
	char *name;
	xmlChar *uuidcl;
	char *ret;

	for (etcl = etroot->children; etcl; etcl = etcl->next) {
		if (etcl->type != XML_ELEMENT_NODE)
			continue;
		uuidcl = xmlGetProp(etcl, (xmlChar *)"id");
		if (!uuidcl) {
			fprintf(stderr, "WARNING Cluster without UUID\n");
			continue;
		}
		name = NULL;
		for (et = etcl->children; et; et = et->next) {
			if (et->type != XML_ELEMENT_NODE)
				continue;
			if (strcmp((const char *)et->name, "name") == 0) {
				ettext = et->children;
				if (!ettext ||
				    ettext->type != XML_TEXT_NODE ||
				    !ettext->content)
					continue;
				name = (char *)ettext->content;
			}
		}
		if (name && strcmp(name, clname) == 0) {
			ret = strdup((char *)uuidcl);
			if (!ret)
				goto err_alloc;
			xmlFree(uuidcl);
			return ret;
		}
		xmlFree(uuidcl);
	}

	fprintf(stderr, "ERROR cluster `%s' not found\n", clname);
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

/*
 * Factory supplies us the cluster name, _none_, or _any_.
 * In case a name, find the UUID.
 * In case of _any_, find something suitable or abort if unable.
 * In case of _none_, return NULL (this means "do not import").
 *
 * This is yet another case of matching every object to find the one we want.
 */
static char *apiclust(struct config *cfg, struct api_conn *connection,
    const char *pathcl, const char *dcid)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	char *ret;
	xmlDocPtr doc;
	xmlNode *etroot;
	CURLcode rcc;
	int rc;

	if (strcmp(cfg->cluster, "_none_") == 0)
		return NULL;

	rc = asprintf(&url, "%s%s", connection->base, pathcl);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api-dc.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "clusters");

	if (strcmp(cfg->cluster, "_any_") == 0)
		ret = apiclust_by_dc(etroot, dcid);
	else
		ret = apiclust_by_name(etroot, cfg->cluster);

	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return ret;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static void api_start(struct api_conn *connection, struct config *cfg)
{
	struct http_uri huri;
	char *scheme, *host, *path, *base;
	bool is_ssl;
	char *authraw, *authhdr;
	size_t authrlen, authhlen;
	struct curl_slist *headers, *h;
	int rc;

	/*
	 * Note that using a proper URL parser means that we drop query and
	 * fragment from the configured URL. Fortunately, it is never a factor
	 * in RHEV-M API, due to its RESTful nature.
	 */
	if (!huri_parse(&huri, cfg->apiurl)) {
		fprintf(stderr, "ERROR unable to parse `apiurl': `%s'\n",
		    cfg->apiurl);
		exit(EXIT_FAILURE);
	}

	path = strndup(huri.path, huri.path_len);
	if (!path)
		goto err_alloc;
	host = strndup(huri.hostname, huri.hostname_len);
	if (!host)
		goto err_alloc;
	scheme = strndup(huri.scheme, huri.scheme_len);
	if (!scheme)
		goto err_alloc;

	if (strcmp(scheme, "http") == 0) {
		is_ssl = false;
	} else if (strcmp(scheme, "https") == 0) {
		is_ssl = true;
	} else {
		fprintf(stderr, "ERROR Invalid URL scheme `%s'\n", scheme);
		exit(EXIT_FAILURE);
	}

	if (huri.port)
		rc = asprintf(&base, "%s://%s:%u", scheme, host, huri.port);
	else
		rc = asprintf(&base, "%s://%s", scheme, host);
	if (rc < 0)
		goto err_alloc;

	connection->base = base;
	connection->path = path;
	connection->curl = curl_easy_init();
	if (is_ssl) {
		/*
		 * FIXME We should check the certificates, not ignore the problem.
		 */
		curl_easy_setopt(connection->curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt(connection->curl, CURLOPT_SSL_VERIFYPEER, 0);
	}

	headers = NULL;

	rc = asprintf(&authraw, "%s:%s", cfg->apiuser, cfg->apipass);
	if (rc < 0)
		goto err_alloc;
	authrlen = strlen(authraw);
	authhlen = ((authrlen+2)/3) * 4;	/* base64 expands 3 into 4 */
	authhlen += sizeof("Authorization: Basic ")-1;
	authhdr = malloc(authhlen + 1);		/* nul */
	if (!authhdr)
		goto err_alloc;
	strcpy(authhdr, "Authorization: Basic ");
	base64_encode(authraw, authrlen,
		      authhdr + (sizeof("Authorization: Basic ")-1),
		      authhlen - (sizeof("Authorization: Basic ")-1));
	authhdr[authhlen] = 0;	/* base64_encode zero-pads if smaller */

	h = curl_slist_append(headers, authhdr);
	if (!h)
		goto err_alloc;
	headers = h;

	connection->hdrs = headers;

	free(authhdr);
	free(authraw);
	free(scheme);
	free(host);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static void api_done(struct api_conn *connection)
{
	curl_easy_cleanup(connection->curl);
	curl_slist_free_all(connection->hdrs);
	free(connection->base);
	free(connection->path);
}

static void gen_uuids(struct id_pack *idp)
{
	uuid_t uuid;

	memset(idp, 0, sizeof(struct id_pack));

	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, idp->volume);

	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, idp->image);

	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, idp->template);
}

static void spitovf(const struct config *cfg, const struct stor_dom *sd,
    const char *poolid, const struct id_pack *idp, off_t vol_size)
{
	time_t now;
	struct tm now_tm;
	char now_str[50];
	xmlTextWriterPtr writer;
	char buf100[100];
	char *domdir, *tmpovfdir, *tmpovf, *tmpimgdir, *imgdir, *ovfdir;
	int rc;

	rc = asprintf(&domdir, "%s/%s", cfg->nfsdir, sd->uuid);
	if (rc < 0)
		goto err_alloc;
	rc = asprintf(&tmpovfdir, "%s/iwhd.%s", domdir, idp->template);
	if (rc < 0)
		goto err_alloc;
	rc = asprintf(&tmpovf, "%s/%s.ovf", tmpovfdir, idp->template);
	if (rc < 0)
		goto err_alloc;
	if (mkdir(tmpovfdir, 0770) < 0) {
		fprintf(stderr, "ERROR Failed to make directory %s: %s\n",
		    tmpovfdir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	rc = asprintf(&tmpimgdir, "%s/iwhd.%s", domdir, idp->image);
	if (rc < 0)
		goto err_alloc;
	rc = asprintf(&imgdir, "%s/images/%s", domdir, idp->image);
	if (rc < 0)
		goto err_alloc;

	rc = asprintf(&ovfdir, "%s/master/vms/%s", domdir, idp->template);
	if (rc < 0)
		goto err_alloc;

	/*
	 * When storage domain is freshly imported, without any VMs,
	 * the RHEV-M may not create the "master/vms/". Pre-create.
	 */
	ensure_path(ovfdir);

	now = time(NULL);
	gmtime_r(&now, &now_tm);
	strftime(now_str, 50, "%Y/%m/%d %H:%M:%S", &now_tm);

	writer = xmlNewTextWriterFilename(tmpovf, 0);
	if (!writer) {
		fprintf(stderr, "ERROR Error creating the xml driver for %s\n",
		    tmpovf);
		exit(EXIT_FAILURE);
	}
	xmlTextWriterSetIndent(writer, 1);

	rc = xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL);
	if (rc < 0) {
		fprintf(stderr, "ERROR Error in xmlTextWriterStartDocument\n");
		exit(EXIT_FAILURE);
	}

	rc = xmlTextWriterStartElement(writer, BAD_CAST "ovf:Envelope");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:version", BAD_CAST "0.9");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:ovf",
	    BAD_CAST "http://schemas.dmtf.org/ovf/envelope/1/");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:rasd",
	    BAD_CAST "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:vssd",
	    BAD_CAST "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:xsi",
	    BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "References");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterStartElement(writer, BAD_CAST "File");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%s/%s", idp->image, idp->volume);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:href", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST idp->volume);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu", (long long) vol_size);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:size", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:description", BAD_CAST image_name(cfg->image));
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <File> */
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <References> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Section");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xsi:type", BAD_CAST "ovf:NetworkSection_Type");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "List of Networks");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Section> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Section");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xsi:type", BAD_CAST "ovf:DiskSection_Type");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Disk");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:diskId", BAD_CAST idp->volume);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu",
	    (long long)((vol_size + (1024*1024*1024) - 1) / (1024*1024*1024)));
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:size", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:actual_size", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:vm_snapshot_id", (const xmlChar *) NULID);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%s/%s", idp->image, idp->volume);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:fileRef", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:format",
	    BAD_CAST "http://www.vmware.com/technical-resources/interfaces/vmdk_access.html");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:volume-format", BAD_CAST "RAW");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:volume-type", BAD_CAST "Preallocated");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:disk-interface", BAD_CAST "VirtIO");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:disk-type", BAD_CAST "System");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:boot", BAD_CAST "true");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:wipe-after-delete", BAD_CAST "false");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Disk> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Section> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Content");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xsi:type", BAD_CAST "ovf:VirtualSystem_Type");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST "out");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Name", BAD_CAST image_name(cfg->image));
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "TemplateId", BAD_CAST idp->template);
	if (rc < 0) goto err_xml;
	/* spec also has 'TemplateName' */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Description", BAD_CAST "Template by iwhd");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Domain", BAD_CAST "");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "CreationDate", BAD_CAST now_str);
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "TimeZone", BAD_CAST "");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "IsAutoSuspend", BAD_CAST "false");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "VmType", BAD_CAST "1");
	if (rc < 0) goto err_xml;

	/* vnc = 0, gxl = 1 */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "default_display_type", BAD_CAST "0");
	if (rc < 0) goto err_xml;

	/*
	 * C=0,   DC=1,  N=2, CDN=3, CND=4, DCN=5, DNC=6, NCD=7,
	 * NDC=8, CD=9, D=10, CN=11, DN=12, NC=13, ND=14
	 * (C - HardDisk, D - CDROM, N - Network)
	 */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "default_boot_sequence", BAD_CAST "1");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Section");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xsi:type", BAD_CAST "ovf:OperatingSystemSection_Type");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST idp->template);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:required", BAD_CAST "false");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "Guest OS");
	if (rc < 0) goto err_xml;
	/* This is rigid, must be "Other", "OtherLinux", "RHEL6", or such. */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Description", BAD_CAST "OtherLinux");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Section> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Section");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xsi:type", BAD_CAST "ovf:VirtualHardwareSection_Type");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "1 CPU, 512 Memory");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "System");
	if (rc < 0) goto err_xml;
	/* This is probably wrong, needs actual type. */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "vssd:VirtualSystemType", BAD_CAST "RHEVM 4.6.0.163");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <System> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Caption", BAD_CAST "1 virtual CPU");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST "Number of virtual CPU");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST "1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "3");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:num_of_sockets", BAD_CAST "1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:cpu_per_socket", BAD_CAST "1");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Caption", BAD_CAST "512 MB of memory");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST "Memory Size");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST "2");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "4");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AllocationUnits", BAD_CAST "MegaBytes");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:VirtualQuantity", BAD_CAST "512");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Caption", BAD_CAST "Drive 1");
	if (rc < 0) goto err_xml;
	/* Why no rasd:Description for disks? */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST idp->volume);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "17");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%s/%s", idp->image, idp->volume);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:HostResource", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Parent",
	    (const xmlChar *) NULID);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Template",
	    (const xmlChar *) NULID);
	if (rc < 0) goto err_xml;
	/* List of installed applications, separated by comma */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ApplicationList", BAD_CAST "");
	if (rc < 0) goto err_xml;
	/*
	 * "Storage Domain Id"
	 * This corresponds to ID of volgroup in host where snapshot was taken.
	 * Obviously we have nothing like it.
	 */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:StorageId",
	    (const xmlChar *) NULID);
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:StoragePoolId", BAD_CAST poolid);
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:CreationDate", BAD_CAST now_str);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:LastModified", BAD_CAST now_str);
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Caption", BAD_CAST "Ethernet 0 rhevm");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST "3");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "10");
	if (rc < 0) goto err_xml;
	/* e1000 = 2, pv = 3 */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceSubType", BAD_CAST "3");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Connection", BAD_CAST "rhevm");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Name", BAD_CAST "eth0");
	if (rc < 0) goto err_xml;

	/* also allowed is "MACAddress" */

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:speed", BAD_CAST "1000");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Caption", BAD_CAST "Graphics");
	if (rc < 0) goto err_xml;
	/* doc says "6", reality is "5" */
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST "5");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "20");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:VirtualQuantity", BAD_CAST "1");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Section> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <Content> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndDocument(writer);
	if (rc < 0) {
		fprintf(stderr, "ERROR Error in xmlTextWriterEndDocument\n");
		exit(EXIT_FAILURE);
	}

	xmlFreeTextWriter(writer);

	if (rename(tmpimgdir, imgdir) < 0) {
		fprintf(stderr, "ERROR Failed to rename from %s to %s: %s\n",
		    tmpimgdir, imgdir, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (rename(tmpovfdir, ovfdir) < 0) {
		fprintf(stderr, "ERROR Failed to rename from %s to %s: %s\n",
		    tmpovfdir, ovfdir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	free(domdir);
	free(tmpovfdir);
	free(tmpovf);
	free(tmpimgdir);
	free(imgdir);
	free(ovfdir);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);

 err_xml:
	fprintf(stderr, "ERROR Failed to form XML\n");
	exit(EXIT_FAILURE);
}

static void copyimage(const struct config *cfg, const struct id_pack *idp,
    const struct stor_dom *sd, const char *poolid)
{
	int rc;
	struct stat statb;
	char *domdir, *tmpimgdir;
	char *imgsrc, *imgdst, *imgmeta;
	time_t now;
	off_t vol_size;
	FILE *fp;

	if (geteuid() == 0) {
		/* printf("We're root, changing user and group to 36"); */
		setregid(-1, NFSGID);
		setreuid(-1, NFSUID);
	} else {
		if (geteuid() != NFSUID || getegid() != NFSGID) {
			fprintf(stderr,
			    "ERROR Have to run with user and group 36\n");
			exit(EXIT_FAILURE);
		}
	}

	rc = asprintf(&domdir, "%s/%s", cfg->nfsdir, sd->uuid);
	if (rc < 0)
		goto err_alloc;
	if (stat(domdir, &statb) < 0) {
		fprintf(stderr, "ERROR failed to stat %s: %s\n",
		    domdir, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!S_ISDIR(statb.st_mode)) {
		fprintf(stderr, "ERROR path %s is not a directory\n", domdir);
		exit(EXIT_FAILURE);
	}

	/* FIXME Do something about garbage-collecting iwhd.* directories */

	rc = asprintf(&tmpimgdir, "%s/iwhd.%s", domdir, idp->image);
	if (rc < 0)
		goto err_alloc;
	if (mkdir(tmpimgdir, 0770) < 0) {
		fprintf(stderr, "ERROR Failed to make directory %s: %s\n",
		    tmpimgdir, strerror(errno));
		exit(EXIT_FAILURE);
	}

	now = time(NULL);

	imgsrc = cfg->image;
	rc = asprintf(&imgdst, "%s/%s", tmpimgdir, idp->volume);
	if (rc < 0)
		goto err_alloc;

	/* No error processing here, it exits on error. */
	copy_file_preserving(imgsrc, imgdst);

	if (stat(imgdst, &statb) < 0) {
		fprintf(stderr, "ERROR failed to stat %s: %s\n",
		    imgdst, strerror(errno));
		exit(EXIT_FAILURE);
	}
	vol_size = statb.st_size;

	rc = asprintf(&imgmeta, "%s.meta", imgdst);
	if (rc < 0)
		goto err_alloc;

	fp = fopen(imgmeta, "w");
	if (!fp) {
		fprintf(stderr, "ERROR Failed to create %s: %s\n",
		    imgmeta, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fprintf(fp, "DOMAIN=%s\n", sd->uuid);
	/* saved template has VOLTYPE=SHARED */
	fprintf(fp, "VOLTYPE=LEAF\n");
	fprintf(fp, "CTIME=%llu\n", (long long)now);
	/* saved template has FORMAT=COW */
	fprintf(fp, "FORMAT=RAW\n");
	fprintf(fp, "IMAGE=%s\n", idp->image);
	fprintf(fp, "DISKTYPE=1\n");
	fprintf(fp, "PUUID=%s\n", NULID);
	fprintf(fp, "LEGALITY=LEGAL\n");
	fprintf(fp, "MTIME=%llu\n", (long long)now);
	fprintf(fp, "POOL_UUID=%s\n", poolid);
	/* assuming 1KB alignment, 512 is good for sure */
	fprintf(fp, "SIZE=%llu\n", (long long) (vol_size/512));
	fprintf(fp, "TYPE=SPARSE\n");
	fprintf(fp, "DESCRIPTION=Uploaded by iwhd+rhevreg\n");
	fprintf(fp, "EOF\n");
	if (close_stream(fp)) {
		fprintf(stderr, "ERROR Failed to write %s\n", imgmeta);
		exit(EXIT_FAILURE);
	}

	spitovf(cfg, sd, poolid, idp, vol_size);

	free(imgmeta);
	free(imgdst);
	free(tmpimgdir);
	free(domdir);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *import_get_status(xmlNode *etparent)
{
	char *status;
	xmlNode *et;
	xmlNode *ettext;

	for (et = etparent->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, "status") == 0)
			break;
	}
	if (!et) {
		fprintf(stderr, "ERROR No import status\n");
		exit(EXIT_FAILURE);
	}

	ettext = et->children;
	if (!ettext || ettext->type != XML_TEXT_NODE || !ettext->content) {
		fprintf(stderr, "ERROR Empty import status\n");
		exit(EXIT_FAILURE);
	}

	status = strdup((char *)ettext->content);
	if (!status)
		goto err_alloc;

	return status;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static xmlChar *import_start(struct config *cfg, struct api_conn *connection,
    const struct stor_dom *sd, const char *poolid, const char *tplid,
    const char *clustid, const char *msd)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers, *h, *hptr;
	struct api_buf apib, apob;
	char *url;
	char *xmlbuf;
	char *status;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlChar *ahref;
	CURLcode rcc;
	int rc;

	/*
	 * XXX This is incorrect. We should be using the href attribute
	 * in the <action> of the template. But finding that requires
	 * yet another total scan of everything. So we just construct
	 * the path for now.
	 */
	if (sd->toptpl) {
		/*
		 * RHEV-M 2.2 attaches templates at the top.
		 */
		rc = asprintf(&url,
		     "%s%s/storagedomains/%s/templates/%s/import",
		     connection->base, connection->path, sd->uuid, tplid);
	} else {
		/*
		 * RHEV-M 3 has templates deep under datacenters.
		 */
		rc = asprintf(&url,
		     "%s%s/datacenters/%s/storagedomains/%s/templates/%s/import",
		     connection->base, connection->path, poolid, sd->uuid, tplid);
	}
	if (rc < 0)
		goto err_alloc;

	/*
	 * The POST data is not even a complete XML, so we just roll it
	 * with printf.
	 */
	rc = asprintf(&xmlbuf,
	    "<action>\n"
	    "  <cluster id=\"%s\"/>\n"
	    "  <storage_domain id=\"%s\"/>\n"
	    "</action>\n",
	    clustid, msd);
	if (rc < 0)
		goto err_alloc;

	/*
	 * This operation needs a custom header in addition to the usual ones.
	 * Copy them and adjust to suit.
	 */
	headers = NULL;
	for (hptr = connection->hdrs; hptr; hptr = hptr->next) {
		h = curl_slist_append(headers, hptr->data);
		if (!h)
			goto err_alloc;
		headers = h;
	}
	h = curl_slist_append(headers, "Content-type: application/xml");
	if (!h)
		goto err_alloc;
	headers = h;

	/*
	 */
	memset(&apob, 0, sizeof(struct api_buf));
	apob.buf = xmlbuf;
	apob.alloc = strlen(xmlbuf);

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, apob.alloc);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, api_rcb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &apob);
	/* CURLOPT_HTTPGET later */

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed POST url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "action");

	ahref = xmlGetProp(etroot, (xmlChar *)"href");
	if (!ahref) {
		fprintf(stderr, "ERROR API action without href\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Get the status from POST reply in case it's COMPLETE or ERROR.
	 * We may not get another chance.
	 */
	status = import_get_status(etroot);
	if (c_strcasecmp(status, "COMPLETE") == 0) {
		/*
		 * One little idiosyncrasy of RHEV-2.2 is that if it returned
		 * a "COMPLETE" once, the status cannot be read again (although
		 * it also returns href=). A new access of the action href ends
		 * in a 301 with Location pointing to the imported template.
		 * We need to signal this up.
		 */
		xmlFree(ahref);
		ahref = NULL;
	} else if (c_strcasecmp(status, "PENDING") == 0 ||
		   c_strcasecmp(status, "IN_PROGRESS") == 0) {
		;
	} else {
		fprintf(stderr, "ERROR Bad import status `%s'\n", status);
		/*
		 * XXX process "FAILED" status, report meaningful error
		 *
		 * <action>
		 *     <storage_domain id="af096e18-4b05-4a04-bc60-5a4148d73b9c"/>
		 *     <cluster id="2ffa21f2-0d68-4c6b-98e3-0ef6ec5003e7"/>
		 *     <status>FAILED</status>
		 *     <fault>
		 *         <reason>RHEVM operation failed</reason>
		 *         <detail>[vm cannot import template name exists, var  action  import, var  type  vm template]</detail>
		 *     </fault>
		 * </action>
		 */
		exit(EXIT_FAILURE);
	}

	free(status);
	xmlFreeDoc(doc);
	free(apib.buf);
	free(xmlbuf);
	free(url);
	return ahref;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

static char *import_status(struct config *cfg, struct api_conn *connection,
    xmlChar *ahref)
{
	CURL *curl = connection->curl;
	struct curl_slist *headers = connection->hdrs;
	struct api_buf apib;
	char *url;
	char *status;
	xmlDocPtr doc;
	xmlNode *etroot;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, ahref);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);

	// if (debugging) /* if (verbose) */
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	etroot = xmlDocGetRootElement(doc);
	require_api_root(etroot->name, "action");

	status = import_get_status(etroot);

	xmlFreeDoc(doc);
	free(apib.buf);
	free(url);
	return status;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

/*
 * Import consists of two phases:
 *   1. collect the IDs that we need,
 *   2. issue the import call and monitor its progress.
 *
 * For phase 2 we need:
 *   - Datacenter ID
 *      + for which we remember that Pool ID is one and the same
 *   - Import Storage Domain ID, whence to import the template
 *      + uuid in sd
 *   - Template ID
 *   - Cluster ID
 *      + Supplied by command line or auto-detected
 *   - Master Storage Domain, destination where to import
 *
 * This is phase 2.
 */
static void import_tpl(struct config *cfg, struct api_conn *connection,
    const struct stor_dom *sd, const char *poolid, const char *tplid,
    const char *clustid, const char *msd)
{
	xmlChar *ahref;
	char *status;
	struct timespec tm;
	unsigned int i;

/* P3 */ printf("import cluster %s\n", clustid);
/* P3 */ printf("import target %s\n", msd);
	ahref = import_start(cfg, connection, sd, poolid, tplid, clustid, msd);
	if (!ahref)
		return;
/* P3 */ printf("import href %s\n", ahref);

	i = 0;
	for (;;) {
		status = import_status(cfg, connection, ahref);
		if (c_strcasecmp(status, "COMPLETE") == 0) {
			break;
		}
		if (c_strcasecmp(status, "PENDING") == 0 ||
		    c_strcasecmp(status, "IN_PROGRESS") == 0) {
			if (++i >= 20) {
				fprintf(stderr,
				    "ERROR import times out, status `%s'\n",
				    status);
				exit(EXIT_FAILURE);
			}
		} else {
			fprintf(stderr, "ERROR Unknown import status `%s'\n",
			    status);
			exit(EXIT_FAILURE);
		}

		tm.tv_sec = 3;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);

		free(status);
	}

	free(status);
	xmlFree(ahref);
}

static void delete_tpl(struct config *cfg,
    const struct stor_dom *sd, const struct id_pack *idp)
{
	char *path;
	int rc;

	/*
	 * Remove the OVF first. This kills the template for RHEV-M,
	 * so we can dismantle it in peace.
	 */
	rc = asprintf(&path, "%s/%s/master/vms/%s/%s.ovf",
	     cfg->nfsdir, sd->uuid, idp->template, idp->template);
	if (rc < 0)
		goto err_alloc;
	if (unlink(path) < 0)
		goto err_unlink;
	free(path);

	rc = asprintf(&path, "%s/%s/master/vms/%s",
	     cfg->nfsdir, sd->uuid, idp->template);
	if (rc < 0)
		goto err_alloc;
	if (rmdir(path) < 0)
		goto err_rmdir;
	free(path);

	rc = asprintf(&path, "%s/%s/images/%s/%s.meta",
	     cfg->nfsdir, sd->uuid, idp->image, idp->volume);
	if (rc < 0)
		goto err_alloc;
	if (unlink(path) < 0)
		goto err_unlink;
	free(path);

	rc = asprintf(&path, "%s/%s/images/%s/%s",
	     cfg->nfsdir, sd->uuid, idp->image, idp->volume);
	if (rc < 0)
		goto err_alloc;
	if (unlink(path) < 0)
		goto err_unlink;
	free(path);

	rc = asprintf(&path, "%s/%s/images/%s",
	     cfg->nfsdir, sd->uuid, idp->image);
	if (rc < 0)
		goto err_alloc;
	if (rmdir(path) < 0)
		goto err_rmdir;
	free(path);

	return;

 err_unlink:
	fprintf(stderr, "ERROR Cannot unlink `%s': %s\n",
	    path, strerror(errno));
	exit(EXIT_FAILURE);

 err_rmdir:
	fprintf(stderr, "ERROR Cannot remove `%s': %s\n",
	    path, strerror(errno));
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv, char **envp)
{
	json_error_t err;
	const char *cfgname;
	struct config cfg;
	struct api_conn conn;
	json_t *jcfg;
	char *pathsd, *pathdc, *pathcl;
	struct id_pack ids;
	struct stor_dom *sd;
	char *poolid, *clustid;
	char *msd;	/* Master Storage Domain - no need for full stor_dom */

	set_program_name (TAG);
	atexit (close_stdout);

	env_p = envp;

	if (argc == 1) {
		cfgname = TAG ".conf";
	} else if (argc == 2) {
		cfgname = argv[1];
		if (cfgname[0] == 0 || cfgname[0] == '-')
			Usage();
	} else {
		Usage();
		return 2; /* gcc warning about cfgname initialization */
	}

	memset(&cfg, 0, sizeof(struct config));

	jcfg = json_load_file(cfgname, &err);
	if (!jcfg) {
		fprintf(stderr, "ERROR configuration JSON error %s:%d: %s\n",
		    cfgname, err.line, err.text);
		exit(EXIT_FAILURE);
	}

	if (json_typeof(jcfg) != JSON_OBJECT) {
		fprintf(stderr,
		    "ERROR configuration JSON %s: root is not a struct\n",
		    cfgname);
		exit(EXIT_FAILURE);
	}

	/* image: local filename with disk image */
	cfg_veripick(&cfg.image, cfgname, jcfg, "image");
	if (!path_exists(cfg.image)) {
		fprintf(stderr, "ERROR image %s does not exist\n", cfg.image);
		exit(EXIT_FAILURE);
	}
	/* apiurl: the so-called "base", usually "rhev-api" */
	cfg_veripick(&cfg.apiurl, cfgname, jcfg, "apiurl");
	strip_trailing_slashes(cfg.apiurl);
	/*
	 * apiuser: username@AD.domain
	 * We do not enforce with '@' syntax in case someone comes up with
	 * RHEV-M that takes local authentication of some other trick.
	 */
	cfg_veripick(&cfg.apiuser, cfgname, jcfg, "apiuser");
	/* apipass: password for apiuser */
	cfg_veripick(&cfg.apipass, cfgname, jcfg, "apipass");
	/*
	 * nfshost: NFS server name
	 * nfspath: export path
	 * All RHEV-M servers have several storage domains, so we use this to
	 * select one. Also, we verify if 'nfsdir' points where it should.
	 */
	cfg_veripick(&cfg.nfshost, cfgname, jcfg, "nfshost");
	cfg_veripick(&cfg.nfspath, cfgname, jcfg, "nfspath");
	/*
	 * nfsdir: A directory where sysadmin, scripts or autofs mounted the
	 * same area that RHEV-M considers an export domain (/mnt/vdsm/rhevm23).
	 * N.B. If iwhd is running on the NFS server itself, nfsdir can be the
	 * exported directory itself (like /home/vdsm/rhevm23). We verify that
	 * the directory contains an expected structure, so attach it to RHEV-M
	 * before trying to register any images.
	 */
	cfg_veripick(&cfg.nfsdir, cfgname, jcfg, "nfsdir");
	if (cfg.nfsdir[0] == 0) {
		fprintf(stderr, "ERROR configuration: `nfsdir' is empty\n");
		exit(EXIT_FAILURE);
	}
	if (cfg.nfsdir[0] != '/') {
		fprintf(stderr, "ERROR configuration: `nfsdir' is relative\n");
		exit(EXIT_FAILURE);
	}

	cfg_veripick(&cfg.cluster, cfgname, jcfg, "cluster");

	json_decref(jcfg);
	jcfg = NULL;

	gen_uuids(&ids);

	api_start(&conn, &cfg);

	/*
	 * Step 1.1, fetch the refs
	 *
	 * This is largely a formality, because if we know names of resources,
	 * why not to fetch resources directly? But the docs imply we should
	 * jump through this hoop.
	 */
	apipaths(&conn, &pathsd, &pathdc, &pathcl);

	/*
	 * Step 1.2, get import domain
	 */
	sd = apistordom(&cfg, &conn, pathsd);

	/*
	 * Step 1.3, find the "storage pool ID"
	 *
	 * This is crazy to be a separate step. You'd expect the storage domain
	 * descriptor itself contain its pool, to be saved on Step 2. But no.
	 */
	poolid = apipool(&cfg, &conn, pathdc, sd->uuid);

	/*
	 * The first major transfer: create a template in an import domain.
	 */
	copyimage(&cfg, &ids, sd, poolid);

	/*
	 * Step 2.1, resolve or find the cluster
	 */
	clustid = apiclust(&cfg, &conn, pathcl, poolid);
	if (!clustid) {
		/*
		 * No cluster means no import. Just return the template.
		 */
		printf("IMAGE %s\n", ids.template);

		api_done(&conn);
		// sd_free(sd) -- XXX
		free(poolid);
		return 0;
	}

	/*
	 * Step 2.2, find the destination storage domain
	 */
	msd = apimaster(&cfg, &conn, pathdc, poolid);

	/*
	 * The second major transfer: import template into a master domain.
	 */
	import_tpl(&cfg, &conn, sd, poolid, ids.template, clustid, msd);

	/*
	 * Finally, delete the intermediary template in the export domain.
	 */
	delete_tpl(&cfg, sd, &ids);

	/*
	 * Same ID after import as before import, just located in a different
	 * storage domain now.
	 */
	printf("IMAGE %s\n", ids.template);

	api_done(&conn);
	// sd_free(sd) -- XXX
	free(poolid);
	return 0;
}
