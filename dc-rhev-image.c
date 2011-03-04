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
/* need _GNU_SOURCE for asprintf */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "copy-file.h"

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

struct stor_dom {
	char *uuid;
	char *address;
	char *path;
	char *poolid;
};

struct api_buf {
	char *buf;
	size_t alloc;
	size_t used;
};

struct api_conn {
	CURL *curl;
	char *base;
};

static void Usage(void)
{
	fprintf(stderr, "ERROR Usage: " TAG " [" TAG ".conf]\n");
	exit(1);
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

static int path_exists(const char *path)
{
	return access(path, R_OK) == 0;
}

static void
cfg_veripick(char **cfgval, const char *cfgname, json_t *jcfg, char *cfgtag)
{
	json_t *elem;
	const char *name;
	char *tmp;

	elem = json_object_get(jcfg, cfgtag);
	if (!json_is_string(elem)) {
		fprintf(stderr,
		    "ERROR configuration %s: tag %s is not a string\n",
		    cfgname, cfgtag);
		exit(2);
	}
	name = json_string_value(elem);
	if (!name) {
		fprintf(stderr, "ERROR configuration %s: tag %s has no value\n",
		    cfgname, cfgtag);
		exit(2);
	}
	tmp = strdup(name);
	if (!tmp) {
		fprintf(stderr, "ERROR no core\n");
		exit(1);
	}
	*cfgval = tmp;
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

static void apipaths(struct api_conn *connection, struct curl_slist *headers,
    char *path, char **psd, char **pdc)
{
	CURL *curl = connection->curl;
	struct api_buf apib;
	char *url;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *et;
	xmlChar *reltype;
	xmlChar *s;
	char *pathsd = NULL, *pathdc = NULL;
	CURLcode rcc;
	int rc;

	rc = asprintf(&url, "%s%s", connection->base, path);
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	// 	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(1);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(1);
	}

	etroot = xmlDocGetRootElement(doc);
	if (strcmp((const char *)etroot->name, "api") != 0) {
		fprintf(stderr, "ERROR API root is `api'\n");
		exit(1);
	}

	for (et = etroot->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, "link") != 0)
			continue;
		reltype = xmlGetProp(et, (xmlChar *)"rel");
		if (!reltype)
			continue;
		if (strcmp((char *)reltype, "storagedomains") == 0) {
			s = xmlGetProp(et, (xmlChar *)"href");
			if (!s)
				goto err_href;
			free(pathsd);
			pathsd = strdup((char *)s);
			if (!pathsd)
				goto err_alloc;
			xmlFree(s);
		} else if (strcmp((char *)reltype, "datacenters") == 0) {
			s = xmlGetProp(et, (xmlChar *)"href");
			if (!s)
				goto err_href;
			free(pathdc);
			pathdc = strdup((char *)s);
			if (!pathdc)
				goto err_alloc;
			xmlFree(s);
		}
		xmlFree(reltype);
	}

	if (!pathsd) {
		fprintf(stderr, "ERROR API has no `rel=storagedomains'\n");
		exit(1);
	}
	if (!pathdc) {
		fprintf(stderr, "ERROR API has no `rel=datacenters'\n");
		exit(1);
	}

	*psd = pathsd;
	*pdc = pathdc;

	xmlFreeDoc(doc);
	/* xmlCleanupParser(); -- hopefuly not necessary */
	free(apib.buf);
	free(url);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);

 err_href:
	fprintf(stderr, "ERROR <link /> with no `href'\n");
	exit(1);
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

static struct stor_dom *apistordom_1(struct config *cfg, xmlChar *uuidsd,
    xmlNode *etstor)
{
	xmlNode *ettext, *etaddr, *etpath;
	struct stor_dom *sd;

	etaddr = xmlGetChild(etstor, "address");
	if (!etaddr) {
		fprintf(stderr,
		    "WARNIING NFS storage domain without address\n");
		return NULL;
	}
	etpath = xmlGetChild(etstor, "path");
	if (!etpath) {
		fprintf(stderr,
		    "WARNIING NFS storage domain without path\n");
		return NULL;
	}

	/*
	 * XXX canonicalize host in case of e.g. raw IPv4/IPv6 address.
	 */
	ettext = etaddr->children;	/* mysterious indirection */
	if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
		return NULL;
	if (strcmp((char *)ettext->content, cfg->nfshost) != 0) {
		/*
		 * Why even print this message? Because we want to do at least
		 * something if configuration is ham-fisted. However, this
		 * will pop up for every server that has 2 NFS storage domains.
		 * For now we cop-out by tagging it "INFO".
		 */
		fprintf(stderr, "INFO Host `%s' does not match cfg `%s'\n",
		    (char *)ettext->content, cfg->nfshost);
		return NULL;
	}
	ettext = etpath->children;	/* mysterious indirection */
	if (!ettext || ettext->type!=XML_TEXT_NODE || !ettext->content)
		return NULL;
	if (strcmp((char *)ettext->content, cfg->nfspath) != 0) {
		/*
		 * Why even print this message? Because we want to do at least
		 * something if configuration is ham-fisted. However, this
		 * will pop up for every server that has 2 NFS storage domains.
		 * For now we cop-out by tagging it "INFO".
		 */
		fprintf(stderr, "INFO Host `%s' does not match cfg `%s'\n",
		    (char *)ettext->content, cfg->nfshost);
		return NULL;
	}

	if (!(sd = malloc(sizeof(struct stor_dom)))) {
		fprintf(stderr, "ERROR No core\n");
		exit(1);
	}
	memset(sd, 0, sizeof(struct stor_dom));
	sd->uuid = strdup((char *)uuidsd);
	if (!sd->uuid) {
		fprintf(stderr, "ERROR No core\n");
		exit(1);
	}
	sd->address = cfg->nfshost;
	sd->path = cfg->nfspath;

	return sd;
}

static struct stor_dom *apistordom(struct config *cfg,
    struct api_conn *connection, struct curl_slist *headers, char *pathsd)
{
	CURL *curl = connection->curl;
	struct api_buf apib;
	char *url;
	struct stor_dom *sd;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *et;
	xmlNode *ettype, *etstor, *ettext;
	xmlChar *uuidsd;
	CURLcode rcc;
	int rc;

	// XXX GET /rhevm-api/storagedomains/ crashes server, see bz#670397
	// So for now we ignore the pathsd and use a query instead.
	// rc = asprintf(&url, "%s%s", connection->base, pathsd);
	rc = asprintf(&url, "%s%s", connection->base, "/rhevm-api/storagedomains/?search=type%20%21%3D%20fcp");
	if (rc < 0)
		goto err_alloc;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	// if (debugging) /* if (verbose) */
	// 	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(1);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(1);
	}

	etroot = xmlDocGetRootElement(doc);
	if (strcmp((const char *)etroot->name, "storage_domains") != 0) {
		fprintf(stderr, "ERROR API root is `storage_domains'\n");
		exit(1);
	}

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
		if (strcmp((char *)ettext->content, "EXPORT") != 0)
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
		if (strcmp((char *)ettext->content, "NFS") != 0)
			continue;

		uuidsd = xmlGetProp(et, (xmlChar *)"id");
		if (!uuidsd) {
			fprintf(stderr,
			    "WARNING NFS storage domain without UUID\n");
			continue;
		}
		sd = apistordom_1(cfg, uuidsd, etstor);
		xmlFree(uuidsd);
		if (sd)
			break;
	}

	if (!sd) {
		fprintf(stderr, "ERROR NFS storage domain for `%s' not found\n",
		    url);
		exit(1);
	}

	xmlFreeDoc(doc);
	/* xmlCleanupParser(); -- hopefuly not necessary */
	free(apib.buf);
	free(url);
	return sd;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);
	return NULL;
}

static int apipoolid(struct config *cfg, struct api_conn *connection,
    struct curl_slist *headers, xmlChar *pathsds, char *sd_uuid)
{
	CURL *curl = connection->curl;
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
	// 	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(1);
	}

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(1);
	}

	etroot = xmlDocGetRootElement(doc);
	if (strcmp((const char *)etroot->name, "storage_domains") != 0) {
		fprintf(stderr, "ERROR API root is `storage_domains'\n");
		exit(1);
	}

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
	/* xmlCleanupParser(); -- hopefuly not necessary */
	free(apib.buf);
	free(url);
	return rc;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);
	return 0;
}

static char *apipool(struct config *cfg, struct api_conn *connection,
    struct curl_slist *headers, char *pathdc, char *sd_uuid)
{
	CURL *curl = connection->curl;
	struct api_buf apib;
	char *url;
	char *ret;
	xmlDocPtr doc;
	xmlNode *etroot;
	xmlNode *etdc, *etlink;
	// xmlNode *ettype, *etstor, *ettext;
	xmlChar *uuiddc;
	xmlChar *rel, *href;
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
	// 	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, "ERROR curl failed GET url `%s'\n", url);
		exit(1);
	}

	/* <--- cleanup curl connection here if needed */

	doc = xmlReadMemory(apib.buf, apib.used, "rhev-api-dc.xml", NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "ERROR API parse error in `%s'\n", url);
		exit(1);
	}

	etroot = xmlDocGetRootElement(doc);
	if (strcmp((const char *)etroot->name, "data_centers") != 0) {
		fprintf(stderr, "ERROR API root is `data_centers'\n");
		exit(1);
	}

	for (etdc = etroot->children; etdc; etdc = etdc->next) {
		if (etdc->type != XML_ELEMENT_NODE)
			continue;
		uuiddc = xmlGetProp(etdc, (xmlChar *)"id");
		if (!uuiddc) {
			fprintf(stderr,
			    "WARNING NFS storage domain without UUID\n");
			continue;
		}
		for (etlink = etdc->children; etlink; etlink = etlink->next) {
			if (etlink->type != XML_ELEMENT_NODE)
				continue;
			/* most likely it's not even a link, but "name" or "version" */
			if (strcmp((const char *)etlink->name, "link") != 0)
				continue;
			rel = xmlGetProp(etlink, (xmlChar *)"rel");
			if (!rel)
				continue;
			/* there's a bunch of other links like "files", "permissions" */
			if (strcmp((const char *)rel, "storagedomains") != 0) {
				xmlFree(rel);
				continue;
			}
			href = xmlGetProp(etlink, (xmlChar *)"href");
			if (!href) {
				fprintf(stderr,
				    "WARNING data canter link without href\n");
				xmlFree(rel);
				continue;
			}

			if (apipoolid(cfg, connection, headers, href, sd_uuid)) {
				/* StoragePoolId is Data Center's UUID */

				ret = strdup((char *)uuiddc);
				if (!ret)
					goto err_alloc;
				xmlFree(href);
				xmlFree(rel);

				xmlFree(uuiddc);
				xmlFreeDoc(doc);
				/* xmlCleanupParser(); -- hopefuly not necessary */
				free(apib.buf);
				free(url);
				return ret;
			}
			xmlFree(href);
			xmlFree(rel);
		}
		xmlFree(uuiddc);
	}

	fprintf(stderr, "ERROR pool not found for storage domain %s\n", sd_uuid);
	exit(1);
	return NULL;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);
	return NULL;
}

static struct stor_dom *apistart(struct config *cfg)
{
	struct http_uri huri;
	struct stor_dom *sd;
	char *host, *path, *base;
	char *pathsd, *pathdc;
	char *authraw, *authhdr;
	size_t authrlen, authhlen;
	struct curl_slist *headers, *h;
	struct api_conn connection;
	int rc;

	/*
	 * Note that using a proper URL parser means that we drop query and
	 * fragment from the configured URL. Fortunately, it is never a factor
	 * in RHEV-M API, due to its RESTful nature.
	 */
	if (!huri_parse(&huri, cfg->apiurl)) {
		fprintf(stderr, "ERROR unable to parse `apiurl': `%s'\n",
		    cfg->apiurl);
		exit(1);
	}

	path = strndup(huri.path, huri.path_len);
	if (!path)
		goto err_alloc;
	host = strndup(huri.hostname, huri.hostname_len);
	if (!host)
		goto err_alloc;

	if (huri.port)
		rc = asprintf(&base, "http://%s:%u", host, huri.port);
	else
		rc = asprintf(&base, "http://%s", host);
	if (rc < 0)
		goto err_alloc;

	connection.base = base;
	connection.curl = curl_easy_init();

	headers = NULL;

	rc = asprintf(&authraw, "%s:%s", cfg->apiuser, cfg->apipass);
	if (rc < 0)
		goto err_alloc;
	authrlen = strlen(authraw);
	authhlen = ((authrlen+2)/3) * 4;	/* base64 expands 3 into 4 */
	authhlen += sizeof("Authorization: Basic ")-1;
	authhdr = malloc(authhlen + 3);		/* \r\n and nul */
	if (!authhdr)
		goto err_alloc;
	strcpy(authhdr, "Authorization: Basic ");
	base64_encode(authraw, authrlen,
		      authhdr + (sizeof("Authorization: Basic ")-1),
		      authhlen - (sizeof("Authorization: Basic ")-1));
	strcat(authhdr, "\r\n");

	h = curl_slist_append(headers, authhdr);
	if (!h)
		goto err_alloc;
	headers = h;

	/*
	 * Step 1, fetch the API root
	 *
	 * This is largely a formality, because if we know names of resources,
	 * why not to fetch resources directly? But the docs imply we should
	 * jump through this hoop.
	 */
	apipaths(&connection, headers, path, &pathsd, &pathdc);

	/*
	 * We should pull the API version and check that it's more than 2.3 XXX
	 *
	 * Step 2, connect again, get domains
	 */
	sd = apistordom(cfg, &connection, headers, pathsd);

	/*
	 * Step 3, find the "storage pool ID"
	 *
	 * This is crazy to be a separate step. You'd expect the storage domain
	 * descriptor itself contain its pool, to be saved on Step 2. But no.
	 */
	sd->poolid = apipool(cfg, &connection, headers, pathdc, sd->uuid);

	curl_easy_cleanup(connection.curl);

	free(authhdr);
	free(authraw);
	free(host);
	free(path);
	free(base);
	return sd;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);
}

static void spitovf(struct config *cfg, struct stor_dom *sd,
    uuid_t img_uuid, uuid_t vol_uuid, off_t vol_size, uuid_t tpl_uuid)
{
	time_t now;
	struct tm now_tm;
	char now_str[50];
	xmlTextWriterPtr writer;
	char uuidbuf[37];
	char buf100[100];
	char *s;
	char *domdir, *tmpovfdir, *tmpovf, *tmpimgdir, *imgdir, *ovfdir;
	int rc;

	uuid_generate_random(tpl_uuid);

	rc = asprintf(&domdir, "%s/%s", cfg->nfsdir, sd->uuid);
	if (rc < 0)
		goto err_alloc;
	uuid_unparse_lower(tpl_uuid, uuidbuf);
	rc = asprintf(&tmpovfdir, "%s/iwhd.%s", domdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;
	uuid_unparse_lower(tpl_uuid, uuidbuf);
	rc = asprintf(&tmpovf, "%s/%s.ovf", tmpovfdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;
	if (mkdir(tmpovfdir, 0770) < 0) {
		fprintf(stderr, "ERROR Failed to make directory %s: %s\n",
		    tmpovfdir, strerror(errno));
		exit(1);
	}

	uuid_unparse_lower(img_uuid, uuidbuf);
	rc = asprintf(&tmpimgdir, "%s/iwhd.%s", domdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;
	uuid_unparse_lower(img_uuid, uuidbuf);
	rc = asprintf(&imgdir, "%s/images/%s", domdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;

	uuid_unparse_lower(tpl_uuid, uuidbuf);
	rc = asprintf(&ovfdir, "%s/master/vms/%s", domdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;

	now = time(NULL);
	gmtime_r(&now, &now_tm);
	strftime(now_str, 50, "%Y/%m/%d %H:%M:%S", &now_tm);

	writer = xmlNewTextWriterFilename(tmpovf, 0);
	if (!writer) {
		fprintf(stderr, "ERROR Error creating the xml driver for %s\n",
		    tmpovf);
		exit(1);
	}

	rc = xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL);
	if (rc < 0) {
		fprintf(stderr, "ERROR Error in xmlTextWriterStartDocument\n");
		exit(1);
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
	uuid_unparse_lower(img_uuid, buf100);
	buf100[36] = '/';
	uuid_unparse_lower(vol_uuid, buf100+37);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:href", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	uuid_unparse_lower(vol_uuid, uuidbuf);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST uuidbuf);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu", (long long) vol_size);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:size", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	/* This is basename(), but we handroll it to make sure, due to BSD. */
	if (!(s = strrchr(cfg->image, '/')) || s[1]==0)
		s = cfg->image;
	else
		s++;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:description", BAD_CAST s);
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
	uuid_unparse_lower(vol_uuid, uuidbuf);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:diskId", BAD_CAST uuidbuf);
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
	uuid_unparse_lower(img_uuid, buf100);
	buf100[36] = '/';
	uuid_unparse_lower(vol_uuid, buf100+37);
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

	if (!(s = strrchr(cfg->image, '/'))) s = cfg->image;
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "Name", BAD_CAST s);
	if (rc < 0) goto err_xml;

	uuid_unparse_lower(tpl_uuid, uuidbuf);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "TemplateId", BAD_CAST uuidbuf);
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
	uuid_unparse_lower(tpl_uuid, uuidbuf);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST uuidbuf);
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
	uuid_unparse_lower(vol_uuid, uuidbuf);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceId", BAD_CAST uuidbuf);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "17");
	if (rc < 0) goto err_xml;
	uuid_unparse_lower(img_uuid, buf100);
	buf100[36] = '/';
	uuid_unparse_lower(vol_uuid, buf100+37);
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
	    BAD_CAST "rasd:StoragePoolId", BAD_CAST sd->poolid);
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
		exit(1);
	}

	xmlFreeTextWriter(writer);

	if (rename(tmpimgdir, imgdir) < 0) {
		fprintf(stderr, "ERROR Failed to rename from %s to %s: %s\n",
		    tmpimgdir, imgdir, strerror(errno));
		exit(1);
	}
	if (rename(tmpovfdir, ovfdir) < 0) {
		fprintf(stderr, "ERROR Failed to rename from %s to %s: %s\n",
		    tmpovfdir, ovfdir, strerror(errno));
		exit(1);
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
	exit(1);

 err_xml:
	fprintf(stderr, "ERROR Failed to form XML\n");
	exit(1);
}

static void copyimage(struct config *cfg, struct stor_dom *sd, uuid_t tpl_uuid)
{
	int rc;
	struct stat statb;
	uuid_t vol_uuid, img_uuid;
	char *domdir, *tmpimgdir;
	char *imgsrc, *imgdst, *imgmeta;
	char uuidbuf[37];
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
			exit(1);
		}
	}

	rc = asprintf(&domdir, "%s/%s", cfg->nfsdir, sd->uuid);
	if (rc < 0)
		goto err_alloc;
	if (stat(domdir, &statb) < 0) {
		fprintf(stderr, "ERROR failed to stat %s: %s\n",
		    domdir, strerror(errno));
		exit(1);
	}
	if (!S_ISDIR(statb.st_mode)) {
		fprintf(stderr, "ERROR path %s is not a directory\n", domdir);
		exit(1);
	}

	uuid_generate_random(vol_uuid);
	uuid_generate_random(img_uuid);

	/* XXX Do something about garbage-collecting iwhd.* directories */

	uuid_unparse_lower(img_uuid, uuidbuf);
	rc = asprintf(&tmpimgdir, "%s/iwhd.%s", domdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;
	if (mkdir(tmpimgdir, 0770) < 0) {
		fprintf(stderr, "ERROR Failed to make directory %s: %s\n",
		    tmpimgdir, strerror(errno));
		exit(1);
	}

	now = time(NULL);

	imgsrc = cfg->image;
	uuid_unparse_lower(vol_uuid, uuidbuf);
	rc = asprintf(&imgdst, "%s/%s", tmpimgdir, uuidbuf);
	if (rc < 0)
		goto err_alloc;

	/* No error processing here, it exits on error. */
	copy_file_preserving(imgsrc, imgdst);

	if (stat(imgdst, &statb) < 0) {
		fprintf(stderr, "ERROR failed to stat %s: %s\n",
		    imgdst, strerror(errno));
		exit(1);
	}
	vol_size = statb.st_size;

	rc = asprintf(&imgmeta, "%s.meta", imgdst);
	if (rc < 0)
		goto err_alloc;

	fp = fopen(imgmeta, "w");
	if (!fp) {
		fprintf(stderr, "ERROR Failed to create %s: %s\n",
		    imgmeta, strerror(errno));
		exit(1);
	}
	fprintf(fp, "DOMAIN=%s\n", sd->uuid);
	/* saved template has VOLTYPE=SHARED */
	fprintf(fp, "VOLTYPE=LEAF\n");
	fprintf(fp, "CTIME=%llu\n", (long long)now);
	/* saved template has FORMAT=COW */
	fprintf(fp, "FORMAT=RAW\n");
	uuid_unparse_lower(img_uuid, uuidbuf);
	fprintf(fp, "IMAGE=%s\n", uuidbuf);
	fprintf(fp, "DISKTYPE=1\n");
	fprintf(fp, "PUUID=%s\n", NULID);
	fprintf(fp, "LEGALITY=LEGAL\n");
	fprintf(fp, "MTIME=%llu\n", (long long)now);
	fprintf(fp, "POOL_UUID=%s\n", sd->poolid);
	/* assuming 1KB alignment, 512 is good for sure */
	fprintf(fp, "SIZE=%llu\n", (long long) (vol_size/512));
	fprintf(fp, "TYPE=SPARSE\n");
	fprintf(fp, "DESCRIPTION=Uploaded by iwhd+rhevreg\n");
	fprintf(fp, "EOF\n");
	if (close_stream(fp)) {
		fprintf(stderr, "ERROR Failed to write %s\n", imgmeta);
		exit(1);
	}

	spitovf(cfg, sd, img_uuid, vol_uuid, vol_size, tpl_uuid);

	free(imgmeta);
	free(imgdst);
	free(tmpimgdir);
	free(domdir);
	return;

 err_alloc:
	fprintf(stderr, "ERROR No core\n");
	exit(1);
}

int main(int argc, char **argv, char **envp)
{
	uuid_t tpl_uuid;
	json_error_t err;
	char *cfgname;
	struct config cfg;
	json_t *jcfg;
	struct stor_dom *sd;
	char uuidbuf[37];

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
		exit(2);
	}

	if (json_typeof(jcfg) != JSON_OBJECT) {
		fprintf(stderr,
		    "ERROR configuration JSON %s: root is not a struct\n",
		    cfgname);
		exit(2);
	}

	/* image: local filename with disk image */
	cfg_veripick(&cfg.image, cfgname, jcfg, "image");
	if (!path_exists(cfg.image)) {
		fprintf(stderr, "ERROR image %s does not exist\n", cfg.image);
		exit(1);
	}
	/* apiurl: the so-called "base", usually "rhev-api" */
	cfg_veripick(&cfg.apiurl, cfgname, jcfg, "apiurl");
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
	 * nfsdir: A directory where sysadmin or boot scripts or autofs mounted
	 * the same area that RHEV-M considers an export domain (/mnt/vdsm/rhevm23).
	 * N.B. If iwhd is running on the NFS server itself, nfsdir can be the
	 * exported directory itself (like /home/vdsm/rhevm23). We verify that
	 * the directory contains an expected structure, so attach it to RHEV-M
	 * before trying to register any images.
	 */
	cfg_veripick(&cfg.nfsdir, cfgname, jcfg, "nfsdir");
	if (cfg.nfsdir[0] == 0) {
		fprintf(stderr, "ERROR configuration: `nfsdir' is empty\n");
		exit(2);
	}
	if (cfg.nfsdir[0] != '/') {
		fprintf(stderr, "ERROR configuration: `nfsdir' is relative\n");
		exit(2);
	}

	json_decref(jcfg);
	jcfg = NULL;

	sd = apistart(&cfg);

	copyimage(&cfg, sd, tpl_uuid);

	uuid_unparse_lower(tpl_uuid, uuidbuf);
	printf("IMAGE %s\n", uuidbuf);
	return 0;
}
