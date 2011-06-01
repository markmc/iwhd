/*
 * dc-vmware-image: register an image in vSphere
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <zlib.h>

#define TAG "dc-vmware-image"

/*
 * These C structures were officially documented in VMDK specification.
 * We see no reason to roll our own.
 */
typedef uint64_t SectorType;
typedef unsigned char Bool;

struct MetaDataMarker {
	SectorType val;
	uint32_t size;
	uint32_t type;
	unsigned char pad[496];
	unsigned char metadata[0];
};

#define MARKER_EOS	0
#define MARKER_GT	1
#define MARKER_GD	2
#define MARKER_FOOTER	3

struct GrainMarker {
	SectorType val;
	uint32_t size;
} __attribute__((__packed__));

struct SparseExtentHeader {
	uint32_t	magicNumber;
	uint32_t	version;
	uint32_t	flags;
	SectorType	capacity;
	SectorType	grainSize;
	SectorType	descriptorOffset;
	SectorType	descriptorSize;
	uint32_t	numGTEsPerGT;
	SectorType	rgdOffset;
	SectorType	gdOffset;
	SectorType	overHead;
	Bool		uncleanShutdown;
	char		singleEndLineChar;
	char		nonEndLineChar;
	char		doubleEndLineChar1;
	char		doubleEndLineChar2;
	uint16_t	compressAlgorithm;
	unsigned char pad[433];
} __attribute__((__packed__));

#define SPARSE_MAGICNUMBER 0x564d444b /* 'V' 'M' 'D' 'K' */

#define COMPRESSION_DEFLATE 1

#define GD_AT_END  0xffffffffffffffff

/*
 */
struct config {
	char *apiurl;
	char *apiuser;
	char *apipass;

	char *push_name;
	char *push_img;
	char *push_host;
	char *push_tmp;
};

struct session {
	CURL *curl;
	struct curl_slist *curlhdrs;
};

struct api_buf {
	char *buf;
	size_t alloc;
	size_t used;	/* a rolling count within [alloc], actually */
};

enum v__HttpNfcLeaseState {
	v__HttpNfcLeaseState__initializing = 0,
	v__HttpNfcLeaseState__ready = 1,
	v__HttpNfcLeaseState__done = 2,
	v__HttpNfcLeaseState__error = 3
};

struct v__ServiceContent {
	xmlDoc *scdoc;
	xmlNode *scnode;
};

struct v__ManagedObjectReference {
	char *type;
	char *__item;
};

struct v_prop {
	// char *name;
	xmlNode *value;
};

struct v__OvfCreateImportSpecResult {
	xmlDoc *doc;
	xmlNode *node;
};

struct v_lease {
	struct v__ManagedObjectReference *mor;
	// xmlNode *info;	/* can save in v_lease_parse_info() */
	char *url;		/* upload URL for our only VMDK */
};

struct v_rpc_arg {
	const char *type;
	const char *value;
};

static void Usage(void)
{
	fprintf(stderr, "Usage: " TAG " apiurl apiuser apipass"
	    " vmname imgfile vmhost tmpname\n");
	fprintf(stderr, " apiurl:  vSphere URL - https://vsphere.virt.bos.redhat.com/sdk\n");
	fprintf(stderr, " apiuser: vSphere login - Administrator@virt.lab.eng.bos.redhat.com\n");
	fprintf(stderr, " apipass: vSphere password - passw0rd\n");
	fprintf(stderr, " vmname:  desired VM name - pushtest\n");
	fprintf(stderr, " imgfile: image file name - ../pushtest.img\n");
	fprintf(stderr, " vmhost:  selected host - virtlab110.virt.bos.redhat.com\n");
	fprintf(stderr, " tmpname: temporary file or \"-\" for pipe\n");
	exit(EXIT_FAILURE);
}

static struct v__ServiceContent *sc_alloc(void)
{
	struct v__ServiceContent *sc;
	sc = malloc(sizeof(struct v__ServiceContent));
	if (!sc)
		return NULL;
	memset(sc, 0, sizeof(struct v__ServiceContent));
	return sc;
}

static void sc_free(struct v__ServiceContent *sc)
{
	xmlFreeDoc(sc->scdoc);
	// sc->scnode should be freed by freeing the doc, we hope.
	free(sc);
}

#if 0
static char *x_strdup(const char *val)
{
	char *ret;

	ret = strdup(val);
	if (!ret)
		goto err_alloc;
	return ret;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}
#endif

static char *x_gettext(xmlNode *et)
{
	xmlNode *retval;
	char *ret;

	retval = et->children;
	if (!retval || retval->type!=XML_TEXT_NODE || !retval->content)
		goto err_notext_retval;

	ret = strdup((const char *)retval->content);
	if (!ret)
		goto err_alloc;
	return ret;

 err_notext_retval:
	fprintf(stderr, TAG ": No text in node `%s'\n", et->name);
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static struct v_prop *prop_new(xmlNode *etval)
{
	struct v_prop *ret;

	ret = malloc(sizeof(struct v_prop));
	if (!ret)
		goto err_alloc;
	ret->value = xmlCopyNode(etval, 1);
	if (!ret->value)
		goto err_alloc;
	return ret;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static void prop_free(struct v_prop *p)
{
	xmlFreeNode(p->value);
	free(p);
}

static int api_dbcb(CURL *curl, curl_infotype type, char *text, size_t size,
    void *arg)
{
	enum { IN_TEXT, IN_EOL } state;
	const char *tag;
	const char *s, *line;
	char *p;

	switch (type) {
	case CURLINFO_TEXT:
		tag = "**";
		break;
	case CURLINFO_HEADER_IN:
		tag = "<<";
		break;
	case CURLINFO_HEADER_OUT:
		tag = ">>";
		break;
	default:
		p = strndup(text, size);
		if (p) {
			fprintf(stderr, "== %s\n", p);
			free(p);
		}
		return 0;
	}

	state = IN_TEXT;
	line = text;
	for (s = text; s < text + size && *s != 0; s++) {
		if (state == IN_TEXT) {
			if (*s == '\r' || *s == '\n') {
				p = strndup(line, s-line);
				if (p) {
					fprintf(stderr, "%s %s\n", tag, p);
					free(p);
				}
				state = IN_EOL;
			}
		} else {
			if (*s != '\r' && *s != '\n') {
				state = IN_TEXT;
				line = s;
			}
		}
	}
	if (state == IN_TEXT && s != line) {
		p = strndup(line, s-line);
		if (p) {
			fprintf(stderr, "%s %s\n", tag, p);
			free(p);
		}
	}
	return 0;
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

static void cfg_parse(struct config *cfg, int argc, char **argv)
{

	memset(cfg, 0, sizeof(struct config));

	if (argc != 8)
		Usage();
	cfg->apiurl = argv[1];
	cfg->apiuser = argv[2];
	cfg->apipass = argv[3];
	cfg->push_name = argv[4];	// "pushtest";
	cfg->push_img = argv[5];	// may need to basename
	cfg->push_host = argv[6];	// "virtlab110.virt.bos.redhat.com"
	if (argv[7][0] != '-') {
		/* Use "-" for a pipe */
		cfg->push_tmp = argv[7];
	}
}

static bool curlx_add_header(struct curl_slist **headers, const char *hdr)
{
	struct curl_slist *h;

	h = curl_slist_append(*headers, hdr);
	if (!h)
		return false;
	*headers = h;
	return true;
}

/* No idea why DV never implemented this, but implemented xmlGetProp. */
static xmlNode *xmlGetChild(xmlNode *etroot, const char *name)
{
	xmlNode *et;

	for (et = etroot->children; et; et = et->next) {
		if (et->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((const char *)et->name, name) != 0)
			continue;
		return et;
	}
	return NULL;
}

static xmlNode *x_getchild(xmlNode *etroot, const char *name)
{
	xmlNode *et;
	const xmlChar *p;

	et = xmlGetChild(etroot, name);
	if (!et) {
		p = xmlGetNodePath(etroot);
		if (!p)
			p = etroot->name;
		fprintf(stderr, TAG ": No child `%s' in node `%s'\n", name, p);
		exit(EXIT_FAILURE);
	}
	return et;
}

static xmlNode *x_addchild(xmlDoc *doc, xmlNs *ns, xmlNode *parent,
    const char *type, const char *value)
{
	xmlNode *child;

	child = xmlNewDocNode(doc, ns, BAD_CAST type, BAD_CAST value);
	if (!child)
		goto err_alloc;
	xmlAddChild(parent, child);
	return child;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static xmlNode *x_addchild_1prop(xmlDoc *doc, xmlNs *ns, xmlNode *parent,
    const char *type, const char *value,
    const char *pr1_name, const char *pr1_value)
{
	xmlNode *child;

	child = xmlNewDocNode(doc, ns, BAD_CAST type, BAD_CAST value);
	if (!child)
		goto err_alloc;
	if (!xmlNewProp(child, BAD_CAST pr1_name, BAD_CAST pr1_value))
		goto err_alloc;
	xmlAddChild(parent, child);
	return child;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static void mor_free(struct v__ManagedObjectReference *p)
{
	free(p->type);
	free(p->__item);
	free(p);
}

static struct v__ManagedObjectReference *mor_new(const char *type,
    const xmlChar *val)
{
	struct v__ManagedObjectReference *p;

	p = malloc(sizeof(struct v__ManagedObjectReference));
	if (!p)
		goto err_struc;
	p->type = strdup(type);
	if (!p->type)
		goto err_type;
	p->__item = strdup((const char *)val);
	if (!p->__item)
		goto err_item;
	return p;

 err_item:
	free(p->type);
 err_type:
	free(p);
 err_struc:
	return NULL;
}

/*
 * The propval can contain several objects, we return one by type.
 */
static struct v__ManagedObjectReference *val2mor(xmlNode *propval,
    const char *type_match)
{
	xmlNode *etmor;
	xmlNode *etval;
	xmlChar *type;
	struct v__ManagedObjectReference *ret;

	for (etmor = propval->children; etmor; etmor = etmor->next) {
		if (etmor->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp((char *)etmor->name, "ManagedObjectReference") != 0)
			continue;
		type = xmlGetProp(etmor, (xmlChar *)"type");
		if (!type)
			continue;
		if (strcmp((char *)type, type_match) != 0) {
			xmlFree(type);
			continue;
		}

		etval = etmor->children;
		if (!etval || etval->type != XML_TEXT_NODE || !etval->content) {
			fprintf(stderr, TAG ": empty MOR of `%s' in `%s'\n",
			    type_match, propval->name);
			exit(EXIT_FAILURE);
		}

		ret = mor_new((const char *)type, etval->content);
		xmlFree(type);
		break;
	}

	if (!etmor) {
		fprintf(stderr, TAG ": no MOR of `%s' in `%s'\n",
		    type_match, propval->name);
		exit(EXIT_FAILURE);
	}

	return ret;
}

static struct v__ManagedObjectReference *text2mor(const char *type,
    xmlNode *et)
{
	xmlNode *retval;
	struct v__ManagedObjectReference *p;

	retval = et->children;
	if (!retval || retval->type!=XML_TEXT_NODE || !retval->content)
		goto err_notext_retval;

	p = mor_new(type, retval->content);
	if (!p)
		goto err_malloc;
	return p;

 err_notext_retval:
	fprintf(stderr, TAG ": No text in node `%s'\n", et->name);
	exit(EXIT_FAILURE);

 err_malloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
	// return NULL;
}

static void x_genxmlhdr(xmlDoc **pdoc, xmlNs **pe, xmlNs **pv, xmlNode **proot)
{
	xmlDoc *reqdoc;
	xmlNsPtr ns_env, ns_enc, ns_xsi, ns_xsd, ns_v;
	xmlNode *etroot;

	/*
	 * N.B. Unused namespaces xsi and xsd are required to be present.
	 */
	reqdoc = xmlNewDoc(BAD_CAST "1.0");
	if (!reqdoc)
		goto err_alloc;
	etroot = xmlNewDocNode(reqdoc, NULL, BAD_CAST "Envelope", NULL);
	if (!etroot)
		goto err_alloc;
	ns_env = xmlNewNs(etroot,
	    BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/",
	    BAD_CAST "SOAP-ENV");
	if (!ns_env)
		goto err_alloc;
	ns_enc = xmlNewNs(etroot,
	    BAD_CAST "http://schemas.xmlsoap.org/soap/encoding/",
	    BAD_CAST "SOAP-ENC");
	if (!ns_enc)
		goto err_alloc;
	ns_xsi = xmlNewNs(etroot,
	    BAD_CAST "http://www.w3.org/2001/XMLSchema-instance",
	    BAD_CAST "xsi");
	if (!ns_xsi)
		goto err_alloc;
	ns_xsd = xmlNewNs(etroot,
	    BAD_CAST "http://www.w3.org/2001/XMLSchema", BAD_CAST "xsd");
	if (!ns_xsd)
		goto err_alloc;
	ns_v = xmlNewNs(etroot, BAD_CAST "urn:vim25", BAD_CAST "v");
	if (!ns_v)
		goto err_alloc;
	xmlSetNs(etroot, ns_env);
	xmlDocSetRootElement(reqdoc, etroot);

	*pdoc = reqdoc;
	*pe = ns_env;
	*pv = ns_v;
	*proot = etroot;
	return;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static xmlDoc *v_runcurl(struct config *cfg, struct session *ses,
    const unsigned char *xmlbuf, int xmllen, const char *proc)
{
	CURL *curl = ses->curl;
	struct api_buf apib, apob;
	xmlDoc *respdoc;
	CURLcode rcc;

	memset(&apob, 0, sizeof(struct api_buf));
	apob.buf = (char *) xmlbuf;
	apob.alloc = xmllen;

	memset(&apib, 0, sizeof(struct api_buf));
	apib.buf = malloc(4000);
	if (!apib.buf)
		goto err_alloc;
	apib.alloc = 4000;

	/* if (verbose)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1); */
	curl_easy_setopt(curl, CURLOPT_URL, cfg->apiurl);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, ses->curlhdrs);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, api_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &apib);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, apob.alloc);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, api_rcb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &apob);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, TAG ": curl failed POST url `%s', proc %s\n",
		     cfg->apiurl, proc);
		exit(EXIT_FAILURE);
	}

	respdoc = xmlReadMemory(apib.buf, apib.used, "rhev-api.xml", NULL, 0);
	if (respdoc == NULL) {
		fprintf(stderr, TAG ": XML parse error, proc %s\n", proc);
		exit(EXIT_FAILURE);
	}

	free(apib.buf);
	return respdoc;

 err_alloc:
	fprintf(stderr, TAG ": No core (%s)\n", proc);
	exit(EXIT_FAILURE);
}

/*
 * The general VMware call.
 * Takes a list of arguments and returns the reply node (document implied).
 * This means that the ret->doc has to be freed, not just ret.
 */
static xmlNode *v_rpc(struct config *cfg, struct session *ses,
    const char *proc, int argc, struct v_rpc_arg argv[])
{
	char *reply;
	xmlChar *buf;
	int len;
	xmlDoc *reqdoc;
	xmlNsPtr ns_env, ns_v;
	xmlNode *etroot, *etbody, *etproc;
	xmlDoc *respdoc;
	xmlNode *etreply;
	xmlNode *et;
	int i;

	if (asprintf(&reply, "%sResponse", proc) < 0)
		goto err_alloc;

	x_genxmlhdr(&reqdoc, &ns_env, &ns_v, &etroot);

	etbody = x_addchild(reqdoc, ns_env, etroot, "Body", NULL);
	etproc = x_addchild(reqdoc, ns_v, etbody, proc, NULL);
	if (argc) {
		/*
		 * The value of "_this" is an unpacked MOR string, and "type"
		 * is the type of the object that MOR represents. gSOAP posts
		 * also xsi:type="ManagedObjectReference", but VMware eats
		 * the argument without, so we don't.
		 */
		x_addchild_1prop(reqdoc, ns_v, etproc, "_this", argv[0].value,
		    "type", argv[0].type);
	}
	for (i = 1; i < argc; i++)
		x_addchild(reqdoc, ns_v, etproc, argv[i].type, argv[i].value);

	xmlDocDumpFormatMemoryEnc(reqdoc, &buf, &len, "UTF-8", 1);

	respdoc = v_runcurl(cfg, ses, buf, len, proc);

	et = xmlDocGetRootElement(respdoc);
	if (strcmp((const char *)et->name, "Envelope") != 0) {
		fprintf(stderr, TAG ": API root is `%s', proc %s\n",
		    et->name, proc);
		exit(EXIT_FAILURE);
	}

	et = x_getchild(et, "Body");
	etreply = x_getchild(et, reply);

	/* Not entirely clear what this is for. */
	// xmlCleanupParser();

	// xmlFreeNs(ns_v) -- does freeing Doc free namespaces? XXX

	if (respdoc != etreply->doc) {
		fprintf(stderr, TAG ": IE, inconsistent XML tree (%s)\n", proc);
		exit(EXIT_FAILURE);
	}
	// xmlFreeDoc(respdoc);

	xmlFreeDoc(reqdoc);
	xmlFree(buf);
	free(reply);
	return etreply;

 err_alloc:
	fprintf(stderr, TAG ": No core (%s)\n", proc);
	exit(EXIT_FAILURE);
}

static struct v__ServiceContent *poke_svcroot(struct config *cfg,
   struct session *ses)
{
	struct v_rpc_arg argv[1];
	struct v__ServiceContent *sc;
	xmlNode *et;

	sc = sc_alloc();
	if (!sc)
		goto err_alloc;

	argv[0].type = "ServiceInstance";
	argv[0].value = "ServiceInstance";
	et = v_rpc(cfg, ses, "RetrieveServiceContent", 1, argv);

	sc->scnode = x_getchild(et, "returnval");
	sc->scdoc = et->doc;

	return sc;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static void poke_Login(struct config *cfg, struct session *ses,
    struct v__ServiceContent *sc)
{
	xmlNode *thisnode;
	xmlChar *thisval;
	struct v_rpc_arg argv[3];
	xmlNode *et;

	thisnode = x_getchild(sc->scnode, "sessionManager");
	if (!thisnode)
		goto err_notext_sesmgr;
	thisval = xmlNodeGetContent(thisnode);
	if (!thisval)
		goto err_notext_sesmgr;

	argv[0].type = "SessionManager";
	argv[0].value = (char *) thisval;
	argv[1].type = "userName";
	argv[1].value = cfg->apiuser;
	argv[2].type = "password";
	argv[2].value = cfg->apipass;
	et = v_rpc(cfg, ses, "Login", 3, argv);

	et = x_getchild(et, "returnval");

	xmlFreeDoc(et->doc);
	xmlFree(thisval);
	return;

 err_notext_sesmgr:
	fprintf(stderr, TAG ": No text for SessionManager\n");
	exit(EXIT_FAILURE);
}

static void poke_Logout(struct config *cfg, struct session *ses,
    struct v__ServiceContent *sc)
{
	xmlNode *thisnode;
	xmlChar *thisval;
	struct v_rpc_arg argv[1];
	xmlNode *et;

	thisnode = x_getchild(sc->scnode, "sessionManager");
	if (!thisnode)
		goto err_notext_sesmgr;
	thisval = xmlNodeGetContent(thisnode);
	if (!thisval)
		goto err_notext_sesmgr;

	argv[0].type = "SessionManager";
	argv[0].value = (char *) thisval;
	et = v_rpc(cfg, ses, "Logout", 1, argv);

	/* Nothing left to verify: LogoutResponse is usually empty. */

	xmlFreeDoc(et->doc);
	xmlFree(thisval);
	return;

 err_notext_sesmgr:
	fprintf(stderr, TAG ": No text for SessionManager\n");
	exit(EXIT_FAILURE);
}

/*
 * Retrieve a property specified by "path" (more like a name actually).
 */
static struct v_prop *v_retr_prop(struct config *cfg,
    struct session *ses, struct v__ServiceContent *sc,
    struct v__ManagedObjectReference *obj, const char *path)
{
	xmlNode *thisnode;
	xmlChar *thisval;
	const char *proc, *reply;
	xmlChar *buf;
	int len;
	struct v_prop *ret;
	xmlDoc *reqdoc;
	xmlNsPtr ns_env, ns_v;
	xmlNode *etroot, *etbody, *etproc;
	xmlNode *etprop, *etobj, *etspec;
	xmlDoc *respdoc;
	xmlNode *etpset;
	xmlNode *et;

	proc = "RetrieveProperties";
	reply = "RetrievePropertiesResponse";

	thisnode = x_getchild(sc->scnode, "propertyCollector");
	if (!thisnode)
		goto err_notext_sesmgr;
	thisval = xmlNodeGetContent(thisnode);
	if (!thisval)
		goto err_notext_sesmgr;

	x_genxmlhdr(&reqdoc, &ns_env, &ns_v, &etroot);

	etbody = x_addchild(reqdoc, ns_env, etroot, "Body", NULL);
	etproc = x_addchild(reqdoc, ns_v, etbody, proc, NULL);

	x_addchild_1prop(reqdoc, ns_v, etproc, "_this", (char *)thisval,
		    "type", "PropertyCollector");
	etspec = x_addchild(reqdoc, ns_v, etproc, "specSet", NULL);

	etprop = x_addchild(reqdoc, ns_v, etspec, "propSet", NULL);
	x_addchild(reqdoc, ns_v, etprop, "type", obj->type);
	x_addchild(reqdoc, ns_v, etprop, "all", "false");
	x_addchild(reqdoc, ns_v, etprop, "pathSet", path);

	etobj = x_addchild(reqdoc, ns_v, etspec, "objectSet", NULL);
	x_addchild_1prop(reqdoc, ns_v, etobj, "obj", obj->__item,
	    "type", obj->type);
	x_addchild(reqdoc, ns_v, etobj, "skip", "false");

	xmlDocDumpFormatMemoryEnc(reqdoc, &buf, &len, "UTF-8", 1);

	respdoc = v_runcurl(cfg, ses, buf, len, proc);

	etroot = xmlDocGetRootElement(respdoc);
	if (strcmp((const char *)etroot->name, "Envelope") != 0) {
		fprintf(stderr, TAG ": API root is `%s'\n", etroot->name);
		exit(EXIT_FAILURE);
	}
	et = x_getchild(etroot, "Body");
	et = x_getchild(et, reply);
	et = x_getchild(et, "returnval");
	etpset = x_getchild(et, "propSet");

	et = x_getchild(etpset, "name");
	et = et->children;
	if (!et || et->type!=XML_TEXT_NODE || !et->content)
		goto err_no_name;

	if (strcmp((char *)et->content, path) != 0) {
		fprintf(stderr,
		    TAG ": %s((%s)%s) got %s for %s\n",
		    proc, obj->type, obj->__item, et->content, path);
		exit(EXIT_FAILURE);
	}

	et = x_getchild(etpset, "val");
	ret = prop_new(et);

	xmlFreeDoc(respdoc);
	xmlFreeDoc(reqdoc);
	xmlFree(buf);
	xmlFree(thisval);
	return ret;

 err_no_name:
	fprintf(stderr, TAG ": No \"name\" tag in returned property\n");
	exit(EXIT_FAILURE);

 err_notext_sesmgr:
	fprintf(stderr, TAG ": No text for propertyCollector\n");
	exit(EXIT_FAILURE);
}

static struct v__ManagedObjectReference *v_find_by_name(struct config *cfg,
    struct session *ses, struct v__ServiceContent *sc,
    char *hostname, int do_vm)
{
	xmlNode *thisnode;
	xmlChar *thisval;
	struct v_rpc_arg argv[3];
	xmlNode *retval;
	struct v__ManagedObjectReference *ret;
	xmlNode *et;

	thisnode = x_getchild(sc->scnode, "searchIndex");
	if (!thisnode)
		goto err_notext_sesmgr;
	thisval = xmlNodeGetContent(thisnode);
	if (!thisval)
		goto err_notext_sesmgr;

	argv[0].type = "SearchIndex";
	argv[0].value = (char *) thisval;
	argv[1].type = "dnsName";
	argv[1].value = hostname;
	argv[2].type = "vmSearch";
	argv[2].value = do_vm?"true":"false";
	et = v_rpc(cfg, ses, "FindByDnsName", 3, argv);

	et = x_getchild(et, "returnval");
	retval = et->children;
	if (!retval || retval->type!=XML_TEXT_NODE || !retval->content)
		goto err_notext_retval;

	ret = mor_new("HostSystem", retval->content);

	xmlFreeDoc(et->doc);
	xmlFree(thisval);
	return ret;

 err_notext_retval:
	fprintf(stderr, TAG ": No text for FindByDnsNameResponse\n");
	exit(EXIT_FAILURE);

 err_notext_sesmgr:
	fprintf(stderr, TAG ": No text for SearchIndex\n");
	exit(EXIT_FAILURE);
}

/*
 * In ImportVM: "This operation only works if the folder's childType includes
 * VirtualMachine."
 */
static struct v__ManagedObjectReference *v_find_vm_folder(struct config *cfg,
    struct session *ses, struct v__ServiceContent *sc,
    struct v__ManagedObjectReference *h)
{
#if 0 /* sample version -- needs at least 1 VM to exist. */
	struct v_prop *prop;
	struct v__ManagedObjectReference *vm;
	struct v__ManagedObjectReference *ret;

	prop = v_retr_prop(cfg, ses, sc, h, "vm");
	vm = val2mor(prop->value, "VirtualMachine");
	prop_free(prop);

	prop = v_retr_prop(cfg, ses, sc, vm, "parent");
	/* XXX Verify that prop->value has type="Folder" */
	// type = xmlGetProp(etmor, BAD_CAST "type");
	ret = text2mor("Folder", prop->value);
	prop_free(prop);

	mor_free(vm);
	return ret;
#endif
#if 1 /* from-the-top version -- needs no VMs, but returns "root" VM folder */
	struct v_prop *prop;
	struct v__ManagedObjectReference *dc;
	xmlNode *et;
	struct v__ManagedObjectReference *root;
	struct v__ManagedObjectReference *ret;

	et = x_getchild(sc->scnode, "rootFolder");
	root = text2mor("Folder", et);

	prop = v_retr_prop(cfg, ses, sc, root, "childEntity");
	dc = val2mor(prop->value, "Datacenter");
	prop_free(prop);

	prop = v_retr_prop(cfg, ses, sc, dc, "vmFolder");
	ret = text2mor("Folder", prop->value);
	prop_free(prop);

	mor_free(root);
	mor_free(dc);
	return ret;
#endif
}

static struct v__OvfCreateImportSpecResult *v_create_import_spec(
    struct config *cfg, struct session *ses, struct v__ServiceContent *sc,
    struct v__ManagedObjectReference *host, char *ovfstr,
    struct v__ManagedObjectReference *rp,	/* ResourcePool */
    struct v__ManagedObjectReference *ds,	/* Datastore */
    struct v__ManagedObjectReference *net,	/* Network */
    char *net_name)
{
	xmlNode *thisnode;
	xmlChar *thisval;
	const char *proc, *reply;
	xmlChar *buf;
	int len;
	struct v__OvfCreateImportSpecResult *ret;
	xmlDoc *reqdoc;
	xmlNsPtr ns_env, ns_v;
	xmlNode *etroot, *etbody, *etproc, *etcisp, *etnetmap;
	xmlDoc *respdoc;
	xmlNode *et;

	proc = "CreateImportSpec";
	reply = "CreateImportSpecResponse";

	thisnode = x_getchild(sc->scnode, "ovfManager");
	if (!thisnode)
		goto err_notext_sesmgr;
	thisval = xmlNodeGetContent(thisnode);
	if (!thisval)
		goto err_notext_sesmgr;

	x_genxmlhdr(&reqdoc, &ns_env, &ns_v, &etroot);

	etbody = x_addchild(reqdoc, ns_env, etroot, "Body", NULL);
	etproc = x_addchild(reqdoc, ns_v, etbody, proc, NULL);

	x_addchild_1prop(reqdoc, ns_v, etproc, "_this", (char *)thisval,
		    "type", "OvfManager");

	/* Argument 1: ovfDescriptor */
	x_addchild(reqdoc, ns_v, etproc, "ovfDescriptor", ovfstr);

	/* Argument 2: resourcePool */
	x_addchild_1prop(reqdoc, ns_v, etproc, "resourcePool", rp->__item,
	    "type", rp->type);

	/* Argument 3: datastore */
	x_addchild_1prop(reqdoc, ns_v, etproc, "datastore", ds->__item,
	    "type", ds->type);

	/* Argument 4: cisp. Bad news, it's struct... with a list of structs. */
	etcisp = x_addchild(reqdoc, ns_v, etproc, "cisp", NULL);

	/* cisp.locale */
	x_addchild(reqdoc, ns_v, etcisp, "locale", "US");

	/* cisp.deploymentOption -- empty for now */
	x_addchild(reqdoc, ns_v, etcisp, "deploymentOption", "");

	/* cisp.entityName */
	x_addchild(reqdoc, ns_v, etcisp, "entityName", cfg->push_name);

	/* cisp.hostSystem -- optional, but set it for now. */
	x_addchild_1prop(reqdoc, ns_v, etcisp, "hostSystem", host->__item,
	    "type", host->type);

	/* cisp.networkMapping. Worse news, another level down. */
	etnetmap = x_addchild(reqdoc, ns_v, etcisp, "networkMapping", NULL);
	x_addchild(reqdoc, ns_v, etnetmap, "name", net_name);
	x_addchild_1prop(reqdoc, ns_v, etnetmap, "network", net->__item,
	     "type", net->type);

	xmlDocDumpFormatMemoryEnc(reqdoc, &buf, &len, "UTF-8", 1);

	respdoc = v_runcurl(cfg, ses, buf, len, proc);

	etroot = xmlDocGetRootElement(respdoc);
	if (strcmp((const char *)etroot->name, "Envelope") != 0) {
		fprintf(stderr, TAG ": API root is `%s'\n", etroot->name);
		exit(EXIT_FAILURE);
	}

	ret = malloc(sizeof(struct v__OvfCreateImportSpecResult));
	if (!ret)
		goto err_alloc;
	memset(ret, 0, sizeof(struct v__OvfCreateImportSpecResult));

	et = x_getchild(etroot, "Body");
	et = x_getchild(et, reply);
	et = x_getchild(et, "returnval");
	/*
	 * Discarding <fileItem> here from the same level as the spec.
	 * In theory, we need these because they carry a relation between
	 * the requested filenames of VMDKs and the deviceId, the latter
	 * being referenced in lease->info. Only by saving <fileItem> we
	 * can find which file to upload. Fortunately, we only have one VMDK.
	 */
	ret->node = x_getchild(et, "importSpec");
	ret->doc = respdoc;

	xmlFreeDoc(reqdoc);
	xmlFree(buf);
	xmlFree(thisval);
	return ret;

 err_notext_sesmgr:
	fprintf(stderr, TAG ": No text for OvfManager\n");
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static struct v_lease *v_import_vapp(struct config *cfg, struct session *ses,
    struct v__ServiceContent *sc,
    struct v__ManagedObjectReference *rp,	/* ResourcePool */
    struct v__OvfCreateImportSpecResult *sr,
    struct v__ManagedObjectReference *vmf,
    struct v__ManagedObjectReference *host)
{
	const char *proc, *reply;
	xmlChar *buf;
	int len;
	struct v_lease *ret;
	xmlChar *rettype, *retval;
	xmlDoc *reqdoc;
	xmlNsPtr ns_env, ns_v;
	xmlNode *etroot, *etbody, *etproc, *etspec;
	xmlDoc *respdoc;
	xmlNode *et;

	ret = malloc(sizeof(struct v_lease));
	if (!ret)
		goto err_alloc;
	memset(ret, 0, sizeof(struct v_lease));

	proc = "ImportVApp";
	reply = "ImportVAppResponse";

	x_genxmlhdr(&reqdoc, &ns_env, &ns_v, &etroot);

	etbody = x_addchild(reqdoc, ns_env, etroot, "Body", NULL);
	etproc = x_addchild(reqdoc, ns_v, etbody, proc, NULL);

	x_addchild_1prop(reqdoc, ns_v, etproc, "_this", rp->__item,
		    "type", rp->type);

	/* Argument 1: (ImportSpec) spec */
	/*
	 * This still does not do what we want: the copied namespace
	 * is retained (e.g. etspec will have an xmlns:xsi attribute).
	 * But it works, so whatever.
	 */
	etspec = xmlDocCopyNode(sr->node, reqdoc, 1);
	if (!etspec)
		goto err_alloc;
	xmlNodeSetName(etspec, BAD_CAST "spec");
	xmlAddChild(etproc, etspec);

	/* Argument 2: (MOR) folder */
	x_addchild_1prop(reqdoc, ns_v, etproc, "folder", vmf->__item,
	    "type", vmf->type);

	/* Argument 3: (MOR) host */
	x_addchild_1prop(reqdoc, ns_v, etproc, "host", host->__item,
	    "type", host->type);

	xmlDocDumpFormatMemoryEnc(reqdoc, &buf, &len, "UTF-8", 1);

	respdoc = v_runcurl(cfg, ses, buf, len, proc);

	etroot = xmlDocGetRootElement(respdoc);
	if (strcmp((const char *)etroot->name, "Envelope") != 0) {
		fprintf(stderr, TAG ": API root is `%s'\n", etroot->name);
		exit(EXIT_FAILURE);
	}
	et = x_getchild(etroot, "Body");
	et = x_getchild(et, reply);
	et = x_getchild(et, "returnval");

	/*
	 * The doc promise a MOR but actually it's a string attribute.
	 * So, custom-extract the type and construct a MOR.
	 */
	rettype = xmlGetProp(et, BAD_CAST "type");
	if (!rettype)
		goto err_norettype;
	if (strcmp((char *)rettype, "HttpNfcLease") != 0) {
		fprintf(stderr, TAG ": bad type in returnval"
		    ": expected `HttpNfcLease' got `%s'\n", rettype);
		xmlFree(rettype);
		exit(EXIT_FAILURE);
	}

	retval = xmlNodeGetContent(et);
	if (!retval)
		goto err_notext_retval;
	ret->mor = mor_new((const char *)rettype, retval);

	xmlFree(rettype);
	xmlFree(retval);
	xmlFreeDoc(respdoc);
	xmlFreeDoc(reqdoc);
	xmlFree(buf);
	return ret;

 err_notext_retval:
	fprintf(stderr, TAG ": No text in returnval (%s)\n", proc);
	exit(EXIT_FAILURE);

 err_norettype:
	fprintf(stderr, TAG ": No type in returnval (%s)\n", proc);
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

/* This is basename(), but we handroll it to make sure, due to BSD. */
static const char *image_name(const char *path)
{
	const char *name;

	if (!(name = strrchr(path, '/')) || name[1]==0)
		name = path;
	else
		name++;
	return name;
}

/*
 * The vol_size is supposed to be the uncompressed size, I think.
 */
static char *genovf(const char *base_name, off_t vol_size,
    char *vm_name, char *net_name)
{
	const char fileid1[] = "file1";
	off_t vmdk_size;
	char buf100[100];
	xmlTextWriterPtr writer;
	xmlBufferPtr buf;
	int instid, ide_id;
	char *ret;
	int rc;

	ide_id = instid = 0;

	/*
	 * We need to create OVF before the image is compressed (on the fly
	 * as it's being uploaded). And one of the fields in the image appears
	 * to be the size of the image being transferred. For now we simply
	 * use the uncompressed size.
	 */
	vmdk_size = vol_size;

	buf = xmlBufferCreateSize(15000);
	if (!buf)
		goto err_alloc;

	writer = xmlNewTextWriterMemory(buf, 0);
	if (!writer)
		goto err_alloc;
	xmlTextWriterSetIndent(writer, 1);

	rc = xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL);
	if (rc < 0) {
		fprintf(stderr, TAG ": Error in xmlTextWriterStartDocument\n");
		exit(EXIT_FAILURE);
	}

	/* N.B. "Envelope", not "ovf:Envelope" like in RHEV */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Envelope");
	if (rc < 0) goto err_xml;
	// rc = xmlTextWriterWriteAttribute(writer,
	//     BAD_CAST "ovf:version", BAD_CAST "0.9");
	// if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns",
	    BAD_CAST "http://schemas.dmtf.org/ovf/envelope/1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:cim",
	    BAD_CAST "http://schemas.dmtf.org/ovf/envelope/1/common");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:ovf",
	    BAD_CAST "http://schemas.dmtf.org/ovf/envelope/1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:rasd",
	    BAD_CAST "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "xmlns:vmw",
	    BAD_CAST "http://www.vmware.com/schema/ovf");
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
	snprintf(buf100, 100, "%s", base_name);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:href", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST fileid1);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu", (long long) vmdk_size);
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:size", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <File> */
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <References> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "DiskSection");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "Virtual disk information");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Disk");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu",
	    (long long)((vol_size + (1024*1024*1024) - 1) / (1024*1024*1024)));
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:capacity", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	/* RHEV-M says "MegaBytes" */
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:capacityAllocationUnits", BAD_CAST "byte * 2^30");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:diskId", BAD_CAST "vmdisk1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:fileRef", BAD_CAST fileid1);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:format", BAD_CAST "http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%llu", (long long) vol_size / 4 * 3); /* guess */
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:populatedSize", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Disk> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <DiskSection> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "NetworkSection");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "The list of logical networks");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Network");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:name", BAD_CAST net_name);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "The %s network", net_name);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Description", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Network> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <NetworkSection> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "VirtualSystem");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST vm_name);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info", BAD_CAST "A virtual machine");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Name", BAD_CAST vm_name);
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer,
	    BAD_CAST "OperatingSystemSection");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:id", BAD_CAST "101");	/* XXX What is this? */
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "vmw:osType", BAD_CAST "otherLinux64Guest");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info",
	    BAD_CAST "The kind of installed guest operating system");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Description", BAD_CAST "Other Linux (64-bit)");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <OperatingSystemSection> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer,
	    BAD_CAST "VirtualHardwareSection");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "Info",
	    BAD_CAST "Virtual hardware requirements");
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "System");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "vssd:ElementName", BAD_CAST "Virtual Hardware Family");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "vssd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "vssd:VirtualSystemIdentifier", BAD_CAST vm_name);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "vssd:VirtualSystemType", BAD_CAST "vmx-07");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <System> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AllocationUnits", BAD_CAST "hertz * 10^6");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST "Number of Virtual CPUs");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "1 virtual CPU(s)");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "3");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:VirtualQuantity", BAD_CAST "1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AllocationUnits", BAD_CAST "byte * 2^20");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST "Memory Size");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "384MB of memory");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "4");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:VirtualQuantity", BAD_CAST "384");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Address", BAD_CAST "0");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST "IDE Controller");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "IDE 0");
	if (rc < 0) goto err_xml;
	ide_id = instid;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "5");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	/*
	 * Ignoring floppies, hope their BIOS boots without.
	 *      <Item ovf:required="false">
	 *        <rasd:AddressOnParent>0</rasd:AddressOnParent>
	 *        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
	 *        <rasd:Description>Floppy Drive</rasd:Description>
	 *        <rasd:ElementName>Floppy drive 1</rasd:ElementName>
	 *        <rasd:InstanceID>5</rasd:InstanceID>
	 *        <rasd:ResourceType>14</rasd:ResourceType>
	 *      </Item>
	 */

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AddressOnParent", BAD_CAST "0");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "Hard disk 1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:HostResource", BAD_CAST "ovf:/disk/vmdisk1");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", ide_id);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Parent", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "17");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	/*
	 * In VMware CD is hooked to its own IDE controller, so this may
	 * fail to work properly.
	 * We use one Parent and different AddressOnParent.
	 */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteAttribute(writer,
	    BAD_CAST "ovf:required", BAD_CAST "false");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AddressOnParent", BAD_CAST "1");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AutomaticAllocation", BAD_CAST "false");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "CD/DVD Drive 1");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", ide_id);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Parent", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "15");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "Item");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AddressOnParent", BAD_CAST "7");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:AutomaticAllocation", BAD_CAST "true");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Connection", BAD_CAST net_name);
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "E1000 ethernet adapter on \"%s\"", net_name);
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:Description", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ElementName", BAD_CAST "Network adapter 1");
	if (rc < 0) goto err_xml;
	snprintf(buf100, 100, "%d", instid);    instid++;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:InstanceID", BAD_CAST buf100);
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceSubType", BAD_CAST "E1000");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterWriteElement(writer,
	    BAD_CAST "rasd:ResourceType", BAD_CAST "10");
	if (rc < 0) goto err_xml;
	rc = xmlTextWriterEndElement(writer);	/* close <Item> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <VirtualHardwareSection> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndElement(writer);	/* close <VirtualSystem> */
	if (rc < 0) goto err_xml;

	rc = xmlTextWriterEndDocument(writer);
	if (rc < 0) {
		fprintf(stderr, "ERROR Error in xmlTextWriterEndDocument\n");
		exit(EXIT_FAILURE);
	}

	xmlFreeTextWriter(writer);

	ret = malloc(buf->use+1);
	if (!ret)
		goto err_alloc;
	memcpy(ret, buf->content, buf->use);
	ret[buf->use] = 0;
	xmlBufferFree(buf);
	return ret;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);

 err_xml:
	fprintf(stderr, TAG ": Failed to form XML\n");
	exit(EXIT_FAILURE);
}

/*
 * Update lease with the fetched HttpNcfLeaseInfo.
 */
static int v_lease_parse_info(struct v_lease *lease, struct v_prop *prop)
{
	xmlNode *et;

	et = x_getchild(prop->value, "deviceUrl");
	et = x_getchild(et, "url");
	lease->url = x_gettext(et);
	return 0;
}

static int v_lease_state(struct config *cfg, struct session *ses,
    struct v__ServiceContent *sc, struct v_lease *lease)
{
	struct v_prop *prop;
	char *status;
	int ret;

	prop = v_retr_prop(cfg, ses, sc, lease->mor, "state");
	status = x_gettext(prop->value);

	if (strcmp(status, "initializing") == 0)
		ret = v__HttpNfcLeaseState__initializing;
	else if (strcmp(status, "ready") == 0)
		ret = v__HttpNfcLeaseState__ready;
	else if (strcmp(status, "done") == 0)
		ret = v__HttpNfcLeaseState__done;
	else if (strcmp(status, "error") == 0)
		ret = v__HttpNfcLeaseState__error;
	else
		ret = -1;

	free(status);
	prop_free(prop);
	return ret;
}

static void v_lease_progress(struct config *cfg, struct session *ses,
    struct v__ManagedObjectReference *ls, int pcs)
{
	struct v_rpc_arg argv[2];
	char bufpc[4];
	xmlNode *et;

	snprintf(bufpc, sizeof(bufpc), "%d", pcs);

	argv[0].type = ls->type;
	argv[0].value = ls->__item;
	argv[1].type = "percent";
	argv[1].value = bufpc;
	et = v_rpc(cfg, ses, "HttpNfcLeaseProgress", 2, argv);

	/* Response is empty. */

	xmlFreeDoc(et->doc);
	return;
}

static void v_lease_complete(struct config *cfg, struct session *ses,
    struct v__ManagedObjectReference *ls)
{
	struct v_rpc_arg argv[1];
	xmlNode *et;

	argv[0].type = ls->type;
	argv[0].value = ls->__item;
	et = v_rpc(cfg, ses, "HttpNfcLeaseComplete", 1, argv);

	/* Response is empty. */

	xmlFreeDoc(et->doc);
	return;
}

static int v_upload(struct config *cfg, struct session *ses,
    int use_put, const char *url, int tfd)
{
	FILE *fp;
	CURL *curl;		/* new handle */
	struct curl_slist *curlhdrs = NULL;
	CURLcode rcc;

	/*
	 * Not possible to determine the size of pipe.
	 */
#if 0 /* fsize */
	struct stat statb;
	curl_off_t fsize;

	if (fstat(tfd, &statb) < 0) {
		fprintf(stderr, TAG ": failed to stat temp: %s\n",
		    strerror(errno));
		exit(EXIT_FAILURE);
	}
	fsize = statb.st_size;
#endif

	fp = fdopen(tfd, "r");
	if (!fp) {
		fprintf(stderr, TAG ": fdopen of pipe error: %s\n",
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Use new session - in order to update the progress indicator.
	 * Session cookies should not be necessary, the URL is the key.
	 */
	curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, fread);
	curl_easy_setopt(curl, CURLOPT_READDATA, fp);
	if (use_put) {
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
#if 0 /* fsize */
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, fsize);
#endif
	} else {
		curl_easy_setopt(curl, CURLOPT_POST, 1);
#if 0 /* fsize */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, fsize);
#endif
	}

#if 1 /* fsize */
	/*
	 * We know that VMware is not HTTP 1.0, so just set chunked.
	 * Also, libcurl takes care of properly chunking for us.
	 */
	if (!curlx_add_header(&curlhdrs,
	    "Transfer-Encoding: chunked"))
		goto err_alloc;
#endif
	/*
	 * This is especially important if !use_put, because curl sets
	 * "Content-Type: application/x-www-form-urlencoded" otherwise.
	 * (actually VMware ignores this, so, I mean, important in general).
	 */
	if (!curlx_add_header(&curlhdrs,
	    "Content-Type: application/octet-stream"))
		goto err_alloc;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curlhdrs);

	rcc = curl_easy_perform(curl);
	if (rcc != CURLE_OK) {
		fprintf(stderr, TAG ": curl failed upload url `%s'\n", url);
		exit(EXIT_FAILURE);
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(curlhdrs);
	fclose(fp);
	return 0;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static void run_upload(struct config *cfg, struct session *ses, bool use_put,
    const char *url, int tfd, struct v__ManagedObjectReference *ls)
{
	pid_t uploader;
	int wstat;
	int fake_pct;
	time_t now, last;
	int interval;
	struct timespec tm;
	int rc;

	fflush(stdout);
	fflush(stderr);

	uploader = fork();
	if (uploader < 0) {
		fprintf(stderr, TAG ": fork error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (uploader == 0) {
		v_upload(cfg, ses, 0, url, tfd);
		exit(EXIT_SUCCESS);
	}

	fake_pct = 0;
	interval = 1;
	last = time(NULL);

	for (;;) {
		rc = waitpid(uploader, &wstat, WNOHANG);
		if (rc < 0) {
			fprintf(stderr,
			    TAG ": waitpid error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (rc != 0) {
			if (!WIFEXITED(wstat)) {
				fprintf(stderr,
				    TAG ": uploader is killed (status 0x%x)\n",
				    wstat);
				exit(EXIT_FAILURE);
			}
			if (WEXITSTATUS(wstat)) {
				/*
				 * Don't print anything here. An error code
				 * means an error message from the child, which
				 * is precious. Let it be captured in ami-id
				 * instead of our useless message.
				 */
				/* fprintf(stderr, "uploader exited with code %d\n",
				    WEXITSTATUS(wstat)); */
				exit(EXIT_FAILURE);
			}
			break;
		}

		tm.tv_sec = interval;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);
		/* XXX Use SIGCHLD */
		if (interval < 20)
			interval *= 2;

		now = time(NULL);
		if (now >= last + 150) {
			if (fake_pct < 98)
				fake_pct++;
			v_lease_progress(cfg, ses, ls, fake_pct);
			last = now;
		}
	}
}

static unsigned long divro(unsigned long num, unsigned long divisor)
{
	unsigned long ret;

	ret = num / divisor;
	if (ret * divisor != num)
		ret++;
	return ret;
}

static bool is_zero(const char *p, size_t len)
{
	while (len) {
		--len;
		if (*p++ != 0)
			return false;
	}
	return true;
}

static off_t file_size(const char *fname)
{
	struct stat statb;

	if (stat(fname, &statb) < 0) {
		fprintf(stderr, TAG ": failed to stat `%s': %s\n",
		    fname, strerror(errno));
		exit(EXIT_FAILURE);
	}
	/*
	 * This is a little nasty, but we need to know the file size.
	 * If we ever want to process a pipe or a socket, size has to
	 * be in argv somewhere.
	 */
	if (!S_ISREG(statb.st_mode)) {
		fprintf(stderr, TAG ": not a regular file `%s'\n", fname);
		exit(EXIT_FAILURE);
	}
	return statb.st_size;
}

/* See https://github.com/imcleod/VMDK-stream-converter */
static void convert(const char *fname, off_t vol_size, int vfd)
{
	void *sectb;
	int ifd;
	unsigned long infileSectors, infileCylinders;
	unsigned int grainSectors;
	unsigned long totalGrains, totalGrainTables;
	unsigned long grainDirectorySectors, grainDirectoryEntries;
	char *image_descriptor_pad;
	size_t image_descriptor_len;
	struct SparseExtentHeader sehb;
	struct GrainMarker *gm;
	struct MetaDataMarker gtmarker, gdmarker, eosmarker, footmarker;
	unsigned int *currentGrainTable, *grainDirectory;
	unsigned int cgx, gdx;
	unsigned long inputSectorPointer, outputSectorPointer;
	unsigned char *inChunk;
	unsigned char *obuf;
	size_t cbufsz;
	unsigned long chunklen;
	int i;
	ssize_t rrc, wrc;
	int rc;

	sectb = malloc(512);
	if (!sectb)
		goto err_alloc;

	ifd = open(fname, O_RDONLY);
	if (ifd == -1) {
		fprintf(stderr, TAG ": failed to open %s: %s\n",
		    fname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	infileSectors = (vol_size + 511) / 512;
	grainSectors = 128;	/* Why? Just because. Ask Ian. */
	totalGrains = divro(infileSectors, grainSectors);
	totalGrainTables = divro(totalGrains, 512);
	grainDirectorySectors = divro(totalGrainTables*4, 512);
	grainDirectoryEntries = grainDirectorySectors*128;
	printf("DEBUG: Number of entries (overhead value in header) in Grain Directory - (%ld)\n", (long)grainDirectoryEntries);

	infileCylinders = divro(infileSectors, (63*255));

	image_descriptor_len = 512;
	image_descriptor_pad = malloc(image_descriptor_len);
	if (!image_descriptor_pad)
		goto err_alloc;
	memset(image_descriptor_pad, 0, image_descriptor_len);

	snprintf(image_descriptor_pad, image_descriptor_len,
		"# Description file created by Image Warehouse\n"
		"version=1\n"
		"# Believe this is random\n"
		"CID=7e5b80a7 \n"
		"# Indicates no parent\n"
		"parentCID=ffffffff \n"
		"createType=\"streamOptimized\" \n"
		"\n"
		"# Extent description\n"
		"RDONLY #SECTORS# SPARSE \"call-me-stream.vmdk\"\n"
		"\n"
		"# The Disk Data Base \n"
		"#DDB\n"
		"\n"
		"ddb.adapterType = \"lsilogic\"\n"
		"# %lu / 63 / 255 rounded up\n"
		"ddb.geometry.cylinders = \"%lu\"\n"
		"ddb.geometry.heads = \"255\"\n"
		"ddb.geometry.sectors = \"63\"\n"
		"# Believe this is random\n"
		"ddb.longContentID = \"8f15b3d0009d9a3f456ff7b28d324d2a\"\n"
		"ddb.virtualHWVersion = \"7\"\n",
	    infileSectors, infileCylinders);

	memset(&sehb, 0, sizeof(sehb));
	sehb.magicNumber = SPARSE_MAGICNUMBER;
	sehb.version = 3;
	sehb.flags |= (3 << 16);
	sehb.capacity = infileSectors;
	sehb.grainSize = 128;
	sehb.descriptorOffset = sizeof(sehb)/512;
	sehb.descriptorSize = image_descriptor_len/512;
	sehb.numGTEsPerGT = 512;
	sehb.rgdOffset = 0;
	sehb.gdOffset = GD_AT_END;
	sehb.overHead = 128;	/* "128 is almost guaranteed to be enough" */
	sehb.uncleanShutdown = 0;
	sehb.singleEndLineChar = '\n';
	sehb.nonEndLineChar = ' ';
	sehb.doubleEndLineChar1 = '\r';
	sehb.doubleEndLineChar2 = '\n';
	sehb.compressAlgorithm = COMPRESSION_DEFLATE;

	wrc = write(vfd, &sehb, sizeof(sehb));
	if (wrc < 0)
		goto err_write;
	wrc = write(vfd, image_descriptor_pad, image_descriptor_len);
	if (wrc < 0)
		goto err_write;

	/*
	 * Don't just lseek here, we're going to pipe this out if we can.
	 */
	memset(sectb, 0, 512);
	for (i = (sizeof(sehb)+image_descriptor_len)/512; i < 128; i++) {
		wrc = write(vfd, sectb, 512);
		if (wrc < 0)
			goto err_write;
	}
	outputSectorPointer = 128;

	memset(&gtmarker, 0, sizeof(struct MetaDataMarker));
	gtmarker.val = 4;
	gtmarker.size = 0;
	gtmarker.type = MARKER_GT;

	memset(&gdmarker, 0, sizeof(struct MetaDataMarker));
	gdmarker.val = grainDirectorySectors;
	gdmarker.size = 0;
	gdmarker.type = MARKER_GD;

	memset(&eosmarker, 0, sizeof(struct MetaDataMarker));
	eosmarker.type = MARKER_EOS;

	memset(&footmarker, 0, sizeof(struct MetaDataMarker));
	footmarker.val = 1;
	footmarker.size = 0;
	footmarker.type = MARKER_FOOTER;

	cbufsz = compressBound(grainSectors * 512);
	obuf = malloc(sizeof(struct GrainMarker) + cbufsz + 512);
	if (!obuf)
		goto err_alloc;

	inputSectorPointer = 0;

	inChunk = malloc(grainSectors * 512);
	if (!inChunk)
		goto err_alloc;

	grainDirectory = malloc(grainDirectoryEntries * sizeof(unsigned int));
	if (!grainDirectory)
		goto err_alloc;
	memset(grainDirectory, 0, grainDirectoryEntries * sizeof(unsigned int));
	gdx = 0;
	currentGrainTable = malloc(512 * sizeof(unsigned int));
	if (!currentGrainTable)
		goto err_alloc;
	memset(currentGrainTable, 0, 512 * sizeof(unsigned int));
	cgx = 0;

	for (;;) {
		rrc = read(ifd, inChunk, grainSectors * 512);
		if (rrc < 0)
			goto err_read;
		if (rrc == 0)
			break;

		if (gdx >= grainDirectoryEntries) {
			/* Should never happen, see the calculations above. */
			fprintf(stderr, TAG ": GD overflow (%d)\n", gdx);
			exit(EXIT_FAILURE);
		}

		if (is_zero((char *)inChunk, rrc)) {
			currentGrainTable[cgx++] = 0;
		} else {
			currentGrainTable[cgx++] = outputSectorPointer;

			chunklen = cbufsz;
			rc = compress(obuf + sizeof(struct GrainMarker),
			    &chunklen, inChunk, rrc);
			if (rc != Z_OK || chunklen == 0)
				goto err_compress;

			gm = (struct GrainMarker *) obuf;
			gm->val = inputSectorPointer;
			gm->size = chunklen;

			chunklen += sizeof(struct GrainMarker);
			chunklen = (chunklen + 511) & ~511;

			wrc = write(vfd, obuf, chunklen);
			if (wrc < 0)
				goto err_write;
			if ((size_t)wrc < chunklen)
				goto err_short;
			outputSectorPointer += wrc / 512;
		}

		if (cgx == 512) {
			if (!is_zero((char *)currentGrainTable,
			    512 * sizeof(int))) {
				wrc = write(vfd, &gtmarker, 512);
				if (wrc < 0)
					goto err_write;
				wrc = write(vfd, &currentGrainTable,
				    512 * sizeof(int));
				if (wrc < 0)
					goto err_write;
				grainDirectory[gdx++] = outputSectorPointer + 1;
				outputSectorPointer += 5;
			} else {
				grainDirectory[gdx++] = 0;
			}
			memset(currentGrainTable, 0, 512 * sizeof(int));
			cgx = 0;
		}

		inputSectorPointer += rrc / 512;
	}
	if (cgx) {
		if (!is_zero((char *)currentGrainTable, cgx * sizeof(int))) {
			wrc = write(vfd, &gtmarker, 512);
			if (wrc < 0)
				goto err_write;
			wrc = write(vfd, &currentGrainTable,
			    512 * sizeof(unsigned int));
			if (wrc < 0)
				goto err_write;
			grainDirectory[gdx++] = outputSectorPointer + 1;
			outputSectorPointer += 5;
		}
	}

	wrc = write(vfd, &gdmarker, 512);
	if (wrc < 0)
		goto err_write;
	outputSectorPointer += 1;

	printf("Grain directory length (%d)\n", gdx);
	printf("Grain directory: ");
	for (gdx = 0; gdx < grainDirectoryEntries; gdx++) {
		if (gdx)
			printf(", ");
		printf("%d", grainDirectory[gdx]);
	}
	printf("]\n");

	wrc = write(vfd, grainDirectory, grainDirectoryEntries * sizeof(int));
	if (wrc < 0)
		goto err_write;
	// outputSectorPointer += grainDirectorySectors;

	wrc = write(vfd, &footmarker, sizeof(struct MetaDataMarker));
	if (wrc < 0)
		goto err_write;

	memset(&sehb, 0, sizeof(sehb));
	sehb.magicNumber = SPARSE_MAGICNUMBER;
	sehb.version = 3;
	sehb.flags |= (3 << 16);
	sehb.capacity = infileSectors;
	sehb.grainSize = 128;
	sehb.descriptorOffset = sizeof(sehb)/512;
	sehb.descriptorSize = image_descriptor_len/512;
	sehb.numGTEsPerGT = 512;
	sehb.rgdOffset = 0;
	sehb.gdOffset = outputSectorPointer;	/* saved above */
	sehb.overHead = 128;	/* "128 is almost guaranteed to be enough" */
	sehb.uncleanShutdown = 0;
	sehb.singleEndLineChar = '\n';
	sehb.nonEndLineChar = ' ';
	sehb.doubleEndLineChar1 = '\r';
	sehb.doubleEndLineChar2 = '\n';
	sehb.compressAlgorithm = COMPRESSION_DEFLATE;

	wrc = write(vfd, &sehb, sizeof(sehb));
	if (wrc < 0)
		goto err_write;

	/* Is this just me, or eosmarker is just a sector full of zeroes? */
	wrc = write(vfd, &eosmarker, sizeof(struct MetaDataMarker));
	if (wrc < 0)
		goto err_write;

	close(ifd);
	free(obuf);
	free(currentGrainTable);
	free(inChunk);
	free(grainDirectory);
	free(image_descriptor_pad);
	free(sectb);
	return;

 err_compress:
	fprintf(stderr, TAG ": zlib error\n");
	exit(EXIT_FAILURE);

 err_write:
	fprintf(stderr, TAG ": VMDK write error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);

 err_short:
	fprintf(stderr, TAG ": VMDK short write\n");
	exit(EXIT_FAILURE);

 err_read:
	fprintf(stderr, TAG ": image read error: %s\n", strerror(errno));
	exit(EXIT_FAILURE);

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);
}

static void push(struct config *cfg, off_t vol_size, int tfd)
{
	struct session ses;
	CURL *curl;
	struct v__ServiceContent *sc;
	const char *base_name;
	struct v_prop *prop;
	struct v__ManagedObjectReference *h;	/* HostSystem */
	struct v__ManagedObjectReference *net;	/* Network */
	char *net_name;
	char *ovf;
	struct v__ManagedObjectReference *host_parent;	/* ResourcePool */
	struct v__ManagedObjectReference *rp;	/* ResourcePool */
	struct v__ManagedObjectReference *ds;	/* Datastore */
	struct v__OvfCreateImportSpecResult *sr;
	struct v__ManagedObjectReference *vmf;	/* Folder */
	struct v_lease *lease;			/* HttpNfcLease */
	enum v__HttpNfcLeaseState state;
	int i;

	memset(&ses, 0, sizeof(struct session));
	ses.curl = curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, api_dbcb);

	/* It is essential to specify vim25, because we need ovfManager. */
	if (!curlx_add_header(&ses.curlhdrs, "SOAPAction: \"urn:vim25/4.1\""))
		goto err_alloc;
	if (!curlx_add_header(&ses.curlhdrs,
	    "Content-Type: text/xml; charset=utf-8"))
		goto err_alloc;

	// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	sc = poke_svcroot(cfg, &ses);
	poke_Login(cfg, &ses, sc);

	h = v_find_by_name(cfg, &ses, sc, cfg->push_host, 0);
	/* printf("host %s\n", h->__item); */

	prop = v_retr_prop(cfg, &ses, sc, h, "network");
	net = val2mor(prop->value, "Network");
	prop_free(prop);

	prop = v_retr_prop(cfg, &ses, sc, net, "name");
	net_name = x_gettext(prop->value);
	prop_free(prop);

	vmf = v_find_vm_folder(cfg, &ses, sc, h);

	base_name = image_name(cfg->push_img);
	ovf = genovf(base_name, vol_size, cfg->push_name, net_name);

	prop = v_retr_prop(cfg, &ses, sc, h, "parent");
	host_parent = text2mor("ComputeResource", prop->value);
	prop_free(prop);

	prop = v_retr_prop(cfg, &ses, sc, host_parent, "resourcePool");
	rp = text2mor("ResourcePool", prop->value);
	prop_free(prop);

	prop = v_retr_prop(cfg, &ses, sc, h, "datastore");
	/* prop at this point is a list of MORs for all datastores */
	ds = val2mor(prop->value, "Datastore");
	prop_free(prop);

	sr = v_create_import_spec(cfg, &ses, sc, h, ovf, rp, ds, net, net_name);

	lease = v_import_vapp(cfg, &ses, sc, rp, sr, vmf, h);

	i = 0;
	for (;;) {
		state = v_lease_state(cfg, &ses, sc, lease);
		if (state == v__HttpNfcLeaseState__ready)
			break;
		if (state == v__HttpNfcLeaseState__error)
			goto err_lease;
		if (++i >= 20) {
			fprintf(stderr, TAG ": Lease fails to get ready (%d)\n",
			    state);
			exit(EXIT_FAILURE);
		}
		sleep(3);
	}

	/*
	 * The info property is only valid when the lease is in the ready state.
	 */
	prop = v_retr_prop(cfg, &ses, sc, lease->mor, "info");
	v_lease_parse_info(lease, prop);
	prop_free(prop);

	/*
	 * The URL may have a wildcard '*' for a host. Process that. XXX
	 * The PUT method is used when <fileItem> has <create> field true. XXX
	 */
	run_upload(cfg, &ses, false, lease->url, tfd, lease->mor);

	v_lease_progress(cfg, &ses, lease->mor, 100);
	v_lease_complete(cfg, &ses, lease->mor);

	/*
	 * We think we may be switching to MOR eventually, so we use
	 * a selector for compatibility ("name").
	 */
	printf("IMAGE name:%s\n", cfg->push_name);

	poke_Logout(cfg, &ses, sc);

	mor_free(lease->mor);  free(lease->url);  free(lease);
	xmlFreeDoc(sr->doc);  free(sr);
	mor_free(ds);
	mor_free(rp);
	mor_free(host_parent);
	free(net_name);
	mor_free(vmf);
	mor_free(net);
	mor_free(h);
	sc_free(sc);
	curl_easy_cleanup(ses.curl);
	curl_slist_free_all(ses.curlhdrs);
	return;

 err_alloc:
	fprintf(stderr, TAG ": No core\n");
	exit(EXIT_FAILURE);

 err_lease:
	fprintf(stderr, TAG ": Lease entered an error state\n");
	{
		xmlNode *et;
		char *err;
		prop = v_retr_prop(cfg, &ses, sc, lease->mor, "error");
		et = x_getchild(prop->value, "localizedMessage");
		err = x_gettext(et);
		fprintf(stderr, TAG ": Lease message: %s\n", err);
	}
	exit(EXIT_FAILURE);
}

static void push_file(struct config *cfg, const char *tmpname)
{
	int fd;
	off_t vol_size;

	vol_size = file_size(cfg->push_img);

	fd = open(tmpname, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (fd == -1) {
		fprintf(stderr, TAG ": failed to create `%s': %s\n",
		    tmpname, strerror(errno));
		exit(EXIT_FAILURE);
	}
	convert(cfg->push_img, vol_size, fd);
	if (close(fd) != 0) {
		fprintf(stderr, TAG ": failed to write `%s': %s\n",
		    tmpname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fd = open(tmpname, O_RDONLY)) == -1) {
		fprintf(stderr, TAG ": unable to reopen `%s': %s\n",
		    tmpname, strerror(errno));
		exit(EXIT_FAILURE);
	}
	push(cfg, vol_size, fd);
	close(fd);

	/* The tmpname is not unlinked, so it can be examined for debugging. */
}

/*
 * This is quite inefficient, because it pipes the bulk of the data
 * to be uploaded through a system pipe, instead of just storing it in
 * a circular buffer or something. We do it for expediency, to preserve
 * the old code that worked with temporary files.
 */
static void push_pipe(struct config *cfg)
{
	off_t vol_size;
	int pipe_cvt_bulk[2];
	int wstat;
	pid_t converter;

	vol_size = file_size(cfg->push_img);

	if (pipe(pipe_cvt_bulk) < 0) {
		fprintf(stderr, TAG ": pipe error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	fflush(stdout);
	fflush(stderr);

	converter = fork();
	if (converter < 0) {
		fprintf(stderr, TAG ": fork error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (converter == 0) {
		close(pipe_cvt_bulk[0]);
		convert(cfg->push_img, vol_size, pipe_cvt_bulk[1]);
		exit(EXIT_SUCCESS);
	}

	close(pipe_cvt_bulk[1]);
	push(cfg, vol_size, pipe_cvt_bulk[0]);

	if (waitpid(converter, &wstat, 0) < 0) {
		fprintf(stderr, TAG ": waitpid error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!WIFEXITED(wstat)) {
		fprintf(stderr, TAG ": converter is killed (status 0x%x)\n",
		    wstat);
		exit(EXIT_FAILURE);
	}
	if (WEXITSTATUS(wstat)) {
		fprintf(stderr, "converter exited with code %d\n",
		    WEXITSTATUS(wstat));
		exit(EXIT_FAILURE);
	}

	close(pipe_cvt_bulk[0]);
}

int main(int argc, char **argv, char **envp)
{
	struct config cfg;

	/*
	 * SSL in curl blows up in uploader subprocess, because in Fedora
	 * libcurl is built with NSS, and NSS insists on initializing PKCS11
	 * (which we don't even need), and PKCS11 is defined to reject forks.
	 * The correct approach would be curl_global_cleanup() after fork().
	 * Alas, that breaks because NS_Initialize fails on second run.
	 * So, layering violation it is.
	 */
	if (setenv("NSS_STRICT_NOFORK", "DISABLED", 1) != 0) {
		fprintf(stderr, "setenv failed\n");
		exit(EXIT_FAILURE);
	}

	if (curl_global_init(CURL_GLOBAL_ALL) != 0)
		exit(EXIT_FAILURE);

	cfg_parse(&cfg, argc, argv);
	if (cfg.push_tmp) {
		push_file(&cfg, cfg.push_tmp);
	} else {
		push_pipe(&cfg);
	}

        curl_global_cleanup();
	return 0;
}
