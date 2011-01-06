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

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <jansson.h>

#include "iwh.h"
#include "setup.h"
#include "query.h"
#include "meta.h"

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

/* Bitfield for things to check in validate_server */
#define NEED_SERVER	0x00000001
#define NEED_CREDS	0x00000002
#define NEED_PATH	0x00000004
#define NEED_ALL	~0

extern backend_func_tbl	bad_func_tbl;
extern backend_func_tbl	s3_func_tbl;
extern backend_func_tbl	curl_func_tbl;
extern backend_func_tbl	cf_func_tbl;
extern backend_func_tbl	fs_func_tbl;

static json_t		*config		= NULL;
static GHashTable	*prov_hash	= NULL;

provider_t	*main_prov	= NULL;
provider_t	*master_prov	= NULL;

static int
validate_server (unsigned int i)
{
	json_t		*server;
	json_t		*elem;
	const char	*name;
	const char	*type;
	unsigned int	 needs	= NEED_ALL;

	server = json_array_get(config,i);
	if (!json_is_object(server)) {
		error(0,0,"config elem %u: missing object",i);
		return 0;
	}

	elem = json_object_get(server,"name");
	if (!json_is_string(elem)) {
		error(0,0,"config elem %u: missing name",i);
		return 0;
	}
	name = json_string_value(elem);

	elem = json_object_get(server,"type");
	if (!json_is_string(elem)) {
		error(0,0,"config elem %u (%s): missing type",i,name);
		return 0;
	}
	type = json_string_value(elem);

	if (!strcasecmp(type,"s3") || !strcasecmp(type,"cf")) {
		needs = NEED_SERVER | NEED_CREDS;
	}
	else if (!strcasecmp(type,"http")) {
		needs = NEED_SERVER;
	}
	else if (!strcasecmp(type,"fs")) {
		needs = NEED_PATH;
	}
	else {
		error(0,0,"config elem %u (%s): bad type",i,name);
		return 0;
	}

	if (needs & NEED_SERVER) {
		elem = json_object_get(server,"host");
		if (!json_is_string(elem)) {
			error(0,0,"config elem %u (%s): missing host",
				i,name);
			return 0;
		}
		elem = json_object_get(server,"port");
		if (!json_is_integer(elem)) {
			error(0,0,"config elem %u (%s): missing port",
				i,name);
			return 0;
		}
	}

	if (needs & NEED_CREDS) {
		elem = json_object_get(server,"key");
		if (!json_is_string(elem)) {
			error(0,0,"config elem %u (%s): missing key",
			      i, name);
			return 0;
		}
		elem = json_object_get(server,"secret");
		if (!json_is_string(elem)) {
			error(0,0, "config elem %u (%s): missing secret",
			      i, name);
			return 0;
		}
	}

	if (needs & NEED_PATH) {
		elem = json_object_get(server,"path");
		if (!json_is_string(elem)) {
			error(0,0,"config elem %u (%s): missing path",
			      i, name);
			return 0;
		}
	}

	return 1;
}

static const char *
dup_json_string (const json_t *obj, const char *field)
{
	const char	*tmp;

	tmp = json_string_value(json_object_get(obj,field));
	if (tmp) {
		tmp = strdup(tmp);
	}

	return tmp;
}

static int
is_reserved_attr (const char *name)
{
	static char const *const rsvd[] = {
		"name", "type", "host", "port", "key", "secret", "path",
		NULL
	};
	const char *const *r;

	for (r = rsvd; *r; ++r) {
		if (!strcasecmp(*r,name)) {
			return 1;
		}
	}

	return 0;
}

static int
convert_provider (int i, provider_t *out)
{
	json_t		*server;
	void		*iter;
	const char	*key;
	const char	*value;

	server = json_array_get(config,i);
	if (!server) {
		DPRINTF("no such entry %d\n",i);
		return 0;
	}

	out->name = dup_json_string(server,"name");
	out->type = dup_json_string(server,"type");
	out->host = dup_json_string(server,"host");
	out->port = json_integer_value(json_object_get(server,"port"));
	/* TBD: change key/secret field names to username/password */
	out->username = dup_json_string(server,"key");
	out->password = dup_json_string(server,"secret");
	out->path = dup_json_string(server,"path");

	/* TBD: do this a cleaner way. */
	if (!strcasecmp(out->type,"s3")) {
		out->func_tbl = &s3_func_tbl;
	}
	else if (!strcasecmp(out->type,"http")) {
		out->func_tbl = &curl_func_tbl;
	}
	else if (!strcasecmp(out->type,"cf")) {
		out->func_tbl = &cf_func_tbl;
	}
	else if (!strcasecmp(out->type,"fs")) {
		out->func_tbl = &fs_func_tbl;
	}
	else {
		out->func_tbl = &bad_func_tbl;
	}

	out->attrs = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);
	iter = json_object_iter(server);
	while (iter) {
		key = json_object_iter_key(iter);
		if (!is_reserved_attr(key)) {
			value = json_string_value(json_object_iter_value(iter));
			if (value) {
				value = strdup(value);
			}
			if (value) {
				DPRINTF("%p.%s = %s\n",out,key,value);
				g_hash_table_insert(out->attrs,
					strdup((char *)key), (char *)value);
			}
			else {
				error(0,0,"could not extract %u.%s",i,key);
			}
		}
		iter = json_object_iter_next(server,iter);
	}

	out->token = NULL;

	return 1;
}

static const char *
parse_config_inner (void)
{
	unsigned int	 nservers;
	unsigned int	 i;
	json_t          *server;
	const char	*new_key;
	provider_t      *new_prov;
	const char	*primary	= NULL;

	if (json_typeof(config) != JSON_ARRAY) {
		error(0,0,"config should be a JSON array");
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
	printf("%u replication servers defined\n",nservers-1);
	prov_hash = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);
	if (!prov_hash) {
		error(0,0,"could not allocate provider hash");
		goto err;
	}
	for (i = 0; i < nservers; ++i) {
		server = json_array_get(config,i);
		if (!server) {
			error(0,0,"could not get pointer to provider %u",i);
			goto err_free_hash;
		}
		new_key = dup_json_string(server,"name");
		if (!new_key) {
			error(0,errno,"could not copy key %u",i);
			goto err_free_hash;
		}
		new_prov = (provider_t  *)malloc(sizeof(*new_prov));
		if (!new_prov) {
			error(0,errno,"could not allocate provider %u",i);
			free((char *)new_key);
			goto err_free_hash;
		}
		if (!convert_provider(i,new_prov)) {
			error(0,0,"could not add provider %u",i);
			free((char *)new_key);
			free(new_prov);
		}
		g_hash_table_insert(prov_hash,(char *)new_key,new_prov);
		if (!i) {
			main_prov = new_prov;
			primary = new_prov->name;
		}
		new_prov->func_tbl->init_func(new_prov);
	}
	return primary;

err_free_hash:
	g_hash_table_destroy(prov_hash);
	prov_hash = NULL;
err:
	return 0;
}

const char *
parse_config (char *cfg_file)
{
	json_error_t	 err;
	const char	*primary	= NULL;

	/*
	 * The master provider is special.  It's not in the provider hash
	 * (so replication code doesn't try to initiate replication to it)
	 * and it's always assumed to be our own protocol (which we access
	 * using CURL).
	 *
	 * TBD: initialize this in a separate module-init function, passing
	 * in master_host and master_port instead of using globals.
	 */
	if (!master_prov) {
		master_prov = malloc(sizeof(*master_prov));
		if (master_prov) {
			master_prov->func_tbl = &curl_func_tbl;
		}
	}

	if (access(cfg_file,R_OK) < 0) {
		error(0,errno,"failed to open %s for reading", cfg_file);
		return NULL;
	}

	config = json_load_file(cfg_file,&err);
	if (!config) {
		error(0,0,"JSON error on line %d: %s",err.line,err.text);
		return NULL;
	}

	primary = parse_config_inner();

	json_decref(config);
	config = NULL;

	return primary;
}

const char *
auto_config(void)
{
	static const char auto_json[] = {
		"[ {\n"
		"  \"name\": \"fs_autostart\",\n"
		"  \"type\": \"fs\",\n"
		"  \"path\": \"" AUTO_DIR_FS "\"\n"
		"} ]\n",
	};
	json_error_t	 err;
	const char	*primary	= NULL;

	if (auto_start(db_port) != 0) {
		return NULL;
	}

	config = json_loads(auto_json,&err);
	if (!config) {
		fprintf(stderr,"JSON error on line %d: %s\n",err.line,err.text);
		return NULL;
	}

	primary = parse_config_inner();
	if (primary) {
		printf("auto-start in effect\n");
	}
	else {
		error(0, 0, "invalid autostart configuration (internal error)");
	}

	json_decref(config);
	config = NULL;

	return primary;
}

const provider_t *
get_provider (const char *name)
{
	if (!prov_hash || !name || (*name == '\0')) {
		return NULL;
	}
	return g_hash_table_lookup(prov_hash,name);
}

const char *
get_provider_value (const provider_t *prov, const char *fname)
{
	if (!prov || !fname || (*fname == '\0')) {
		return NULL;
	}
	return g_hash_table_lookup(prov->attrs,fname);
}

void
init_prov_iter (GHashTableIter *iter)
{
	g_hash_table_iter_init(iter,prov_hash);
}

void
update_provider (const char *provname, const char *username,
		 const char *password)
{
	provider_t	*prov;

	DPRINTF("updating %s username=%s password=%s\n",
		provname, username, password);

	prov = (provider_t *)get_provider(provname);
	if (!prov) {
		DPRINTF("  could not find provider %s\n",provname);
		return;	/* TBD: return actual HTTP status for user */
	}

	free((char *)prov->username);
	prov->username = strdup(username);
	free((char *)prov->password);
	prov->password = strdup(password);
}
