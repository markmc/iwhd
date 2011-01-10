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

#if !defined(_SETUP_H)
#define _SETUP_H

#include <glib.h>
#include <curl/curl.h>	/* needed by stuff in state_defs.h (from backend.h) */
#include <microhttpd.h>	/* ditto */
#include <assert.h>
#include "backend.h"
#include "hash.h"
#include "hash-pjw.h"

typedef struct _provider {
	const char		*name;
	const char		*type;
	const char		*host;
	int			 port;
	int			 deleted;
	const char		*username;
	const char		*password;
	const char		*path;
	backend_func_tbl	*func_tbl;
	Hash_table		*attrs;
	char			*token;
} provider_t;

provider_t	*g_master_prov;

const char	 *parse_config		(char *);
provider_t	 *get_provider		(const char *name);
void		  update_provider	(const char *provname,
					 const char *username,
					 const char *password);
const char	 *get_provider_value	(const provider_t *prov,
					 const char *fname);

const char	 *auto_config		(void);
int validate_provider (Hash_table *h);
provider_t *find_provider (const char *name);
int add_provider (Hash_table *h);
provider_t *get_main_provider (void);
void set_main_provider (provider_t *prov);

provider_t *hash_get_first_prov (void);
provider_t *hash_get_next_prov (void *p);

struct kv_pair
{
  char *key;
  char *val;
};

#define STREQ(a, b) (strcmp (a, b) == 0)

static inline size_t
kv_hash (void const *x, size_t table_size)
{
  struct kv_pair const *p = x;
  return hash_pjw (p->key, table_size);
}

static inline bool
kv_compare (void const *x, void const *y)
{
  struct kv_pair const *u = x;
  struct kv_pair const *v = y;
  return STREQ (u->key, v->key) ? true : false;
}

static inline void
kv_free (void *x)
{
  struct kv_pair *p = x;
  free (p->key);
  free (p->val);
  free (p);
}

static inline int
kv_hash_insert_new (Hash_table *ht, char *k, char *v)
{
  struct kv_pair *kv = malloc (sizeof *kv);
  if (!kv)
    return 0;
  kv->key = k;
  kv->val = v;
  void *e = hash_insert (ht, kv);
  assert (e == kv);
  return 1;
}

/* Given a hash table and key K, return the value
   corresponding to K.  The caller must not free K.  */
static char *
kv_hash_lookup (Hash_table const *ht, char const *k)
{
  struct kv_pair kv;
  kv.key = (char *) k;
  struct kv_pair *p = hash_lookup (ht, &kv);
  return p ? p->val : NULL;
}

static void
kv_hash_delete (Hash_table *ht, char const *k)
{
  struct kv_pair kv;
  kv.key = (char *) k;
  struct kv_pair *p = hash_delete (ht, &kv);
  if (p) {
    free (p->key);
    free (p->val);
    free (p);
  }
}

/* Determine whether a key/value pair exists for which PRED_FN returns true.
   If so, return a pointer to that kv_pair.  Otherwise, return NULL.  */
static struct kv_pair *
kv_find_val (Hash_table *ht, Hash_processor pred_fn, void *ctx)
{
  void *found_kv = NULL;
  hash_do_for_each (ht, pred_fn, &found_kv);
  return found_kv;
}

#endif
