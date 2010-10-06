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

#if !defined(_META_H)
#define _META_H

#if defined(__cplusplus)
extern "C" {
#endif

enum { QUERY_BKT_LIST, QUERY_OBJ_LIST, QUERY_FILTER };

void meta_init (void);
void meta_fini (void);
char *meta_did_put (const char *bucket, const char *key, const char *loc,
		    size_t size);
void meta_got_copy (const char *bucket, const char *key, const char *loc);
char *meta_has_copy (const char *bucket, const char *key, const char *loc);
int meta_set_value (const char *bucket, const char *key, const char *mkey,
		    const char *mvalue);
int meta_get_value (const char *bucket, const char *key, const char *mkey,
		    char **mvalue);

void *meta_query_new (const char *bucket, const char *key, const char *expr);
int meta_query_next (void *qobj, char **bucket, char **key);
void meta_query_stop (void *qobj);
void meta_delete (const char *bucket, const char *key);
size_t meta_get_size (const char *bucket, const char *key);
void *meta_get_attrs (const char *bucket, const char *key);
int meta_attr_next (void *aobj, const char **, const char **);
void meta_attr_stop (void *aobj);

#if defined(__cplusplus)
}
#endif

#endif
