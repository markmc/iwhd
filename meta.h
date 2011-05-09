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

#ifndef _META_H
#define _META_H

#ifdef __cplusplus
extern "C" {
#endif

enum { QUERY_BKT_LIST, QUERY_OBJ_LIST, QUERY_FILTER };

extern void meta_init (void);
extern void meta_fini (void);
extern char *meta_did_put (const char *bucket, const char *key, const char *loc,
			   size_t size);
extern void meta_got_copy (const char *bucket, const char *key, const char *loc);
extern char *meta_has_copy (const char *bucket, const char *key, const char *loc);
extern int meta_set_value (const char *bucket, const char *key, const char *mkey,
			   const char *mvalue);
extern int meta_get_value (const char *bucket, const char *key, const char *mkey,
			   char **mvalue);
extern void *meta_query_new (const char *bucket, const char *key,
			     const char *expr);
extern int meta_query_next (void *qobj, char **bucket, char **key);
extern void meta_query_stop (void *qobj);
extern void meta_delete (const char *bucket, const char *key);
extern size_t meta_get_size (const char *bucket, const char *key);
extern void *meta_get_attrs (const char *bucket, const char *key);
extern int meta_attr_next (void *aobj, const char **, const char **);
extern void meta_attr_stop (void *aobj);

#ifdef __cplusplus
}
#endif

#endif
