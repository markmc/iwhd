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

#if !defined(_TEMPLATE_H)
#define _TEMPLATE_H

#define TMPL_BUF_SIZE	1024

typedef struct {
	const char	*root_header;
	const char	*root_entry;
	const char	*root_footer;
	const char	*prov_header;
	const char	*prov_entry;
	const char	*prov_footer;
	const char	*list_header;
	const char	*list_entry;
	const char	*list_footer;
	const char	*obj_header;
	const char	*obj_entry;
	const char	*obj_footer;
	int		 z_offset;	/* offset to use when index is zero */
} tmpl_format_t;

typedef struct {
	const tmpl_format_t *format;
	const char	*base;
	unsigned int	 index;
	char		 raw_buf[TMPL_BUF_SIZE];
	const char		*buf;
} tmpl_ctx_t;

#define TMPL_CTX_DONE	((tmpl_ctx_t *)(-1))

tmpl_ctx_t	*tmpl_get_ctx		(const char *type);
size_t		 tmpl_root_header	(tmpl_ctx_t *ctx,
					 const char *name, const char *version);
size_t		 tmpl_root_entry	(tmpl_ctx_t *ctx,
					 const char *rel, const char *link);
size_t		 tmpl_root_footer	(tmpl_ctx_t *ctx);
size_t		 tmpl_prov_header	(tmpl_ctx_t *ctx);

int tmpl_prov_entry (char *buf, size_t buf_len,
		     const char *fmt,
		     const char *name, const char *type,
		     const char *host, int port,
		     const char *user, const char *pass);

size_t		 tmpl_prov_footer	(tmpl_ctx_t *ctx);
size_t		 tmpl_list_header	(tmpl_ctx_t *ctx);
size_t		 tmpl_list_entry	(tmpl_ctx_t *ctx,
					 const char *bucket, const char *key);
size_t		 tmpl_list_footer	(tmpl_ctx_t *ctx);
size_t		 tmpl_obj_header	(tmpl_ctx_t *ctx,
					 const char *bucket, const char *key);
size_t		 tmpl_obj_entry		(tmpl_ctx_t *ctx, const char *bucket,
					 const char *key, const char *attr);
size_t		 tmpl_obj_footer	(tmpl_ctx_t *ctx);


#endif
