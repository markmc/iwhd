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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "template.h"
#include "gc-wrap.h"

static const char xml_root_header[] = "\
<api service=\"%s\" version=\"%s\">\
";

static const char xml_root_entry[] = "\
\n\
	<link rel=\"%s\" href=\"http://%s/\%s\"/>\
";

static const char xml_root_footer[] = "\
\n\
</api>\n\
";

static const char xml_prov_header[] = "\
<providers>\
";

static const char xml_prov_entry[] = "\
\n\
	<provider name=\"%s\">\n\
		<type>%s</type>\n\
		<host>%s</host>\n\
		<port>%d</port>\n\
		<username>%s</username>\n\
		<password>%s</password>\n\
	</provider>\
";

static const char xml_prov_footer[] = "\
\n\
</providers>\n\
";

static const char xml_list_header[] = "\
<objects>\
";

static const char xml_list_entry[] = "\
\n\
	<object>\n\
		<bucket>%s</bucket>\n\
		<key>%s</key>\n\
	</object>\
";

static const char xml_list_footer[] = "\
\n\
</objects>\n\
";

static const char xml_obj_header[] = "\
<object>\n\
	<object_body path=\"http://%s/%s/%s/body\"/>\n\
	<object_attr_list path=\"http://%s/%s/%s/_attrs\"/>\
";

static const char xml_obj_entry[] = "\
\n\
	<object_attr name=\"%s\" path=\"http://%s/%s/%s/attr_%s\"/>\
";

static const char xml_obj_footer[] = "\
\n\
</object>\n\
";

static const tmpl_format_t xml_format = {
	.root_header	= xml_root_header,
	.root_entry	= xml_root_entry,
	.root_footer	= xml_root_footer,
	.prov_header	= xml_prov_header,
	.prov_entry	= xml_prov_entry,
	.prov_footer	= xml_prov_footer,
	.list_header	= xml_list_header,
	.list_entry	= xml_list_entry,
	.list_footer	= xml_list_footer,
	.obj_header	= xml_obj_header,
	.obj_entry	= xml_obj_entry,
	.obj_footer	= xml_obj_footer,
	.z_offset	= 0
};

static const char json_root_header[] = "\
{\n\
	\"service\": \"%s\",\n\
	\"version\": \"%s\",\n\
	[\
";

static const char json_root_entry[] = "\
,\n\
		{\n\
			\"rel\": \"%s\",\n\
			\"link\": \"http://%s/%s\"\n\
		}\
";

static const char json_root_footer[] = "\
\n\
	]\n\
}\n\
";

static const char json_prov_header[] = "\
[\
";

static const char json_prov_entry[] = "\
,\n\
	{\n\
		\"name\": \"%s\",\n\
		\"type\": \"%s\",\n\
		\"host\": \"%s\",\n\
		\"port\": %d,\n\
		\"username\": \"%s\",\n\
		\"password\": \"%s\"\n\
	}\
";

static const char json_prov_footer[] = "\
\n\
]\n\
";

static const char json_list_header[] = "\
[\
";

static const char json_list_entry[] = "\
,\n\
	{\n\
		\"bucket\": \"%s\",\n\
		\"key\": \"%s\"\n\
	}\
";

static const char json_list_footer[] = "\
\n\
]\n\
";

static char json_obj_header[] = "\
{\n\
	\"object_body\": \"http://%s/%s/%s/body\"\n\
	\"object_attr_list\": \"http://%s/%s/%s/_attrs\"\
";

static char json_obj_entry[] = "\
,\n\
	\"attr_%s\": \"http://%s/%s/%s/attr_%s\"\
";

static char json_obj_footer[] = "\
\n\
}\n\
";

static const tmpl_format_t json_format = {
	.root_header	= json_root_header,
	.root_entry	= json_root_entry,
	.root_footer	= json_root_footer,
	.prov_header	= json_prov_header,
	.prov_entry	= json_prov_entry,
	.prov_footer	= json_prov_footer,
	.list_header	= json_list_header,
	.list_entry	= json_list_entry,
	.list_footer	= json_list_footer,
	.obj_header	= json_obj_header,
	.obj_entry	= json_obj_entry,
	.obj_footer	= json_obj_footer,
	.z_offset	= 1
};

tmpl_ctx_t *
tmpl_get_ctx (const char *type)
{
	tmpl_ctx_t	*tmp;

	tmp = malloc(sizeof(*tmp));
	if (tmp) {
		if (type && strstr(type,"/json")) {
			tmp->format = &json_format;
		}
		else {
			tmp->format = &xml_format;
		}
		tmp->index = 0;
	}
	return tmp;
}

size_t
tmpl_root_header (tmpl_ctx_t *ctx, const char *name, const char *version)
{
	int size;
	const tmpl_format_t *fmt = ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->root_header,
		name,version);
	if (size >= TMPL_BUF_SIZE || size < 0) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	return size;
}

size_t
tmpl_root_entry (tmpl_ctx_t *ctx, const char *rel, const char *link)
{
	int size;
	const tmpl_format_t *fmt = ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->root_entry,
		rel, ctx->base, link);
	if (size >= TMPL_BUF_SIZE || size < 0) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	if (size && (ctx->index == 0)) {
		ctx->buf += fmt->z_offset;
		size -= fmt->z_offset;
	}

	++(ctx->index);
	return size;
}

size_t
tmpl_root_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->root_footer;
	return strlen(ctx->buf);
}

size_t
tmpl_prov_header (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->prov_header;
	return strlen(ctx->buf);
}

int
tmpl_prov_entry (char *buf, size_t buf_len,
		 tmpl_ctx_t *ctx,
		 const char *name, const char *type,
		 const char *host, int port,
		 const char *user, const char *pass)
{
	if (!name)	name = "";
	if (!type)	type = "";
	if (!host)	host = "";
	if (!user)	user = "";
	if (!pass)	pass = "";

	const char *fmt = ctx->format->prov_entry;
	if (ctx->index == 0)
		fmt += ctx->format->z_offset;
	int size = snprintf(buf, buf_len, fmt,
			    name, type, host, port, user, pass);
	if (0 < size && size < buf_len)
		ctx->index++;

	return size;
}

size_t
tmpl_prov_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->prov_footer;
	return strlen(ctx->buf);
}

size_t
tmpl_list_header (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->list_header;
	return strlen(ctx->buf);
}

size_t
tmpl_list_entry (tmpl_ctx_t *ctx, const char *bucket, const char *key)
{
	int size;
	const tmpl_format_t *fmt = ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->list_entry,bucket,key);
	if (size >= TMPL_BUF_SIZE || size < 0) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	if (size && (ctx->index == 0)) {
		ctx->buf += fmt->z_offset;
		size -= fmt->z_offset;
	}

	++(ctx->index);
	return size;
}

size_t
tmpl_list_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->list_footer;
	return strlen(ctx->buf);
}

size_t
tmpl_obj_header (tmpl_ctx_t *ctx, const char *bucket, const char *key)
{
	int size;
	const tmpl_format_t *fmt = ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->obj_header,
		ctx->base, bucket, key,		/* once for the body... */
		ctx->base, bucket, key);	/* ...and once for the attrs */
	if (size >= TMPL_BUF_SIZE || size < 0) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	++(ctx->index);
	return size;
}

size_t
tmpl_obj_entry (tmpl_ctx_t *ctx, const char *bucket, const char *key,
		const char *attr)
{
	int size;
	const tmpl_format_t *fmt = ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->obj_entry,
		attr, ctx->base, bucket, key, attr);
	if (size >= TMPL_BUF_SIZE || size < 0) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	if (size && (ctx->index == 0)) {
		ctx->buf += fmt->z_offset;
		size -= fmt->z_offset;
	}

	++(ctx->index);
	return size;
}

size_t
tmpl_obj_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->obj_footer;
	return strlen(ctx->buf);
}
