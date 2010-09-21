#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "template.h"

char xml_root_header[] = "\
<api service=\"%s\" version=\"%s\">\
";

char xml_root_entry[] = "\
\n\
	<link rel=\"%s\" href=\"http://%s/\%s\"/>\
";

char xml_root_footer[] = "\
\n\
</api>\n\
";

char xml_prov_header[] = "\
<providers>\
";

char xml_prov_entry[] = "\
\n\
	<provider name=\"%s\">\n\
		<type>%s</type>\n\
		<host>%s</host>\n\
		<port>%d</port>\n\
		<username>%s</username>\n\
		<password>%s</password>\n\
	</provider>\
";

char xml_prov_footer[] = "\
\n\
</providers>\n\
";

char xml_obj_header[] = "\
<objects>\
";

char xml_obj_entry[] = "\
\n\
	<object>\n\
		<bucket>%s</bucket>\n\
		<key>%s</key>\n\
	</object>\
";

char xml_obj_footer[] = "\
\n\
</objects>\n\
";


tmpl_format_t xml_format = {
	.root_header	= xml_root_header,
	.root_entry	= xml_root_entry,
	.root_footer	= xml_root_footer,
	.prov_header	= xml_prov_header,
	.prov_entry	= xml_prov_entry,
	.prov_footer	= xml_prov_footer,
	.obj_header	= xml_obj_header,
	.obj_entry	= xml_obj_entry,
	.obj_footer	= xml_obj_footer,
	.z_offset	= 0
};

char json_root_header[] = "\
{\n\
	\"service\": \"%s\",\n\
	\"version\": \"%s\",\n\
	[\
";

char json_root_entry[] = "\
,\n\
		{\n\
			\"rel\": \"%s\",\n\
			\"link\": \"http://%s/%s\"\n\
		}\
";

char json_root_footer[] = "\
\n\
	]\n\
}\n\
";

char json_prov_header[] = "\
[\
";

char json_prov_entry[] = "\
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

char json_prov_footer[] = "\
\n\
]\n\
";

char json_obj_header[] = "\
[\
";

char json_obj_entry[] = "\
,\n\
	{\n\
		\"bucket\": \"%s\",\n\
		\"key\": \"%s\"\n\
	}\
";

char json_obj_footer[] = "\
\n\
]\n\
";

tmpl_format_t json_format = {
	.root_header	= json_root_header,
	.root_entry	= json_root_entry,
	.root_footer	= json_root_footer,
	.prov_header	= json_prov_header,
	.prov_entry	= json_prov_entry,
	.prov_footer	= json_prov_footer,
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

int
tmpl_root_header (tmpl_ctx_t *ctx, const char *name, const char *version)
{
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->root_header,
		name,version);
	if (size >= TMPL_BUF_SIZE) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	return size;
}

int
tmpl_root_entry (tmpl_ctx_t *ctx, const char *rel, const char *link)
{
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->root_entry,
		rel, ctx->base, link);
	if (size >= TMPL_BUF_SIZE) {
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

int
tmpl_root_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->root_footer;
	return strlen(ctx->buf);
}

int
tmpl_prov_header (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->prov_header;
	return strlen(ctx->buf);
}

int
tmpl_prov_entry (tmpl_ctx_t *ctx,
		 const char *name, const char *type,
		 const char *host, int port,
		 const char *user, const char *pass)
{
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->prov_entry,
		name, type, host, port, user, pass);
	if (size >= TMPL_BUF_SIZE) {
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

int
tmpl_prov_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->prov_footer;
	return strlen(ctx->buf);
}

int
tmpl_obj_header (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->obj_header;
	return strlen(ctx->buf);
}

int
tmpl_obj_entry (tmpl_ctx_t *ctx, const char *bucket, const char *key)
{
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->obj_entry,bucket,key);
	if (size >= TMPL_BUF_SIZE) {
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

int
tmpl_obj_footer (tmpl_ctx_t *ctx)
{
	ctx->buf = ctx->format->obj_footer;
	return strlen(ctx->buf);
}
