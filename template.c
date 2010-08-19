#include <stdio.h>
#include <stdlib.h>
#include "template.h"

char xml_root_header[] = "\
<api service=\"%s\" version=\"%s\">\
";

char xml_root_entry[] = "\
\n\
	<link rel=\"%s\" href=\"%s/\%s\"/>\
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
</providers>\n\
";

tmpl_format_t xml_format = {
	.root_header	= xml_root_header,
	.root_entry	= xml_root_entry,
	.root_footer	= xml_root_footer,
	.prov_header	= xml_prov_header,
	.prov_entry	= xml_prov_entry,
	.prov_footer	= xml_prov_footer,
	.z_offset	= 0
};

tmpl_ctx_t *
tmpl_get_ctx (char *type)
{
	tmpl_ctx_t	*tmp;

	tmp = (tmpl_ctx_t *)malloc(sizeof(*tmp));
	if (tmp) {
		tmp->format = &xml_format;
		tmp->index = 0;
	}
}

int
tmpl_root_header (tmpl_ctx_t *ctx, char *name, char *version)
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
tmpl_root_entry (tmpl_ctx_t *ctx, char *rel, char *link)
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
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->root_footer);
	if (size >= TMPL_BUF_SIZE) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	return size;
}

int
tmpl_prov_header (tmpl_ctx_t *ctx)
{
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->prov_header);
	if (size >= TMPL_BUF_SIZE) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	return size;
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
	int		 size;
	tmpl_format_t	*fmt	= ctx->format;

	size = snprintf(ctx->raw_buf,TMPL_BUF_SIZE,fmt->prov_footer);
	if (size >= TMPL_BUF_SIZE) {
		return 0;
	}
	ctx->buf = ctx->raw_buf;

	return size;
}
