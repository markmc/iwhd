#if !defined(_TEMPLATE_H)
#define _TEMPLATE_H

#define TMPL_BUF_SIZE	1024

typedef struct {
	char	*root_header;
	char	*root_entry;
	char	*root_footer;
	char	*prov_header;
	char	*prov_entry;
	char	*prov_footer;
	char	*obj_header;
	char	*obj_entry;
	char	*obj_footer;
	int	 z_offset;	/* offset to use when index is zero */
} tmpl_format_t;

typedef struct {
	tmpl_format_t	*format;
	const char	*base;
	unsigned int	 index;
	char		 raw_buf[TMPL_BUF_SIZE];
	char		*buf;
} tmpl_ctx_t;

#define TMPL_CTX_DONE	((tmpl_ctx_t *)(-1))

tmpl_ctx_t	*tmpl_get_ctx		(const char *type);
int		 tmpl_root_header	(tmpl_ctx_t *ctx,
					 char *name, char *version);
int		 tmpl_root_entry	(tmpl_ctx_t *ctx,
					 char *rel, char *link);
int		 tmpl_root_footer	(tmpl_ctx_t *ctx);
int		 tmpl_prov_header	(tmpl_ctx_t *ctx);
int		 tmpl_prov_entry	(tmpl_ctx_t *ctx,
					 const char *name, const char *type,
					 const char *host, int port,
					 const char *user, const char *pass);
int		 tmpl_root_footer	(tmpl_ctx_t *ctx);
int		 tmpl_obj_header	(tmpl_ctx_t *ctx);
int		 tmpl_obj_entry		(tmpl_ctx_t *ctx,
					 const char *bucket, const char *key);
int		 tmpl_obj_footer	(tmpl_ctx_t *ctx);
int		 tmpl_prov_footer	(tmpl_ctx_t *ctx);

#endif
