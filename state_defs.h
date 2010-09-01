#define MAX_FIELD_LEN	64

typedef enum {
	MS_NEW,
	MS_NORMAL,
} ms_state;

typedef struct {
	int				 cleanup;
	/* for everyone */
	MHD_AccessHandlerCallback	 handler;
	ms_state			 state;
	/* for local ops */
	int				 fd;
	/* for proxy ops */
	char				*url;
	char				 bucket[MAX_FIELD_LEN];
	char				 key[MAX_FIELD_LEN];
	char				 attr[MAX_FIELD_LEN];
	/* for proxy gets */
	CURL				*curl;
	long				 rc;
	/* for proxy puts */
	size_t				 size;
	/* for proxy puts and queries */
	struct MHD_Connection		*conn;
	/* for proxy queries */
	struct MHD_PostProcessor	*post;
	void				*query;
	/* for bucket-level puts */
	GHashTable			*dict;
	/* for new producer/consumer model */
	pipe_shared			 pipe;
	int				 from_master;
	pthread_t			 backend_th;
	pthread_t			 cache_th;
	/* for bucket/object/provider list generators */
	tmpl_ctx_t			*gen_ctx;
} my_state;

#define CLEANUP_CURL	0x01
#define CLEANUP_BUF_PTR	0x02
#define CLEANUP_POST	0x04
#define CLEANUP_DICT	0x08
#define CLEANUP_QUERY	0x10
#define CLEANUP_TMPL	0x20
#define CLEANUP_URL	0x40


void free_ms (my_state *ms);
