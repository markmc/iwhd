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

typedef void qcb_t (char *, char *, void *);
int meta_query (const char *mkey, const char *mvalue, qcb_t *cb, void *ctx);
void *meta_query_new (const char *bucket, const char *key, const char *expr);
int meta_query_next (void *qobj, char **bucket, char **key);
void meta_query_stop (void *qobj);
void meta_delete (const char *bucket, const char *key);
size_t meta_get_size (const char *bucket, const char *key);

#if defined(__cplusplus)
}
#endif

#endif
