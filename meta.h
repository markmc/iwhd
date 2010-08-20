#if defined(__cplusplus)
extern "C" {
#endif

enum { QUERY_BKT_LIST, QUERY_OBJ_LIST, QUERY_FILTER };

void meta_init (void);
void meta_fini (void);
char *meta_did_put (char * bucket, char * key, char * loc, size_t size);
void meta_got_copy (char * bucket, char * key, char * loc);
char *meta_has_copy (char * bucket, char * key, char * loc);
int meta_set_value (char * bucket, char * key, char * mkey, char * mvalue);
int meta_get_value (char * bucket, char * key, char * mkey, char ** mvalue);

typedef void qcb_t (char *, char *, void *);
int meta_query (char * mkey, char * mvalue, qcb_t * cb, void * ctx);
void * meta_query_new (char * bucket, char * key, char * expr);
int meta_query_next (void * qobj, char ** bucket, char ** key);
void meta_query_stop (void * qobj);
void meta_delete (char * bucket, char * key);
size_t meta_get_size (char * bucket, char * key);

#if defined(__cplusplus)
}
#endif
