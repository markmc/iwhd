#if defined(__cplusplus)
extern "C" {
#endif

void meta_init (void);
void meta_fini (void);
char *meta_did_put (char * bucket, char * key, char * loc);
void meta_got_copy (char * bucket, char * key, char * loc);
char *meta_has_copy (char * bucket, char * key, char * loc);
int meta_set_value (char * bucket, char * key, char * mkey, char * mvalue);
int meta_get_value (char * bucket, char * key, char * mkey, char ** mvalue);

typedef void qcb_t (char *, char *, void *);
int meta_query (char * mkey, char * mvalue, qcb_t * cb, void * ctx);
void * meta_query_new (char * expr);
int meta_query_next (void * qobj, char ** bucket, char ** key);
void meta_query_stop (void * qobj);

#if defined(__cplusplus)
}
#endif
