typedef void	*get_child_func_t	(void *);
typedef void	*put_child_func_t	(void *);
typedef void	*cache_child_func_t	(void *);

typedef struct {
	/* TBD: init function */
	get_child_func_t	*get_child_func;
	put_child_func_t	*put_child_func;
	cache_child_func_t	*cache_child_func;
	/* TBD: delete function */
	/* TBD: bucket-create function */
} backend_func_tbl;

#define THREAD_FAILED	((void *)(-1))
