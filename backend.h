typedef void	 init_func_t		(void);
typedef void	*get_child_func_t	(void *);
typedef void	*put_child_func_t	(void *);
typedef void	*cache_child_func_t	(void *);
typedef int	 delete_func_t		(char *bucket, char *key, char *url);
typedef int	 bcreate_func_t		(char *bucket);

typedef struct {
	init_func_t		*init_func;
	get_child_func_t	*get_child_func;
	put_child_func_t	*put_child_func;
	cache_child_func_t	*cache_child_func;
	delete_func_t		*delete_func;
	bcreate_func_t		*bcreate_func;
} backend_func_tbl;

#define THREAD_FAILED	((void *)(-1))
