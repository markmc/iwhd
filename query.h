#if !defined(_QUERY_H)

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
extern "C" {
#endif

typedef enum {
	C_LESSTHAN,	C_LESSOREQ,
	C_EQUAL,	C_DIFFERENT,
	C_GREATEROREQ,	C_GREATERTHAN
} comp_t;

typedef enum {
	T_NUMBER, T_STRING, T_OFIELD, T_SFIELD,
	T_COMP, T_NOT, T_AND, T_OR, T_LINK
} type_t;

typedef struct _value {
	type_t type;
	union {
		long long as_num;
		char *as_str;
		struct {
			comp_t op;
			struct _value *left;
			struct _value *right;
		} as_tree;
	};
} value_t;

typedef struct {
	char	*(*func)	(void *, const char *);
	void	*ctx;
} getter_t;
#define CALL_GETTER(g,x)	g->func(g->ctx,x)


value_t	*parse		(const char *text);
int	 eval		(const value_t *expr, getter_t *oget, getter_t *sget);
void	 free_value	(const value_t *);
void	 print_value	(const value_t *);

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
}
#endif

#endif
