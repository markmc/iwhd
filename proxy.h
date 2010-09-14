#if !defined(_PROXY_H)
#define _PROXY_H

#include "backend.h"

typedef struct _provider {
	int			 index;
	const char		*name;
	const char		*type;
	const char		*host;
	int			 port;
	const char		*username;
	const char		*password;
	backend_func_tbl	*func_tbl;
} provider_t;

char	*parse_config		(void);
void	 repl_init		(void);
void	 replicate		(char *url, size_t size, char *policy);
void	 replicate_delete	(char *url);
int	 get_provider		(int i, provider_t *out);
void	 update_provider	(char *provider,
				 char *username, char *password);
char	*get_provider_value	(int i, char *fname);

#endif
