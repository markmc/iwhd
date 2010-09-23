/* Copyright (C) 2010 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
void	 replicate_bcreate	(char *bucket);
int	 get_provider		(int i, provider_t *out);
void	 update_provider	(char *provider,
				 char *username, char *password);
char	*get_provider_value	(int i, char *fname);

#endif
