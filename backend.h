/* Copyright (C) 2010-2011 Red Hat, Inc.

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

#if !defined(_BACKEND_H)
#define _BACKEND_H

#include "state_defs.h"
#include "hash.h"

typedef void	 init_func_t		(struct _provider *prov);
/* Get provider from passed backend_thunk. */
typedef void	*get_child_func_t	(void *);
/* Get provider from passed pipe_private. */
typedef void	*put_child_func_t	(void *);
typedef void	*cache_child_func_t	(void *);
/* Get provider as an argument. */
typedef int	 delete_func_t		(const struct _provider *prov,
					 const char *bucket, const char *key,
					 const char *url);
typedef int	 bcreate_func_t		(const struct _provider *prov,
					 const char *bucket);
typedef int	 register_func_t	(my_state *ms,
					 const struct _provider *prov,
					 const char *next, Hash_table *args);

typedef struct {
	const char		*name;
	init_func_t		*init_func;
	get_child_func_t	*get_child_func;
	put_child_func_t	*put_child_func;
	cache_child_func_t	*cache_child_func;
	delete_func_t		*delete_func;
	bcreate_func_t		*bcreate_func;
	register_func_t		*register_func;
} backend_func_tbl;

#define THREAD_FAILED	((void *)(-1))

void backend_init (void);

#endif
