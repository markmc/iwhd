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

#if !defined(_SETUP_H)
#define _SETUP_H

#include <glib.h>
#include <curl/curl.h>	/* needed by stuff in state_defs.h (from backend.h) */
#include <microhttpd.h>	/* ditto */
#include "backend.h"

typedef struct _provider {
	const char		*name;
	const char		*type;
	const char		*host;
	int			 port;
	int			 deleted;
	gint			 refcnt;
	const char		*username;
	const char		*password;
	const char		*path;
	backend_func_tbl	*func_tbl;
	GHashTable		*attrs;
	char			*token;
} provider_t;

provider_t	*master_prov;

const char	 *parse_config		(char *);
provider_t	 *get_provider		(const char *name);
void		  update_provider	(const char *provname,
					 const char *username,
					 const char *password);
const char	 *get_provider_value	(const provider_t *prov,
					 const char *fname);
void		  init_prov_iter	(GHashTableIter *iter);

const char	 *auto_config		(void);
int validate_provider (GHashTable *h);
provider_t *find_provider (const char *name);
int add_provider (GHashTable *h);
void delete_provider (provider_t *prov);
provider_t *get_main_provider (void);
void set_main_provider (provider_t *prov);

#endif
