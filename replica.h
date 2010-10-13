/* Copyright (C) 2010 Red Hat, Inc.

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

#if !defined(_REPLICA_H)
#define _REPLICA_H

void	 	  repl_init		(void);
void	 	  replicate		(const char *url, size_t size,
					 const char *policy);
void	 	  replicate_delete	(const char *url);
void	 	  replicate_bcreate	(const char *bucket);
int	 	  get_rep_count		(void);

#endif
