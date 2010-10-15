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

#if !defined(_QUERY_H)

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
extern "C" {
#endif

#include "iwhd-qparser.h"

typedef enum {
	C_LESSTHAN,	C_LESSOREQ,
	C_EQUAL,	C_DIFFERENT,
	C_GREATEROREQ,	C_GREATERTHAN
} comp_t;

typedef enum yytokentype type_t;

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
	const char *resolved;	/* saved result for T_OFIELD/T_SFIELD/T_LINK */
} value_t;

typedef struct {
	const char	*(*func)	(void *, const char *);
	void		*ctx;
} getter_t;
#define CALL_GETTER(g,x)	g->func(g->ctx,x)

int	 eval		(const value_t *expr, getter_t *oget, getter_t *sget);
void	 free_value	(value_t *);
void	 print_value	(const value_t *);

value_t *parse (const char *text);

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
}
#endif

#endif
