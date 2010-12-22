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

#ifndef _QUERY_H
#define _QUERY_H 1

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
extern "C" {
#endif

#include "iwhd-qparser.h"

/*
 * Comparisons are all the same type to the parser, but when it comes to
 * evaluation we need to know the difference so we use these subtypes.
 */
typedef enum {
	C_LESSTHAN,	C_LESSOREQ,
	C_EQUAL,	C_DIFFERENT,
	C_GREATEROREQ,	C_GREATERTHAN
} comp_t;

/* The actual values are generated by the parser. */
typedef enum yytokentype type_t;

/*
 * Universal AST object.  T_NUMBER uses as_num, and some day T_DATE might as
 * well.  Several types (T_STRING, T_ID, T_*FIELD) all use as_str.  The rest
 * use as_tree, but there's a caveat.  In most cases as_tree.right really is
 * a value_t, but for T_LINK it's a bare string.
 * TBD: use a separate as_link union member for T_LINK.
 */
typedef struct value_t {
	type_t type;
	union {
		long long as_num;
		char *as_str;
		struct {
			comp_t op;
			struct value_t *left;
			struct value_t *right;
		} as_tree;
	};
	const char *resolved;	/* saved result for T_OFIELD/T_SFIELD/T_LINK */
} value_t;

/*
 * In a higher-level language, this would be a method pointer.  It's just
 * a pointer to a function plus a little piece of the caller's context (in
 * the replication-policy case it's the current bucket and key) so that we
 * can do concurrent evaluations with separate contexts.
 */
typedef struct {
	const char	*(*func)	(void *, const char *);
	void		*ctx;
} getter_t;
#define CALL_GETTER(g,x)	g->func(g->ctx,x)

/*
 * In the normal case a caller would invoke parse once and eval multiple times.
 * print_value is just for debugging/testing.
 * TBD: make parse reentrant (eval already is).
 * Unfortunately, a quick scan of generated code and information on the web
 * seems to indicate that even a "reentrant" bison parser only encapsulates
 * user state and still relies quite a bit on internal globals.  That might
 * mean that we just have to put a lock around it instead.
 */
int	 eval		(const value_t *expr,
			 const getter_t *oget, const getter_t *sget);
void	 print_value	(const value_t *);

value_t *parse (const char *text);

#if defined(__CPLUSPLUS__) || defined(__cplusplus)
}
#endif

#endif
