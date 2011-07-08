%define api.pure
%error-verbose

%{
#include <config.h>
#include "query.h"
#include "qparser.h"
%}

%union {
  char *str;
  struct value_t *val;
}

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "iwh.h"
#include "logging.h"

/* Return a pointer to this when allocation fails in a value_t-returning
   function.  */
static value_t invalid = { T_INVALID, {0}, NULL };

#define YY_DECL int yylex(YYSTYPE *, void *scanner);
YY_DECL

/* TBD: use separate function to parse dates differently */
static value_t *
make_number (const char *text)
{
	value_t *tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return &invalid;

	tmp->type = T_NUMBER;
	tmp->as_num = strtoll(text,NULL,10);
	tmp->resolved = NULL;
	free ((void *) text);

	return tmp;
}

/* Return a malloc'd value_t buffer, with its type to T and using TEXT
   (already malloc'd) as its string.  */
static value_t *
make_string (const char *text, type_t t)
{
	value_t *tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return &invalid;

	tmp->type = t;
	tmp->as_str = (char *) text;
	tmp->resolved = NULL;

	return tmp;
}

/* Return a malloc'd tree_t, with type T and branches LEFT and RIGHT.
   LEFT must be non-NULL.  RIGHT may be NULL (solely for use in handling
   a negated expression).  */
static value_t *
make_tree (type_t t, const value_t *left, const value_t *right)
{
	if (left->type == T_INVALID)
		return (value_t *) left;
	if (t != T_LINK && right && right->type == T_INVALID)
		return (value_t *) right;
	value_t *tmp = malloc(sizeof(*tmp));

	if (!tmp)
		return &invalid;

	tmp->type = t;
	tmp->as_tree.left = (value_t *) left;
	tmp->as_tree.right = (value_t *) right;
	tmp->resolved = NULL;

	return tmp;
}

/* Return a malloc'd comp_t, with type T and branches LEFT and RIGHT.
   LEFT and RIGHT must both be non-NULL.  */
static value_t *
make_comp (comp_t c, const value_t *left, const value_t *right)
{
	if (left->type == T_INVALID)
		return (value_t *) left;
	if (right->type == T_INVALID)
		return (value_t *) right;
	value_t *tmp = make_tree(T_COMP,left,right);

	if (!tmp)
		return &invalid;

	tmp->as_tree.op = c;

	return tmp;
}

static value_t *
make_link (const value_t *left, const char *right)
{
	return make_tree(T_LINK,left,(value_t *)right);
}

static void
yyerror (void *scanner ATTRIBUTE_UNUSED,
	 value_t **result ATTRIBUTE_UNUSED,
	 const char *msg ATTRIBUTE_UNUSED)
{
	/* empty */
}

%}

%lex-param   { yyscan_t scanner }
%parse-param { void *scanner }
%parse-param { value_t **result }

%token <str> T_STRING T_COMP T_DATE T_ID T_LINK T_NUMBER T_OFIELD T_SFIELD
%token T_EQ T_NE T_NOT T_AND T_OR T_INVALID
%token T_LT T_GT T_LE T_GE

%type <val> atom bbool_expr comp_expr field
%type <val> link_field literal paren_expr ubool_expr

%start policy

%%

policy:
	bbool_expr {
		*result = $1;
	};

bbool_expr:
	ubool_expr {
		// printf("promoting ubool_expr to bbool_expr\n");
		$$ = $1;
	}|
	bbool_expr T_AND ubool_expr {
		// printf("found AND expression\n");
		$$ = make_tree(T_AND,$1,$3);
	}|
	bbool_expr T_OR ubool_expr {
		// printf("found OR expression\n");
		$$ = make_tree(T_OR,$1,$3);
	};

ubool_expr:
	comp_expr {
		// printf("promoting comp_expr to ubool_expr\n");
		$$ = $1;
	}|
	T_NOT comp_expr {
		// printf("found NOT expression\n");
		$$ = make_tree(T_NOT,$2,NULL);
	};


comp_expr:
	atom {
		// printf("promoting atom to comp_expr\n");
		$$ = $1;
	}|
	atom T_LT atom {
		// printf("found LESS THAN expression\n");
		$$ = make_comp(C_LESSTHAN,$1,$3);
	}|
	atom T_LE atom {
		// printf("found LESS OR EQUAL expression\n");
		$$ = make_comp(C_LESSOREQ,$1,$3);
	}|
	atom T_EQ atom {
		// printf("found EQUAL expression\n");
		$$ = make_comp(C_EQUAL,$1,$3);
	}|
	atom T_NE atom {
		// printf("found NOT EQUAL expression\n");
		$$ = make_comp(C_DIFFERENT,$1,$3);
	}|
	atom T_GE atom {
		// printf("found GREATER OR EQUAL expression\n");
		$$ = make_comp(C_GREATEROREQ,$1,$3);
	}|
	atom T_GT atom {
		// printf("found GREATER THAN expression\n");
		$$ = make_comp(C_GREATERTHAN,$1,$3);
	};

atom:
	link_field {
		// printf("promoting link_field to atom\n");
		$$ = $1;
	}|
	literal {
		// printf("promoting literal to atom\n");
		$$ = $1;
	}|
	paren_expr {
		// printf("promoting paren_expr to atom\n");
		$$ = $1;
	};

link_field:
	field {
		// printf("promoting field to link_field\n");
		$$ = $1;
	}|
	link_field '.' T_ID {
		// printf("found LINK FIELD\n");
		$$ = make_link($1,$3);
	};

field:
	'$' T_ID {
		// printf("found DOLLAR FIELD\n");
		$$ = make_string($2,T_OFIELD);
	}|
	'#' T_ID {
		// printf("found WAFFLE FIELD\n");
		$$ = make_string($2,T_SFIELD);
	};

literal:
	T_NUMBER {
		// printf("found NUMBER %s\n",$1);
		$$ = make_number($1);
	}|
	T_STRING {
		// printf("found STRING %s\n",$1);
		$$ = make_string($1,T_STRING);
	}|
	T_DATE {
		// printf("found DATE\n");
		$$ = make_string($1,T_DATE);
	}|
	T_ID {
		// printf("found ID %s\n",$1);
		$$ = make_string($1,T_ID);
	};

paren_expr:
	'(' bbool_expr ')' {
		// printf("found PAREN expression\n");
		$$ = $2;
	};

%%

#if defined PARSER_UNIT_TEST

#include "xalloc.h"

static const struct { char *name; char *value; } hacked_obj_fields[] = {
        /* Fake object fields for generic unit testing. */
	{ (char*) "a", (char*) "2" },
	{ (char*) "b", (char*) "7" },
	{ (char*) "c", (char*) "11" },
        /* This one's here to test links (e.g. $template.owner.name). */
	{ (char*) "template", (char*) "templates/the_tmpl" },
	{ NULL, NULL }
};

/* Fake out the eval code for unit testing. */
static const char *
unit_oget_func (void * notused, const char *text)
{
	int i;

	for (i = 0; hacked_obj_fields[i].name; ++i) {
		if (!strcmp(hacked_obj_fields[i].name,text)) {
			return hacked_obj_fields[i].value;
		}
	}

	return NULL;
}
static const getter_t unit_oget = { unit_oget_func, NULL };

/*
 * Same as above, but the site-field stuff is so similar to the object-field
 * stuff that it's not worth exercising too much separately.
 */
static const char *
unit_sget_func (void * notused, const char *text)
{
	return "never";
}
static const getter_t unit_sget = { unit_sget_func, NULL };

/* Fake links from an object/key tuple to an object/key string. */
static const struct { char *obj; char *key; char *value; } hacked_links[] = {
	{ (char*) "templates/the_tmpl", (char*) "owner",
	  (char*) "users/the_user" },
	{ (char*) "users/the_user", (char*) "name", (char*) "Jeff Darcy" },
	{ NULL, NULL, NULL }
};

static char *
follow_link (const char *object, const char *key)
{
	unsigned int i;

	for (i = 0; hacked_links[i].obj; ++i) {
		if (strcmp(object,hacked_links[i].obj)) {
			continue;
		}
		if (strcmp(key,hacked_links[i].key)) {
			continue;
		}
		return hacked_links[i].value;
	}

	return NULL;
}
#else
extern char *follow_link (const char *object, const char *key);
#endif

static void
_print_value (const value_t *v, int level)
{
	if (!v) {
		printf("%*sNULL\n",level,"");
		return;
	}

	switch (v->type) {
	case T_NUMBER:
		printf("%*sNUMBER %lld\n",level,"",v->as_num);
		break;
	case T_STRING:
		printf("%*sSTRING %s\n",level,"",v->as_str);
		break;
	case T_OFIELD:
#if defined PARSER_UNIT_TEST
		printf("%*sOBJECT FIELD %s (%s)\n",level,"",v->as_str,
			unit_oget_func(NULL,v->as_str));
#else
		printf("%*sOBJECT FIELD %s\n",level,"",v->as_str);
#endif
		break;
	case T_SFIELD:
#if defined PARSER_UNIT_TEST
		printf("%*sSERVER FIELD %s (%s)\n",level,"",v->as_str,
			unit_sget_func(NULL,v->as_str));
#else
		printf("%*sSERVER FIELD %s\n",level,"",v->as_str);
#endif
		break;
	case T_COMP:
		printf("%*sCOMPARISON\n",level,"");
		_print_value(v->as_tree.left,level+2);
		_print_value(v->as_tree.right,level+2);
		break;
	case T_NOT:
		printf("%*sNOT\n",level,"");
		_print_value(v->as_tree.left,level+2);
		break;
	case T_AND:
		printf("%*sAND\n",level,"");
		_print_value(v->as_tree.left,level+2);
		_print_value(v->as_tree.right,level+2);
		break;
	case T_OR:
		printf("%*sOR\n",level,"");
		_print_value(v->as_tree.left,level+2);
		_print_value(v->as_tree.right,level+2);
		break;
	case T_LINK:
		printf("%*sLINK\n",level,"");
		_print_value(v->as_tree.left,level+2);
		printf("%*sDEST FIELD %s\n",level+2,"",
			(char *)v->as_tree.right);
		break;
	default:
		printf("%*sUNKNOWN %d\n",level,"",v->type);
	}
}

void
print_value (const value_t *v)
{
	_print_value(v,0);
}

#include "qlexer.c"

value_t *
parse (const char *text)
{
  yyscan_t scanner;
  if (yylex_init (&scanner))
    error (0, errno, _("failed to initialize query parser"));
  YY_BUFFER_STATE buf = yy_scan_string (text, scanner);
  value_t *result = NULL;
  value_t *r = yyparse (scanner, &result) == 0 ? result : NULL;
  yy_delete_buffer (buf, scanner);
  yylex_destroy (scanner);
  return r;
}

/*
 * Return the string value of an expression for comparison or display, iff
 * all component parts are string-valued themselves.  That excludes numbers
 * and booleans.
 */
static const char *
string_value (value_t *v, const getter_t *oget, const getter_t *sget)
{
	const char	*left;

	/* Disable this caching, which seems to be invalid. */
	v->resolved = NULL;

	switch (v->type) {
	case T_STRING:
		return v->as_str;
	case T_OFIELD:
		if (!v->resolved) {
			v->resolved = oget ? CALL_GETTER(oget,v->as_str) : NULL;
		}
		return v->resolved;
	case T_SFIELD:
		return sget ? CALL_GETTER(sget,v->as_str) : NULL;
	case T_LINK:
		if (!v->resolved) {
			left = string_value(v->as_tree.left,oget,sget);
			if (left) {
				v->resolved = follow_link((char *)left,
					(char *)v->as_tree.right);
			}
		}
		return v->resolved;
	default:
		return NULL;
	}
}

/*
 * Check whether a string looks like a simple decimal number.  There's
 * probably a library function for this somewhere.
 */
static int
is_ok_number (const char *a_str)
{
	const char	*p;

	if (!a_str) {
		return 0;
	}

	for (p = a_str; *p; ++p) {
		if (!isdigit(*p)) {
			return 0;
		}
	}

	return 1;
}

/*
 * Comparisons are a bit messy.  If both sides are numbers, strings that look
 * like numbers, or expressions that evaluate to numbers (booleans evaluate
 * to 0/1), then we do a numeric comparison.  Otherwise, if both sides
 * evaluate to strings, we attempt a string comparison.   That's the logic,
 * but the code is actually structured a different way to allow re-use of
 * common operator-specific code at the end for both cases.
 */
static int
compare (value_t *left, comp_t op, value_t *right,
	 const getter_t *oget, const getter_t *sget)
{
	const char	*lstr;
	const char	*rstr;
	int	 	 lval = 0; // solely to placate gcc
	int	 	 rval;
	int	 	 num_ok = 1;

	lstr = string_value(left,oget,sget);
	rstr = string_value(right,oget,sget);

	if (left->type == T_NUMBER) {
		lval = left->as_num;
	}
	else if (lstr) {
		if (is_ok_number(lstr)) {
			lval = strtoll(lstr,NULL,0);
		}
		else {
			num_ok = 0;
		}
	}
	else {
		lval = eval(left,oget,sget);
		if (lval < 0) {
			return lval;
		}
	}

	if (right->type == T_NUMBER) {
		rval = right->as_num;
	}
	else if (rstr) {
		if (is_ok_number(rstr)) {
			rval = strtoll(rstr,NULL,0);
		}
		else {
			num_ok = 0;
		}
	}
	else {
		rval = eval(right,oget,sget);
		if (rval < 0) {
			return rval;
		}
	}

        /*
         * Strcmp returns -1/0/1, but -1 for us would mean an error and
         * which of 0/1 we return depends on which comparison operatoer
         * we're dealing with.  Therefore, we stick the strcmp result on
         * the left side and let the switch below do an operator-appropriate
         * compare against zero on the right.
         */
	if (!num_ok) {
		if (!lstr || !rstr) {
			return -1;
		}
		lval = strcmp(lstr,rstr);
		rval = 0;
	}

	switch (op) {
	case C_LESSTHAN:	return (lval < rval);
	case C_LESSOREQ:	return (lval <= rval);
	case C_EQUAL:		return (lval == rval);
	case C_DIFFERENT:	return (lval != rval);
	case C_GREATEROREQ:	return (lval >= rval);
	case C_GREATERTHAN:	return (lval > rval);
	default:
		return -1;
	}
}

/*
 * Evaluate an AST in the current context to one of:
 *      true=1
 *      false=0
 *      error=-1
 * It's up to the caller whether error is functionally the same as false.
 * Note that even T_NUMBER gets squeezed down to these three values.  The
 * only thing numbers are used for is comparing against other numbers to
 * yield a boolean for the query or replication-policy code.  If you want
 * something that returns a number, this is the wrong language for it.
 */

int
eval (const value_t *v, const getter_t *oget, const getter_t *sget)
{
	int	 	 res;
	const char	*str;

	switch (v->type) {
	case T_NUMBER:
		return v->as_num != 0;
	case T_STRING:
		return v->as_str && *v->as_str;
	case T_OFIELD:
		str = CALL_GETTER(oget,v->as_str);
		return str && *str;
	case T_SFIELD:
		str = CALL_GETTER(sget,v->as_str);
		return str && *str;
	case T_LINK:
		str = string_value(v->as_tree.left,oget,sget);
		if (str) {
			str = follow_link(str,(char *)v->as_tree.right);
		}
		return str && *str;
	case T_COMP:
		return compare(v->as_tree.left,(comp_t)v->as_tree.op,
			v->as_tree.right, oget, sget);
	case T_NOT:
		res = eval(v->as_tree.left,oget,sget);
		return (res >= 0) ? !res : res;
	case T_AND:
		res = eval(v->as_tree.left,oget,sget);
		if (res > 0) {
			res = eval(v->as_tree.right,oget,sget);
		}
		return res;
	case T_OR:
		res = eval(v->as_tree.left,oget,sget);
		if (res > 0) {
			return res;
		}
		return eval(v->as_tree.right,oget,sget);
	default:
		return -1;
	}
}

#ifdef PARSER_UNIT_TEST
int
main (int argc, char **argv)
{
  int fail = 0;
  int i;
  GC_INIT ();
  for (i = 1; i < argc; ++i)
    {
      value_t *expr = parse (argv[i]);
      if (!expr)
	{
	  printf ("could not parse '%s'\n", argv[i]);
	  fail = 1;
	  continue;
	}

      print_value (expr);

      const char *str = string_value (expr, &unit_oget, &unit_sget);
      if (str)
	{
	  printf ("s= %s\n", str);
	  continue;
	}
      printf ("d= %d\n", eval (expr, &unit_oget, &unit_sget));
    }

  return fail;
}
#endif
