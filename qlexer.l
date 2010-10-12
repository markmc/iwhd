%{
#include <stdio.h>

#if defined(UNIT_TEST)
enum {
	T_STRING,	T_DATE,		T_NUMBER,	T_ID,
	T_DOLLAR,	T_WAFFLE,	T_LPAREN,	T_RPAREN,
	T_LESS,		T_GREATER,	T_EQUAL,	T_NOT,
	T_AND,		T_OR,		T_DOT,		T_SPACE,
	T_INVALID
};
#else
#include "qparser.tab.h"
#endif
%}

%%

\"[^"]*\"	{ return T_STRING; }
~[^~]*~		{ return T_DATE; }
[0-9]+		{ return T_NUMBER; }
[a-z_]+		{ return T_ID; }
\$		{ return T_DOLLAR; }
#		{ return T_WAFFLE; }
\(		{ return T_LPAREN; }
\)		{ return T_RPAREN; }
\<		{ return T_LESS; }
\>		{ return T_GREATER; }
=		{ return T_EQUAL; }
!		{ return T_NOT; }
&		{ return T_AND; }
\|		{ return T_OR; }
\.		{ return T_DOT; }
[ \t\n\r]+	{ return T_SPACE; }
.		{ return T_INVALID; }

%%

int at_eof = 0;

int
yywrap (void)
{
	return ++at_eof;
}

#if defined(UNIT_TEST)
static void
yyerror (char *msg)
{
	printf("%s: %s\n",__func__,msg);
}

int
main (int argc, char **argv)
{
	int	t;

	yy_scan_string("\"!@#\" ~xxx~ 123 abc $#()<>=!&|.");

	do {
		t = yylex();
		switch (t) {
		case T_STRING:
			if (!yytext[0]) {
				printf("EOF\n");
				break;
			}
		case T_DATE:
		case T_NUMBER:
		case T_ID:
			printf("%d %s\n",t,yytext);
			break;
		case T_SPACE:
			break;
		case T_INVALID:
			printf("INVALID %c\n",yytext[0]);
			break;
		default:
			printf("%d\n",t);
		}
	} while (!at_eof);

	return 0;
}
#endif
