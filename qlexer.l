%{
#include <stdio.h>

#include "iwhd-qparser.h"
#define YY_DECL extern int yylex (YYSTYPE *lvalp)
%}

%%

\"[^"]*\"	{ yytext[yyleng-1] = 0; yytext++; return T_STRING; }
~[^~]*~		{ return T_DATE; }
[0-9]+		{ return T_NUMBER; }
[a-z_]+		{ return T_ID; }
[=$#()<>.]	{ return yytext[0]; }
!		{ return T_NOT; }
&		{ return T_AND; }
\|		{ return T_OR; }
[ \t\n\r]+	{ return T_SPACE; }
.		{ return T_INVALID; }

%%

static int at_eof = 0;

int
yywrap (void)
{
	return ++at_eof;
}

#if defined(UNIT_TEST)
static void
yyerror (const char *msg)
{
	printf("%s: %s\n",__func__,msg);
}

int
main (int argc, char **argv)
{

	yy_scan_string("\"!@#\" ~xxx~ 123 abc $#()<>=!&|.");

	do {
		YYSTYPE v;
		int t = yylex(&v);
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
