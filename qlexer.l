%{
#include <config.h>
#include <stdio.h>

#ifndef FLEX_SCANNER
# error This scanner must be made using flex, not lex.
#endif

#include "iwhd-qparser.h"
#undef YY_DECL
#define YY_DECL extern int yylex (YYSTYPE *yylval_param, yyscan_t yyscanner)
%}

%option warn nounput noinput noyywrap
%option bison-bridge reentrant

%%

\"[^"]*\"	{ yytext[yyleng-1] = 0; yytext++;
		  yylval_param->str = strdup(yytext);
		  return yylval_param->str ? T_STRING : T_INVALID; }
~[^~]*~		{ yylval_param->str = strdup(yytext);
		  return yylval_param->str ? T_DATE : T_INVALID; }
[0-9]+		{ yylval_param->str = strdup(yytext);
		  return yylval_param->str ? T_NUMBER : T_INVALID; }
[a-z_]+		{ yylval_param->str = strdup(yytext);
		  return yylval_param->str ? T_ID : T_INVALID; }
[=$#()<>.]	{ return yytext[0]; }
!=		{ return T_NE; }
!		{ return T_NOT; }
&&		{ return T_AND; }
\|\|		{ return T_OR; }
[ \t\n\r]+	{ return T_SPACE; }
.		{ return T_INVALID; }

<<EOF>>		{ yyterminate (); /* aka return 0; */ }


%%

#if defined(UNIT_TEST)
static void
yyerror (const char *msg)
{
	printf("%s: %s\n",__func__,msg);
}

int
main (int argc, char **argv)
{
	yyscan_t scanner;
	yylex_init (&scanner);
	YY_BUFFER_STATE buf
	  = yy_scan_string ("\"!@#\" ~xxx~ 123 abc $#()<>=!&|.", scanner);

	while (1) {
		YYSTYPE v;
		int t = yylex(&v, scanner);
		if (t == 0)
			break;

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
	}

	yy_delete_buffer (buf, scanner);
	yylex_destroy (scanner);

	return 0;
}
#endif
