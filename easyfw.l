%{
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "easyfw.tab.h"

void str_tolower( char **s )
{
	int i;

	for (i=0; (*s)[i]; i++) {
		(*s)[i] = tolower((*s)[i]);
	}
}

%}

_ip_num         ([1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))
number          [0-9]+
device 		"eth"{number}
ip		{_ip_num}"."{_ip_num}"."{_ip_num}"."{_ip_num}("/"{mask})?
mask            ([0-2][0-9])|3[0-2]
comment		\"[^"\r\n]*\"
policy		"allow"|"deny"|"drop"|"log string"
table		"input"|"output"|"forward"

%option case-insensitive

%%

[ \t\n]			/* ignore whitespace and newlines */
\#[^\r\n]*\n		/* ignore file comments */
{table}			yylval.str=strdup(yytext); str_tolower(&yylval.str); return TABLE;
{policy}		yylval.str=strdup(yytext); str_tolower(&yylval.str); return POLICY;
{comment}		yylval.str=strdup(yytext); return COMMENT;
{device}		yylval.str=strdup(yytext); str_tolower(&yylval.str); return DEVICE;
{ip}			yylval.str=strdup(yytext); str_tolower(&yylval.str); return IP;
udp|tcp|icmp|all	yylval.str=strdup(yytext); str_tolower(&yylval.str); return PROTOCOL;
{number}		yylval.str=strdup(yytext); str_tolower(&yylval.str); return PORT;
default			return tDEFAULT;
in			return tIN;
rule			return tRULE;
\{			return tOBRACE;
\}			return tCBRACE;
do			return tDO;
from			return tFROM;
to			return tTO;
from-port		return tFROMPORT;
to-port			return tTOPORT;
log			return tLOG;
protocol		return tPROTOCOL;
iface			return tINTERFACE;
for			return tFOR;
when			return tWHEN;
,			return tCOMMA;
end			return tEND;
%%
