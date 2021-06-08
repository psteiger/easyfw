%{
#include "efwlib.h"
#include <stdio.h>

#define YYERROR_VERBOSE

void yyerror(const char *str)
{
	fprintf(stderr, "Error: %s\n", str);
}

int yywrap()
{
	return 1;
}

int main()
{
	/* tell the resulting script to execute under default shell */
	printf("#!/bin/sh\n\n");

	/* flush all the rules */
	printf("iptables -F\n\n");

	yyparse();
	return 0;
}

%}

/* tokens to get from lexical analysis */
%token tRULE tIN tDO tOBRACE tCBRACE
%token tFROM tTO
%token tFROMPORT tTOPORT
%token tWHEN tCOMMA tEND
%token tDEFAULT
%token tFOR
%token tLOG tPROTOCOL
%token tINTERFACE

%union {
	char *str;
	struct table *type_table;
}

/* tokens data type is 'string' */
%token <str> TABLE RULE POLICY COMMENT DEVICE IP PROTOCOL PORT

/* non-terminal data types. can be strings or tables */
%type <str> file_input stmt def_policy

%type <type_table> for_stmt for_options 
%type <type_table> port_wordlist ip_wordlist device_wordlist prot_wordlist
%type <type_table> policies 
%type <type_table> rule_stmts rule 
%type <type_table> when_stmt when_option when_options
%%

file_input	: /* empty */ 		{ $$ = NULL; }
	   	| file_input stmt
	   	; 

stmt		: def_policy		{ $$ = NULL }
    		| rule			{ $$ = NULL } // Fix
		;


def_policy	: tDEFAULT TABLE POLICY {
			printf("#default %s %s\n", $2, $3);
			printf("iptables -P %s %s\n\n", trans_table($2), trans_policy($3));
		}
		;

when_stmt	: tWHEN when_options tDO policies tEND { $$ = merge_tables($2, $4); }
		;

for_stmt	: tFOR for_options tDO rule_stmts tEND { $$ = merge_tables($2, $4); }
		;

for_options	: tTOPORT port_wordlist {
	    		$$ = create_table();
			insert_stmt(&$$, NULL, "--dport");
			$$ = merge_tables($$, $2);
		}
		| tFROMPORT port_wordlist {
			$$ = create_table();
			insert_stmt(&$$, NULL, "--sport");
			$$ = merge_tables($$, $2);
		}
		| tINTERFACE device_wordlist {
			$$ = create_table();
			insert_stmt(&$$, NULL, "-i");
			$$ = merge_tables($$, $2);
		}
		| tFROM ip_wordlist {
			$$ = create_table();
			insert_stmt(&$$, NULL, "-s");
			$$ = merge_tables($$, $2);
		}
		| tTO ip_wordlist {
			$$ = create_table();
			insert_stmt(&$$, NULL, "-d");
			$$ = merge_tables($$, $2);
		}
		| tPROTOCOL prot_wordlist {
			$$ = create_table();
			insert_stmt(&$$, NULL, "-p");
			$$ = merge_tables($$, $2);
		}
		;

port_wordlist	: PORT 				{ $$ = create_table(); insert_stmt(&$$, NULL, $1); }
	 	| port_wordlist PORT 		{ $$ = $1; insert_stmt(&$$, NULL, $2); }
		;

device_wordlist	: DEVICE 			{ $$ = create_table(); insert_stmt(&$$, NULL, $1); }
	 	| device_wordlist DEVICE 	{ $$ = $1; insert_stmt(&$$, NULL, $2); }
		;

ip_wordlist	: IP 				{ $$ = create_table(); insert_stmt(&$$, NULL, $1); }
	 	| ip_wordlist IP 		{ $$ = $1; insert_stmt(&$$, NULL, $2); }
		;

prot_wordlist	: PROTOCOL 			{ $$ = create_table(); insert_stmt(&$$, NULL, $1); }
	 	| prot_wordlist PROTOCOL 	{ $$ = $1; insert_stmt(&$$, NULL, $2); }
		;

policies	: POLICY 			{ $$ = create_table(); insert_stmt(&$$, "-j", trans_policy($1)); }
		| tLOG COMMENT 			{ $$ = create_table(); insert_stmt(&$$, "-j LOG --log-prefix", $2); }
		| policies POLICY 		{ $$ = $1; insert_stmt(&$$, "-j", trans_policy($2)); }
		| policies tLOG COMMENT 	{ $$ = $1; insert_stmt(&$$, "-j LOG --log-prefix", $3); }
		;

when_option	: tPROTOCOL PROTOCOL 		{ $$ = create_table(); insert_stmt(&$$, "-p", $2); }
		| tTOPORT PORT 			{ $$ = create_table(); insert_stmt(&$$, "--dport", $2); }
		| tFROMPORT PORT 		{ $$ = create_table(); insert_stmt(&$$, "--sport", $2); }
		| tINTERFACE DEVICE 		{ $$ = create_table(); insert_stmt(&$$, "-i", $2); }
		| tFROM IP 			{ $$ = create_table(); insert_stmt(&$$, "-s", $2); }
		| tTO IP 			{ $$ = create_table(); insert_stmt(&$$, "-d", $2); }
		;

when_options	: when_option 			{ $$ = $1; }
	    	| when_options tCOMMA when_option { $$ = $1; glue_tables(&$$, $3); }
		;

rule_stmts	: policies 			{ $$ = $1; }
	   	| for_stmt 			{ $$ = $1; }
		| rule_stmts for_stmt 		{ $$ = $1; append_to_table(&$$, $2); }
		| when_stmt 			{ $$ = $1; }
		| rule_stmts when_stmt 		{ $$ = $1; append_to_table(&$$, $2); }
		;

rule		: tRULE COMMENT tIN TABLE tOBRACE rule_stmts tCBRACE { 
			printf("# Rule - %s\n", $2);
			$$ = create_table();
			insert_stmt(&$$, "-A", trans_table($4));
			$$ = merge_tables($$, $6);
			print_table($$);
			printf("\n");
      		}
      		;
