#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "efwlib.h"

/** Translates the policy tokens to iptables format **/
char* 
trans_policy( char * str )
{
	char *result;
	
	result = malloc(sizeof(char) * 8);

	if (!strcmp("allow", str)) {
		strcpy(result, "ACCEPT");
	} else if (!strcmp("deny", str)) {
		strcpy(result, "REJECT");
	} else if (!strcmp("drop", str)) {
		strcpy(result, "DROP");
	} else if (!strcmp("log string", str)) {
		strcpy(result, "LOG");
	}

	return result;
}

/** Translate the table tokens to iptables format **/
char* 
trans_table( char *str ) 
{
	char *result;

	result = malloc(sizeof(char) * 8);

	if (!strcmp("input", str)) {
		strcpy(result, "INPUT");
	} else if (!strcmp("output", str)) {
		strcpy(result, "OUTPUT");
	} else if (!strcmp("forward", str)) {
		strcpy(result, "FORWARD");
	}

	return result;
}

/**
 * Conserta a ordem de algumas coisas. Por exemplo, se existem especificacoes
 * de ambas portas e protocolos, a opcao de porta deverá vir depois da de protocolo
**/
char*
normalize( char *str )
{
	char *tokenized_str;
	char *result = malloc(sizeof(char) * 256);
	char *port = NULL;

	int insert_port = 0;
	int insert_protocol = 0;

	tokenized_str = strtok(str, " ");

	while (tokenized_str != NULL) {
		if (insert_port) {
			strcat(port, tokenized_str);
			strcat(port, " ");
			insert_port = 0;
		} else if (!strcmp(tokenized_str, "--dport") ||
			   !strcmp(tokenized_str, "--sport")) {
			port = malloc(sizeof(char) * 20);
			strcat(port, tokenized_str);
			strcat(port, " ");
			insert_port = 1;
		} else if (!strcmp(tokenized_str, "-j")) {
			if (port) {
				strcat(result, port);
			}

			strcat(result, "-j");
			strcat(result, " ");
		} else {
			strcat(result, tokenized_str);
			strcat(result, " ");
		}

		tokenized_str = strtok(NULL, " ");
	}

	return result;
}


struct table*
create_table( void )
{
	struct table *t;
	
	t = malloc(sizeof(struct table));
	t->num_stmts = 0;
	
	return t;
}

void
print_table(struct table *s)
{
	int i;

	for (i=0; i < s->num_stmts; i++) {
		printf("iptables %s\n", normalize(s->statement[i]));
	}
}

void 
insert_stmt(struct table **s, char *iptables_param, char *str)
{
	int i = (*s)->num_stmts; // first free index

	(*s)->statement[i] = malloc(sizeof(char) * 256);

	if (iptables_param != NULL) {
		strcpy((*s)->statement[i], iptables_param);
		strcat((*s)->statement[i], " ");
	}

	strcat((*s)->statement[i], str);
	(*s)->num_stmts += 1;
}

struct table*
merge_tables( struct table *s1, struct table *s2)
{
	struct table *result;
	char *stmt;
	int i, j;

	result = create_table();

	for (i=0; i < s1->num_stmts; i++) {
		for(j=0; j < s2->num_stmts; j++) {
			stmt = malloc(sizeof(char) * 256);
			
			strcat(stmt, s1->statement[i]);
			strcat(stmt, " ");
			strcat(stmt, s2->statement[j]);
			
			insert_stmt(&result, NULL, stmt);
		}
	}

	return result;
}

void
append_to_table( struct table **s1, struct table *s2 )
{
	int i;

	for (i=0; i < s2->num_stmts; i++) {
		insert_stmt(s1, NULL, s2->statement[i]);
	}
}

void
glue_tables( struct table **s1, struct table *s2 )
{
	if ((*s1)->num_stmts != s2->num_stmts)
		printf("Erro brutal\n");

	int i;

	for (i=0; i < (*s1)->num_stmts; i++) {
		strcat((*s1)->statement[i], " ");
		strcat((*s1)->statement[i], s2->statement[i]);
	}
}
