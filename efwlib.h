/* main structure for the compiler semantics */
struct table {
	int num_stmts;
	char *statement[100];
};

/* token translation functions */
char* 		trans_policy(char *str);
char* 		trans_table(char *str);

/* printing-related functions */
char* 		normalize(char *str);
void 		print_table(struct table *s);

/* other table-dealing functions */
struct table* 	create_table(void);
void 		insert_stmt(struct table **s, char *iptables_param, char *str);
struct table*	merge_tables(struct table *s1, struct table *s2);
void		append_to_table(struct table **s1, struct table *s2);
void		glue_tables(struct table **s1, struct table *s2);