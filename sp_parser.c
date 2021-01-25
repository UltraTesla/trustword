#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "trim.h"
#include "sp_parser.h"

char *replace(char *s, char *a, char *b) {
	char *pattern = strstr(s, a);
	if (!pattern)
		return NULL;
	int offset = pattern-s;
	size_t a_length = strlen(a);
	size_t b_length = strlen(b);
	size_t length = strlen(s)-a_length;
	int move_to = offset+a_length;
	length += strlen(b);
	length += 1; /* Por el terminador nulo */
	char *buff = (char *)malloc(length);

	strncpy(buff, s, offset);
	strcat(buff, b);
	s += move_to;
	strcat(buff, s);
	s -= move_to;

	return buff;

}

char *env2val(char *s) {
	char *aux = s;
	char c, l = 0; /* 'c', es el carácter actual y 'l' el anterior */
	int start, end;
	int length;
	int counter;
	int offset;
	int i, j, z;
	char *buff = NULL, *replaced = NULL;
	char *env_val = NULL;
	char *new_s = strdup(s), *new_s_aux = NULL;

	counter = 0, offset = 0;
	while ((c = *aux++)) {
		if (c == '$' && l != '\\') {
			counter++;
			if ((c = *aux++) == '{') {
				start = ++counter;
				while ((c = *aux++) != '}' && c)
					offset++;
				end = start+offset;

				if (c != '}') /* Error de sintaxis */
					continue;

				length = end-start+1;
				buff = (char *)malloc(length);
				for (i = start, j = end, z = 0; i < j; i++, z++)
					buff[z] = s[i];
				buff[z] = '\0';

				env_val = getenv(buff);
				if (env_val) {
					env_val = strdup(env_val);

					replaced = (char *)malloc(length+3); /* 3 para agregar: '$', '{' y '}' */
					strcpy(replaced, "$");
					strcat(replaced, "{");
					strcat(replaced, buff);
					strcat(replaced, "}");

					new_s_aux = new_s;
					new_s = replace(new_s, replaced, env_val);
					free(new_s_aux);
					free(replaced);

				}

				free(buff);
				free(env_val);
				counter += offset;
				offset = 0;

			}

		}

		counter++;
		l = c;

	}

	return new_s;

}

int simple_read_config(const char *fn, parser_function cll, void *config) {
	char *lineptr = NULL;
	size_t n = 0;
	char *key = NULL, *aux_key = NULL;
	char *value = NULL, *aux_value = NULL;
	char *new_value = NULL;
	char *aux_lineptr = NULL;
	FILE *stream;
	int rc = 0;
	int rspaces = 0;

	if (fn == NULL)
		stream = DEFAULT_STREAM;
	else if ((stream = fopen(fn, "rb")) == NULL)
		return errno;

	while (getline(&lineptr, &n, stream) > 0) {
		aux_lineptr = lineptr;

		if (aux_lineptr[0] == '\n')
			continue;

		lstrip(aux_lineptr, NULL);

		if (aux_lineptr[0] == ';')
			continue;

		if (strcmp(aux_lineptr, "") == 0)
			continue;

		aux_key = strtok(aux_lineptr, ":");
		lstrip(aux_key, NULL);
		rstrip(aux_key, &rspaces);
		key = strdup(aux_key);
		
		aux_value = aux_lineptr;
		aux_value += strlen(key)+rspaces+1;
		trim(aux_value);

		new_value = env2val(aux_value);

		rc = cll(key, new_value, config);

		free(key);
		free(value);
		free(new_value);

		value = NULL;

		if (rc != 0)
			break;

	}

	free(lineptr);
	if (stream != DEFAULT_STREAM)
		fclose(stream);
	
	return rc;

}
