#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "trim.h"
#include "sp_parser.h"

int simple_read_config(const char *fn, parser_function cll, void *config) {
	char *lineptr = NULL;
	size_t n = 0;
	char *key = NULL, *aux_key = NULL;
	char *value = NULL, *aux_value = NULL;
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

		value = strdup(aux_value);

		rc = cll(key, value, config);

		free(key);
		free(value);

		value = NULL;

		if (rc != 0)
			break;

	}

	free(lineptr);
	if (stream != DEFAULT_STREAM)
		fclose(stream);
	
	return rc;

}
