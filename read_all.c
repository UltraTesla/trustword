#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "read_all.h"

char *read_all(FILE *f, size_t max_length) {
	char *lineptr = NULL;
	size_t n = 0;
	int errno_bak = 0;
	char *buff = (char *)malloc(sizeof(char));

	if (!buff)
		return buff;

	*buff = '\0';

	size_t len = 0;
	while (getline(&lineptr, &n, f) > 0) {
		len += strlen(lineptr)+1;
		buff = (char *)realloc(buff, len);

		if (max_length > 0 && len >= max_length)
			break;
		
		if (!buff) {
			errno_bak = errno;
			break;

		}

		strcat(buff, lineptr);

	}

	free(lineptr);

	errno = errno_bak;

	return buff;

}
