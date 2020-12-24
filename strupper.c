#include <stdlib.h>
#include <ctype.h>

char *str2upper(char *s, size_t max_len) {
	size_t i;

	for (i = 0; *s != '\0' && i < max_len; i++, s++)
		*s = toupper(*s);

	s -= i;
	
	return s;

}
