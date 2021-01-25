#include <string.h>
#include <ctype.h>

void init_counter(int *n) {
	if (n != NULL)
		*n = 0;

}

void add_counter(int *n) {
	if (n != NULL)
		*n += 1;

}

void rstrip(char *string, int *spaces) {
	init_counter(spaces);

    while(*string != '\0')
        string++;

    string--;
    while(isspace(*string)) {
        *(string--) = '\0';
		add_counter(spaces);

	}
}

void lstrip(char *string, int *spaces) {
	char *begin = string;

	init_counter(spaces);

	while (isspace(*string)) {
		string++;
		add_counter(spaces);

	}

	if (string != begin)
		memmove(begin, string, strlen(string)+1);

}

void trim(char *string) {
	lstrip(string, NULL);
	rstrip(string, NULL);

}
