#include <stdio.h>

#ifndef _SP_PARSER_H
#	define _SP_PARSER_H

#define DEFAULT_STREAM stdin

/* El prototipo del callback a llamar por cada interacción del archivo de configuración */
typedef int(* parser_function)(const char *, const char *, void *);

int simple_read_config(const char *fn, parser_function cll, void *config);

#endif
