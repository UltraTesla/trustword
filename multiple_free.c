#include <stdlib.h>
#include <stdarg.h>

void multiple_free(int ptrc, ...)
{
	va_list ap;

	va_start(ap, ptrc);

	while (ptrc-- > 0)
		free(va_arg(ap, void *));

	va_end(ap);

}
