#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <argon2.h>
#include "multiple_free.h"

char *
argon2_generate(const unsigned char *pwd, size_t pwdlen, int hashlen, int saltlen,
				int t_cost, int m_cost, int parallelism, int encoded_len)
{
	unsigned char *salt = (unsigned char *)malloc(sizeof(unsigned char)*saltlen);
	char *encoded = (char *)malloc(encoded_len);

	if (!salt || !encoded) {
		if (errno != 0)
			perror("malloc()");
		multiple_free(2, salt, encoded);
		return NULL;

	}

	randombytes_buf(salt, saltlen);

	int rc = argon2id_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt,
								   saltlen, hashlen, encoded, encoded_len);
    if (ARGON2_OK != rc) {
		fprintf(stderr, "Ocurrió un error generando el hash: %s\n",
			argon2_error_message(rc));
		multiple_free(2, salt, encoded);
		return NULL;

    }
	multiple_free(1, salt);

    return encoded;
}
