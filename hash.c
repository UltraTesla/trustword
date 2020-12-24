#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define _ERR_String() fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL))
#define _ERR_String_with_free() {_ERR_String(); EVP_MD_CTX_free(mdctx); return NULL;}

unsigned char *bin2hash(const unsigned char *message, size_t message_len, const EVP_MD *function) {
	EVP_MD_CTX *mdctx;
	unsigned char *digest = NULL;
	unsigned digest_len = EVP_MD_size(function);

	if (message_len == -1)
		message_len = strlen(message);

	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		_ERR_String();
		return NULL;

	}

	if (EVP_DigestInit_ex(mdctx, function, NULL) != 1)
		_ERR_String_with_free();

	if (EVP_DigestUpdate(mdctx, message, message_len) != 1)
		_ERR_String_with_free();

	if ((digest = (unsigned char *)malloc(digest_len)) == NULL)
		_ERR_String_with_free();

	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1)
		_ERR_String_with_free();

	EVP_MD_CTX_free(mdctx);

	return digest;
}

unsigned char *hash_sha3_224(const unsigned char *m, size_t s) {
	return bin2hash(m, s, EVP_sha3_224());

}

unsigned char *hash_sha3_256(const unsigned char *m, size_t s) {
	return bin2hash(m, s, EVP_sha3_256());

}
