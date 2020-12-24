#ifndef _BOX_H
#	define _BOX_H
#	define BOX_PUBLIC_KEY 1
#	define BOX_SECRET_KEY 2
#	define BOX_VERIFY_KEY 3
#	define BOX_SIGN_KEY   4

#	define HASH_SIZE     28 /* = (EVP_MD_size(EVP_sha3_224())) */
#	define HASH_SIZE_HEX (HASH_SIZE*2)

#	include <sodium.h>

#	define PUBLICKEY_SIZE_BIN    crypto_kx_PUBLICKEYBYTES
#	define SECRETKEY_SIZE_BIN    (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + crypto_kx_SECRETKEYBYTES)
#	define PUBLICKEY_SIZE_HEX    (PUBLICKEY_SIZE_BIN*2)
#	define SECRETKEY_SIZE_HEX    (SECRETKEY_SIZE_BIN*2)
#	define PUBLICKEY_SIZE_BIN_ID (PUBLICKEY_SIZE_BIN+HASH_SIZE)
#	define SECRETKEY_SIZE_BIN_ID (SECRETKEY_SIZE_BIN+HASH_SIZE)
#	define PUBLICKEY_SIZE_HEX_ID (PUBLICKEY_SIZE_HEX+HASH_SIZE_HEX)
#	define SECRETKEY_SIZE_HEX_ID (SECRETKEY_SIZE_HEX+HASH_SIZE_HEX)

#	define VERIFYKEY_SIZE_BIN    crypto_sign_PUBLICKEYBYTES
#	define SIGNKEY_SIZE_BIN      (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + crypto_sign_SECRETKEYBYTES)
#	define VERIFYKEY_SIZE_HEX    (VERIFYKEY_SIZE_BIN*2)
#	define SIGNKEY_SIZE_HEX      (SIGNKEY_SIZE_BIN*2)
#	define SIGNKEY_SIZE_BIN_ID   (SIGNKEY_SIZE_BIN+HASH_SIZE)
#	define VERIFYKEY_SIZE_BIN_ID (VERIFYKEY_SIZE_BIN+HASH_SIZE)
#	define SIGNKEY_SIZE_BIN_ID   (SIGNKEY_SIZE_BIN+HASH_SIZE)
#	define VERIFYKEY_SIZE_HEX_ID (VERIFYKEY_SIZE_BIN_ID*2)
#	define SIGNKEY_SIZE_HEX_ID   (SIGNKEY_SIZE_BIN_ID*2)

#	define TABLE_CREDENTIALS 1
#	define TABLE_USERS       2

int import_key(sqlite3 *db, const unsigned char *user, int key, const unsigned char *key_content,
			   const unsigned char *passwd);
void delete_user(sqlite3 *db, const char *user);
void generate_keypair(sqlite3 *db, const char *user, const unsigned char *passwd);
void list_keys(sqlite3 *db, char *username);
unsigned char *export_key(sqlite3 *db, const char *user, int key);
void encrypt(FILE *i, FILE *o, long block_size,
			 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
void decrypt(FILE *i, FILE *o, long block_size,
			 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
void aencrypt(sqlite3 *db, FILE *i, FILE *o, long block_size,
			  char *opt_to, char *opt_from, unsigned char *p);
void adecrypt(sqlite3 *db, FILE *i, FILE *o, long block_size,
			  char *opt_to, char *opt_from, unsigned char *p);
unsigned char *sign(sqlite3 *db, FILE *i, FILE *o, long block_size,
					char *username, unsigned char *passwd);
void verify(sqlite3 *db, FILE *i, long block_size, char *username,
			unsigned char *sig_data);

#	include <stdbool.h>

int get_keysize(int key_type, bool hex);

#endif
