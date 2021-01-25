#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include <sqlite3.h>
#include <argon2.h>
#include "argon2_custom.h"
#include "config.h"
#include "box.h"
#include "hash.h"
#include "strupper.h"
#include "multiple_free.h"

unsigned char *get_key(sqlite3 *db, const unsigned char *user_digest, int key_type) {
	sqlite3_stmt *res;
	unsigned char *result = NULL;

	char *sql;
	if (key_type == BOX_PUBLIC_KEY)
		sql = "SELECT publickey FROM users WHERE user = ?";
	else if (key_type == BOX_SECRET_KEY)
		sql = "SELECT secretkey FROM users WHERE user = ?";
	else if (key_type == BOX_VERIFY_KEY)
		sql = "SELECT verifykey FROM users WHERE user = ?";
	else if (key_type == BOX_SIGN_KEY)
		sql = "SELECT signkey FROM users WHERE user = ?";
	else
		return NULL;

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK)
		sqlite3_bind_blob(res, 1, user_digest, HASH_SIZE, SQLITE_STATIC);
	else
		fprintf(stderr, "No se pudo ejecutar la secuencia SQL para extraer la clave: %s\n",
			sqlite3_errmsg(db));

	int step = sqlite3_step(res);
	if (step == SQLITE_ROW) {
		int key_size = sqlite3_column_bytes(res, 0);

		if ((key_type == BOX_PUBLIC_KEY && key_size != PUBLICKEY_SIZE_BIN) ||
			(key_type == BOX_SECRET_KEY && key_size != SECRETKEY_SIZE_BIN)) {
			fputs("El tamaño de la clave no es correcto.\n", stderr);

		} else {
			result = (unsigned char *)malloc(sizeof(unsigned char)*key_size);
			memcpy(result, sqlite3_column_blob(res, 0), sizeof(unsigned char)*key_size);
		}

	} else
		fprintf(stderr, "Ocurrió un error extrayendo la clave: %s\n",
			sqlite3_errmsg(db));

	sqlite3_finalize(res);

	return result;

}

char *get_passwd_hash(sqlite3 *db, int userid) {
	sqlite3_stmt *res;
	char *sql = "SELECT password FROM credentials WHERE userid = ?";
	char *result = NULL;

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc != SQLITE_OK)
		fprintf(stderr, "Error preparando la consulta SQL para obtener la contraseña: %s\n",
			sqlite3_errmsg(db));
	else
		sqlite3_bind_int(res, 1, userid);

	int step = sqlite3_step(res);
	if (step == SQLITE_ROW)
		result = strdup(sqlite3_column_text(res, 0));
	else
		fprintf(stderr, "No se pudo obtener la contraseña: %s\n",
			sqlite3_errmsg(db));

	sqlite3_finalize(res);

	return result;

}

unsigned char *decrypt_key(const unsigned char *k, const unsigned char *p,
						   int key_type) {
	int key_size;
	int dec_key_size;

	if (key_type == BOX_SECRET_KEY) {
		key_size = SECRETKEY_SIZE_BIN;
		dec_key_size = crypto_kx_SECRETKEYBYTES;
	} else if (key_type == BOX_SIGN_KEY) {
		key_size = SIGNKEY_SIZE_BIN;
		dec_key_size = crypto_sign_SECRETKEYBYTES;
	} else {
		fputs("No se puede determinar el tipo de clave a desencriptar.\n", stderr);
		return NULL;
	}

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char *decrypted = (unsigned char*)malloc(sizeof(unsigned char)*dec_key_size);
	unsigned char *result = NULL;
	
	memcpy(nonce, k, sizeof(nonce));
	k += sizeof(nonce);

	if (crypto_secretbox_open_easy(decrypted, k, key_size-sizeof(nonce), nonce, p) == 0)
		result = decrypted;
	else {
		fputs("Contraseña incorrecta o clave corrupta.\n", stderr);
		free(decrypted);

	}

	k -= sizeof(nonce);

	return result;

}

int get_userid(sqlite3 *db, const unsigned char *user) {
	sqlite3_stmt *res;
	int result = -1;
	char *sql = "SELECT _id FROM users WHERE user = ?";

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "No se pudo ejecutar la sentencia para obtener el identificador de usuario: %s\n",
			sqlite3_errmsg(db));
		result = -2;

	} else
		sqlite3_bind_blob(res, 1, user, HASH_SIZE, SQLITE_STATIC);

	int step = sqlite3_step(res);
	if (step == SQLITE_ROW)
		result = sqlite3_column_int(res, 0);
	else
		fprintf(stderr, "No se pudo obtener el identificador del usuario '%s': %s\n",
			user, sqlite3_errmsg(db));

	sqlite3_finalize(res);

	return result;

}

bool check_key(sqlite3 *db, const unsigned char *u, const unsigned char *k,
			   const unsigned char *p, int key_type) {
	int userid = get_userid(db, u);
	
	if (userid < 0)
		return false;

	char *passwd_hash = get_passwd_hash(db, userid);
	if (passwd_hash == NULL)
		return false;

	if (argon2id_verify(passwd_hash, p, 32) != ARGON2_OK) {
		fputs("Contraseña incorrecta.\n", stderr);
		free(passwd_hash);

		return false;

	}

	unsigned char *key = decrypt_key(k, p, key_type);
	if (key == NULL) {
		free(passwd_hash);
		return false;

	}

	free(key);
	free(passwd_hash);

	return true;

}

char *argon2_mini(const unsigned char *p) {
	return argon2_generate(p, 32, DEFAULT_ARGON2_HASHLEN, DEFAULT_ARGON2_SALTLEN, DEFAULT_ARGON2_T_COST, 
		DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_ENCODED_LEN);

}

int get_keysize(int key_type, bool hex) {
	if (hex)
		if (key_type == BOX_PUBLIC_KEY)
			return PUBLICKEY_SIZE_HEX_ID;
		else if (key_type == BOX_SECRET_KEY)
			return SECRETKEY_SIZE_HEX_ID;
		else if (key_type == BOX_VERIFY_KEY)
			return VERIFYKEY_SIZE_HEX_ID;
		else if (key_type == BOX_SIGN_KEY)
			return SIGNKEY_SIZE_HEX_ID;
		else
			return -1;
	else
		if (key_type == BOX_PUBLIC_KEY)
			return PUBLICKEY_SIZE_BIN_ID;
		else if (key_type == BOX_SECRET_KEY)
			return SECRETKEY_SIZE_BIN_ID;
		else if (key_type == BOX_VERIFY_KEY)
			return VERIFYKEY_SIZE_BIN_ID;
		else if (key_type == BOX_SIGN_KEY)
			return SIGNKEY_SIZE_BIN_ID;
		else
			return -1;
}

void _warning_user_exists(int c, const char *user) {
	if (c == 1)
		fprintf(stderr, "El usuario '%s' ya existe.\n", user);
	else
		fprintf(stderr, "El usuario '%s' no existe.\n", user);

}

int is_user_exists(sqlite3 *db, void *user,
				   bool convert, int type) {
	char *sql;
	if (type == TABLE_USERS)
		sql = "SELECT COUNT() FROM users WHERE user = ? LIMIT 1";
	else if (type == TABLE_CREDENTIALS)
		sql = "SELECT COUNT() FROM credentials WHERE userid = ? LIMIT 1";
	else {
		fputs("No es posible saber a cuál tabla se requiere acceder.\n", stderr);
		return -1;

	}

	int result = 0;
	sqlite3_stmt *res;
	unsigned char *user_hash;

	if (convert)
		user_hash = hash_sha3_224(user, -1);
	else
		user_hash = user;

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK) {
		if (type == TABLE_USERS)
			sqlite3_bind_blob(res, 1, (unsigned char *)user_hash, HASH_SIZE, SQLITE_STATIC);
		else {
			int *userid = (int *)user;
			sqlite3_bind_int(res, 1, *userid);

		}
	} else {
		fprintf(stderr, "No se puede saber si el usuario ya existe o no: %s\n",
			sqlite3_errmsg(db));
		result = -1;

	}

	int step = sqlite3_step(res);
	if (step == SQLITE_ROW)
		if (sqlite3_column_int(res, 0) > 0)
			result = 1;

	sqlite3_finalize(res);
	
	if (convert)
		free(user_hash);

	return result;

}

void generate_keypair(sqlite3 *db, const char *user, const unsigned char *passwd) {
	if (is_user_exists(db, user, true, TABLE_USERS) == 1) {
		_warning_user_exists(1, user);
		return;

	}

	char *passwd_hash = argon2_mini(passwd);
	if (passwd_hash == NULL)
		return;

	unsigned char *user_hash = hash_sha3_224(user, -1);
	unsigned char publickey[crypto_kx_PUBLICKEYBYTES];
	unsigned char secretkey[crypto_kx_SECRETKEYBYTES];
	unsigned char secretkey_enc[SECRETKEY_SIZE_BIN];
	unsigned char verifykey[VERIFYKEY_SIZE_BIN];
	unsigned char signkey[crypto_sign_SECRETKEYBYTES];
	unsigned char signkey_enc[SIGNKEY_SIZE_BIN];

	unsigned char *signkey_enc_aux = signkey_enc;
	unsigned char *secretkey_enc_aux = secretkey_enc;

	unsigned char sign_nonce[crypto_secretbox_NONCEBYTES],
				  skey_nonce[crypto_secretbox_NONCEBYTES];

	char *sql = "INSERT INTO users(user, publickey, secretkey, verifykey, signkey) VALUES(?, ?, ?, ?, ?)";
	sqlite3_stmt *res = NULL;

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK) {
		crypto_kx_keypair(publickey, secretkey);
		crypto_sign_keypair(verifykey, signkey);
		verifykey[VERIFYKEY_SIZE_BIN-1] = randombytes_random();
		
		randombytes_buf(sign_nonce, sizeof(sign_nonce));
		randombytes_buf(skey_nonce, sizeof(skey_nonce));

		memcpy(secretkey_enc_aux, skey_nonce, sizeof(skey_nonce));
		secretkey_enc_aux += sizeof(skey_nonce);
		crypto_secretbox_easy(secretkey_enc_aux, secretkey, sizeof(secretkey), skey_nonce, passwd);
		secretkey_enc_aux -= sizeof(skey_nonce);

		memcpy(signkey_enc_aux, sign_nonce, sizeof(sign_nonce));
		signkey_enc_aux += sizeof(sign_nonce);
		crypto_secretbox_easy(signkey_enc_aux, signkey, sizeof(signkey), sign_nonce, passwd);
		signkey_enc_aux -= sizeof(sign_nonce);

		sqlite3_bind_blob(res, 1, user_hash, HASH_SIZE, SQLITE_STATIC);
		sqlite3_bind_blob(res, 2, publickey, sizeof(publickey), SQLITE_STATIC);
		sqlite3_bind_blob(res, 3, secretkey_enc, sizeof(secretkey_enc), SQLITE_STATIC);
		sqlite3_bind_blob(res, 4, verifykey, sizeof(verifykey), SQLITE_STATIC);
		sqlite3_bind_blob(res, 5, signkey_enc, sizeof(signkey_enc), SQLITE_STATIC);

	} else
		fprintf(stderr, "Error agregando al usuario '%s': %s\n",
			user, sqlite3_errmsg(db));

	int step = sqlite3_step(res);
	if (step == SQLITE_DONE)
		printf("Usuario '%s' agregado con éxito.\n", user);
	else
		fprintf(stderr, "No se pudo agregar el usuario '%s': %s\n", sqlite3_errmsg(db));

	sqlite3_finalize(res);
	sql = "INSERT INTO credentials(userid, password) SELECT _id, ? FROM users WHERE user = ?";

	rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, passwd_hash, -1, SQLITE_STATIC);
		sqlite3_bind_blob(res, 2, user_hash, HASH_SIZE, SQLITE_STATIC);

	} else
		fprintf(stderr, "Error ejecutando la secuencia SQL para agregar "
			"la contraseña del usuario '%s': %s\n",
			user, sqlite3_errmsg(db));

	step = sqlite3_step(res);
	if (step == SQLITE_DONE)
		printf("Contraseña del usuario '%s' agregada con éxito.\n", user);
	else
		fprintf(stderr, "Error agregando la contraseña del usuario '%s': %s\n",
				user, sqlite3_errmsg(db));

	sqlite3_finalize(res);
	free(user_hash);
	free(passwd_hash);

} 

void delete_user(sqlite3 *db, const char *user) {
	unsigned char *user_hash = hash_sha3_224(user, -1);
	if (user_hash == NULL)
		return;
	
	if (is_user_exists(db, user_hash, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, user);
		free(user_hash);
		return;

	}

	sqlite3_stmt *res;
	char *sql = "DELETE FROM credentials WHERE userid = ?";

	int userid = get_userid(db, user_hash);

	if (userid < 0) {
		free(user_hash);
		return;

	}

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK)
		sqlite3_bind_int(res, 1, userid);
	else
		fprintf(stderr, "Error ejecutando la secuencia SQL para borrar la contraseña del usuario '%s': %s\n",
			user, sqlite3_errmsg(db));

	int step = sqlite3_step(res);
	if (step != SQLITE_DONE)
		fprintf(stderr, "No se pudo borrar la contraseña el usuario '%s': %s\n",
			user, sqlite3_errmsg(db));
	else {
		sqlite3_finalize(res);
		printf("Contraseña del usuario '%s' borrada con éxito.\n", user);

		sql = "DELETE FROM users WHERE user = ?";

		rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
		if (rc == SQLITE_OK)
			sqlite3_bind_blob(res, 1, user_hash, HASH_SIZE, SQLITE_STATIC);
		else
			fprintf(stderr, "Error ejecutando la secuencia SQL para borrar al usuario '%s': %s\n",
				user, sqlite3_errmsg(db));
		
		step = sqlite3_step(res);
		if (step == SQLITE_DONE)
			printf("Usuario '%s' borrado.\n", user);
		else
			fprintf(stderr, "No se pudo borrar el usuario '%s': %s\n",
				user, sqlite3_errmsg(db));
	
	}

	sqlite3_finalize(res);
	free(user_hash);

}

unsigned char *export_key(sqlite3 *db, const char *user, int key) {
	unsigned char *digest = hash_sha3_224(user, -1);
	if (digest == NULL)
		return NULL;

	if (is_user_exists(db, digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, user);
		free(digest);
		return NULL;

	}

	unsigned char *id_content = NULL;
	unsigned char *key_content = get_key(db, digest, key);
	int key_size = get_keysize(key, false)-crypto_secretbox_NONCEBYTES;

	if (key_content != NULL) {
		int bytes = 0;

		bytes += HASH_SIZE;
		bytes += key_size;

		id_content = (unsigned char *)malloc(sizeof(unsigned char)*bytes);
		
		if (!id_content || !digest)
			fputs("No hay memoria suficiente para poder continuar "
				  "u ocurrió un error inesperado.\n", stderr);
		else {
			memcpy(id_content, digest, HASH_SIZE);
			id_content += HASH_SIZE;
			memcpy(id_content, key_content, key_size);
			id_content -= HASH_SIZE;

		}

	} else
		fputs("No se pudo obtener la clave.\n", stderr);

	free(digest);
	free(key_content);

	return id_content;

}

int import_key(sqlite3 *db, const unsigned char *user, int key,
			   const unsigned char *key_content, const unsigned char *passwd) {
	char *sql;
	int result = 0;
	int exists = is_user_exists(db, user, false, TABLE_USERS);
	sqlite3_stmt *res;
	int key_size;

	if (exists == -1)
		return -1;

	if (exists != 1 && (key == BOX_SECRET_KEY || key == BOX_SIGN_KEY)) {
		fputs("Es necesario antes agregar el usuario con su "
			"par de clave público.\n", stderr);
		return 0;

	}

	if (key == BOX_SECRET_KEY || key == BOX_SIGN_KEY)
		if (!check_key(db, user, key_content, passwd, key))
			return -1;

	if (key == BOX_PUBLIC_KEY) {
		if (exists != 1)
			sql = "INSERT INTO users(publickey, user) VALUES(?, ?)";
		else
			sql = "UPDATE users SET publickey = ? WHERE user = ?";

		key_size = PUBLICKEY_SIZE_BIN;

	} else if (key == BOX_SECRET_KEY) {
		if (exists != 1)
			sql = "INSERT INTO users(secretkey, user) VALUES(?, ?)";
		else
			sql = "UPDATE users SET secretkey = ? WHERE user = ?";

		key_size = SECRETKEY_SIZE_BIN;

	} else if (key == BOX_VERIFY_KEY) {
		if (exists != 1)
			sql = "INSERT INTO users(verifykey, user) VALUES(?, ?)";
		else
			sql = "UPDATE users SET verifykey = ? WHERE user = ?";

		key_size = VERIFYKEY_SIZE_BIN;

	} else if (key == BOX_SIGN_KEY) {
		if (exists != 1)
			sql = "INSERT INTO users(signkey, user) VALUES(?, ?)";
		else
			sql = "UPDATE users SET signkey = ? WHERE user = ?";

		key_size = SIGNKEY_SIZE_BIN;

	} else {
		fputs("No es posible determinar el tipo de clave a importar.\n", stderr);
		return -1;

	}

	int rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_blob(res, 1, key_content, key_size, SQLITE_STATIC);
		sqlite3_bind_blob(res, 2, user, HASH_SIZE, SQLITE_STATIC);

	} else {
		fprintf(stderr,
			"Error preparando la consulta SQL al importar la clave: %s\n",
			sqlite3_errmsg(db));
		result = -1;

	}

	int step = sqlite3_step(res);
	if (step == SQLITE_DONE)
		result = 1;
	else {
		fprintf(stderr,
			"Error ejecutando la consulta SQL al importar la clave: %s\n",
			sqlite3_errmsg(db));
		result = -1;

	}
	sqlite3_finalize(res);
	res = NULL;

	char *passwd_hash = NULL;
	if (passwd != NULL && (key != BOX_SECRET_KEY && key != BOX_SIGN_KEY)) {
		int userid = get_userid(db, user);
		if (userid < 0)
			return -1;

		if (is_user_exists(db, &userid, false, TABLE_CREDENTIALS) != 1)
			sql = "INSERT INTO credentials(password, userid) VALUES (?, ?)";
		else
			sql = "UPDATE credentials SET password = ? WHERE userid = ?";

		rc = sqlite3_prepare_v2(db, sql, -1, &res, NULL);
		if (rc == SQLITE_OK) {
			passwd_hash = argon2_mini(passwd);
			if (passwd_hash == NULL)
				return -1;

			sqlite3_bind_text(res, 1, passwd_hash, -1, SQLITE_STATIC);
			sqlite3_bind_int(res, 2, userid);

		} else
			fprintf(stderr, "Error ejecutando la secuencia SQL para agregar "
				"o actualizar la contraseña: %s\n", 
				sqlite3_errmsg(db));

		step = sqlite3_step(res);
		if (step == SQLITE_DONE)
			puts("Contraseña actualizada o agregada.");
		else
			fprintf(stderr, "No se pudo actualizar o agregar la contraseña: %s\n",
				sqlite3_errmsg(db));

	}

	sqlite3_finalize(res);
	free(passwd_hash);

	return result;

}

void list_keys(sqlite3 *db, char *username) {
	unsigned char *user_digest = NULL;
	if (username != NULL) {
		user_digest = hash_sha3_224(username, -1);
		if (user_digest == NULL)
			return;

		if (is_user_exists(db, user_digest, false, TABLE_USERS) != 1) {
			_warning_user_exists(0, username);
			free(user_digest);
			return;

		}

	}

	bool keys_is_available = false;
	unsigned char *user;
	unsigned char *publickey, *secretkey;
	unsigned char *verifykey, *signkey;
	unsigned char *hash_publickey, *hash_secretkey = NULL;
	unsigned char *hash_verifykey, *hash_signkey;
	int userid;

	int user_bytes;
	int publickey_bytes, secretkey_bytes;
	int signkey_bytes, verifykey_bytes;

	char user_hex[HASH_SIZE_HEX+1];
	char publickey_hex[PUBLICKEY_SIZE_HEX+1], secretkey_hex[SECRETKEY_SIZE_HEX+1];
	char verifykey_hex[VERIFYKEY_SIZE_HEX+1], signkey_hex[SIGNKEY_SIZE_HEX+1];
	char hash_publickey_hex[HASH32_SIZE_HEX+1], hash_secretkey_hex[HASH32_SIZE_HEX+1];
	char hash_verifykey_hex[HASH32_SIZE_HEX+1], hash_signkey_hex[HASH32_SIZE_HEX+1];

	sqlite3_stmt *res;

	char *sql;
	if (user_digest == NULL)
		sql = "SELECT _id, user, publickey, secretkey, verifykey, signkey FROM users";
	else
		sql = "SELECT _id, user, publickey, secretkey, verifykey, signkey FROM users WHERE user = ?";
	
	int rc = sqlite3_prepare(db, sql, -1, &res, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error preparando la consulta SQL para obtener la lista de claves: %s\n",
			sqlite3_errmsg(db));

	} else if (user_digest != NULL)
		sqlite3_bind_blob(res, 1, user_digest, HASH_SIZE, SQLITE_STATIC);

	int step;
	while ((step = sqlite3_step(res)) == SQLITE_ROW) {
		if (!keys_is_available)
			keys_is_available = true;

		userid = sqlite3_column_int(res, 0);
		user_bytes = sqlite3_column_bytes(res, 1);
		publickey_bytes = sqlite3_column_bytes(res, 2);
		secretkey_bytes = sqlite3_column_bytes(res, 3);
		verifykey_bytes = sqlite3_column_bytes(res, 4);
		signkey_bytes = sqlite3_column_bytes(res, 5);

		if (user_bytes != HASH_SIZE) {
			fprintf(stderr, "(%d) La longitud del identificador de usuario es incorrecta.\n",
				userid);
			continue;

		} else if (publickey_bytes > 0 && publickey_bytes != PUBLICKEY_SIZE_BIN) {
			fprintf(stderr, "(%d) La longitud de la clave pública es incorrecta.\n", userid);
			continue;

		} else if (secretkey_bytes > 0 && secretkey_bytes != SECRETKEY_SIZE_BIN) {
			fprintf(stderr, "(%d) La longitud de la clave secreta es incorrecta.\n", userid);
			continue;

		} else if (verifykey_bytes > 0 && verifykey_bytes != VERIFYKEY_SIZE_BIN) {
			fprintf(stderr, "(%d) La longitud de la clave de verificación es incorrecta.\n", userid);
			continue;

		} else if (signkey_bytes > 0 && signkey_bytes != SIGNKEY_SIZE_BIN) {
			fprintf(stderr, "(%d) La longitud de la clave para firmar es incorrecta.\n", userid);
			continue;

		}

		user = sqlite3_column_blob(res, 1);

		sodium_bin2hex(user_hex, sizeof(user_hex), user, HASH_SIZE);

		printf("\n");
		printf("uid    %s (ID:%d)\n", str2upper(user_hex, -1), userid);

		if (publickey_bytes > 0) {
			publickey = sqlite3_column_blob(res, 2);
			hash_publickey = hash_sha3_256(publickey, PUBLICKEY_SIZE_BIN);
			sodium_bin2hex(publickey_hex, sizeof(publickey_hex), publickey, PUBLICKEY_SIZE_BIN);
			sodium_bin2hex(hash_publickey_hex, sizeof(hash_publickey_hex), hash_publickey, HASH32_SIZE);

			printf("pub    %s\n", str2upper(publickey_hex, -1));
			printf("           [  SHA3_256::%s  ]\n", str2upper(hash_publickey_hex, -1));
		} else {
			puts("pub    [none]");
			puts("           [  SHA3_256::[none]  ]");
		}

		if (secretkey_bytes > 0) {
			secretkey = sqlite3_column_blob(res, 3);
			hash_secretkey = hash_sha3_256(secretkey, SECRETKEY_SIZE_BIN);
			sodium_bin2hex(secretkey_hex, sizeof(secretkey_hex), secretkey, SECRETKEY_SIZE_BIN);
			sodium_bin2hex(hash_secretkey_hex, sizeof(hash_secretkey_hex), hash_secretkey, HASH32_SIZE);

			printf("sec    %s\n", str2upper(secretkey_hex, -1));
			printf("           [  SHA3_256::%s  ]\n", str2upper(hash_secretkey_hex, -1));
		} else {
			puts("sec    [none]");
			puts("           [  SHA3_256::[none]  ]");
		}

		if (verifykey_bytes > 0) {
			verifykey = sqlite3_column_blob(res, 4);
			hash_verifykey = hash_sha3_256(verifykey, VERIFYKEY_SIZE_BIN);
			sodium_bin2hex(verifykey_hex, sizeof(verifykey_hex), verifykey, VERIFYKEY_SIZE_BIN);
			sodium_bin2hex(hash_verifykey_hex, sizeof(hash_verifykey_hex), hash_verifykey, HASH32_SIZE);

			printf("vef    %s\n", str2upper(verifykey_hex, -1));
			printf("           [  SHA3_256::%s  ]\n", str2upper(hash_verifykey_hex, -1));

		} else {
			puts("vef    [none]");
			puts("           [  SHA3_256::[none]  ]");
		}
		
		if (signkey_bytes > 0) {
			signkey = sqlite3_column_blob(res, 5);
			hash_signkey = hash_sha3_256(signkey, SIGNKEY_SIZE_BIN);
			sodium_bin2hex(signkey_hex, sizeof(signkey_hex), signkey, SIGNKEY_SIZE_BIN);
			sodium_bin2hex(hash_signkey_hex, sizeof(hash_signkey_hex), hash_signkey, HASH32_SIZE);

			printf("sig    %s\n", str2upper(signkey_hex, -1));
			printf("           [  SHA3_256::%s  ]\n", str2upper(hash_signkey_hex, -1));

		} else {
			puts("sig    [none]");
			puts("           [  SHA3_256::[none]  ]");
		}

		free(hash_publickey);
		free(hash_secretkey);
		free(hash_verifykey);
		free(hash_signkey);

		hash_publickey = NULL;
		hash_secretkey = NULL;
		hash_verifykey = NULL;
		hash_signkey = NULL;

		putchar('\n');

	}

	if (!keys_is_available)
		fputs("Nada que mostrar.\n", stderr);

	if (step != SQLITE_DONE)
		fprintf(stderr, "Ocurrió un error obteniendo las claves: %s\n",
			sqlite3_errmsg(db));

	sqlite3_finalize(res);
	free(user_digest);

}

void encrypt(FILE *i, FILE *o, long block_size,
			 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char *buf_in = (unsigned char *)malloc(sizeof(unsigned char)*block_size);
    unsigned char *buf_out = (unsigned char *)malloc(sizeof(unsigned char)*block_size + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;
	
    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, sizeof(unsigned char), sizeof(header), o);
    do {
        rlen = fread(buf_in, sizeof(unsigned char), sizeof(unsigned char)*block_size, i);
        eof = feof(i);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, sizeof(unsigned char), (size_t)out_len, o);
    } while (!eof);

	free(buf_in);
	free(buf_out);

}

void decrypt(FILE *i, FILE *o, long block_size,
			 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
	unsigned char *buf_in = (unsigned char *)malloc(sizeof(unsigned char)*block_size + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned char *buf_out = (unsigned char *)malloc(sizeof(unsigned char)*block_size);
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;

    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char  tag;

    fread(header, sizeof(unsigned char), sizeof(header), i);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0)
		fputs("Encabezado incompleto.\n", stderr);
	else {
		do {
			rlen = fread(buf_in, sizeof(unsigned char),
						 (sizeof(unsigned char)*block_size + crypto_secretstream_xchacha20poly1305_ABYTES), i);
			eof = feof(i);
			if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
														   buf_in, rlen, NULL, 0) != 0) {
				fputs("¡Pedazo del contenido corrupto!\n", stderr);
				break;
			}

			if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
				fputs("Fin de archivo prematuro.\n", stderr);
				break;
			}
			fwrite(buf_out, sizeof(unsigned char), (size_t)out_len, o);
		} while (!eof);

	}

	free(buf_in);
	free(buf_out);

}

void aencrypt(sqlite3 *db, FILE *i, FILE *o, long block_size,
			  char *opt_to, char *opt_from, unsigned char *p) {
	unsigned char *opt_to_digest = hash_sha3_224(opt_to, -1);;
	unsigned char *opt_from_digest = hash_sha3_224(opt_from, -1);;

	if (!opt_to_digest || !opt_from_digest) {
		fputs("¡No se pueden obtener los identificadores de usuarios!\n", stderr);
		return;

	}

	if (is_user_exists(db, opt_to_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, opt_to);
		return;

	}
	
	if (is_user_exists(db, opt_from_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, opt_from);
		return;

	}

	unsigned char tx[crypto_kx_SESSIONKEYBYTES];
	unsigned char *pk, *sk_enc, *sk, *dst_pk;

	pk = get_key(db, opt_from_digest, BOX_PUBLIC_KEY);
	if (!pk) {
		multiple_free(2, opt_to_digest, opt_from_digest);
		return;

	}

	dst_pk = get_key(db, opt_to_digest, BOX_PUBLIC_KEY);
	if (!dst_pk) {
		multiple_free(3, pk, opt_to_digest, opt_from_digest);
		return;

	}

	sk_enc = get_key(db, opt_from_digest, BOX_SECRET_KEY);
	if (!sk_enc) {
		multiple_free(4, pk, dst_pk, opt_to_digest, opt_from_digest);
		return;

	}

	sk = decrypt_key(sk_enc, p, BOX_SECRET_KEY);
	if (sk == NULL) {
		multiple_free(5, pk, dst_pk, sk_enc,
			opt_to_digest, opt_from_digest);
		return;

	}

	if (crypto_kx_server_session_keys(NULL, tx,
                                  pk, sk, dst_pk) != 0) {
		fputs("¡Clave pública del remitente sospechosa!\n", stderr);
		multiple_free(6, pk, dst_pk, sk_enc, sk,
			opt_from_digest, opt_to_digest);
		return;
	}

	encrypt(i, o, block_size, tx);

	multiple_free(6, pk, dst_pk, sk_enc, sk,
		opt_from_digest, opt_to_digest);

}

void adecrypt(sqlite3 *db, FILE *i, FILE *o, long block_size,
			  char *opt_to, char *opt_from, unsigned char *p) {
	unsigned char *opt_to_digest = hash_sha3_224(opt_to, -1);
	unsigned char *opt_from_digest = hash_sha3_224(opt_from, -1);

	if (!opt_to_digest || !opt_from_digest) {
		fputs("¡No se pueden obtener los identificadores de usuarios!\n", stderr);
		return;

	}

	if (is_user_exists(db, opt_to_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, opt_to);
		return;

	}
	
	if (is_user_exists(db, opt_from_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, opt_from);
		return;

	}

	unsigned char rx[crypto_kx_SESSIONKEYBYTES];
	unsigned char *pk, *sk_enc, *sk, *dst_pk;
	
	pk = get_key(db, opt_to_digest, BOX_PUBLIC_KEY);
	if (!pk) {
		multiple_free(2, opt_to_digest, opt_from_digest);
		return;

	}

	dst_pk = get_key(db, opt_from_digest, BOX_PUBLIC_KEY);
	if (!dst_pk) {
		multiple_free(3, pk, opt_to_digest, opt_from_digest);
		return;

	}

	sk_enc = get_key(db, opt_to_digest, BOX_SECRET_KEY);
	if (!sk_enc) {
		multiple_free(4, pk, dst_pk, opt_to_digest, opt_from_digest);
		return;

	}

	sk = decrypt_key(sk_enc, p, BOX_SECRET_KEY);
	if (sk == NULL) {
		multiple_free(5, pk, dst_pk, sk_enc,
			opt_to_digest, opt_from_digest);
		return;

	}

	if (crypto_kx_client_session_keys(rx, NULL,
                                  pk, sk, dst_pk) != 0) {
		fputs("¡Clave pública del remitente sospechosa!\n", stderr);
		multiple_free(6, pk, dst_pk, sk_enc, sk,
			opt_from_digest, opt_to_digest);
		return;
	}

	decrypt(i, o, block_size, rx);

	multiple_free(6, pk, dst_pk, sk_enc, sk,
		opt_from_digest, opt_to_digest);
	
}

unsigned char *sign(sqlite3 *db, FILE *i, FILE *o, long block_size,
		  char *username, unsigned char *passwd) {
	unsigned char *user_digest = hash_sha3_224(username, -1);
	if (user_digest == NULL)
		return NULL;

	if (is_user_exists(db, user_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, username);
		free(user_digest);
		return NULL;

	}

	unsigned char *signkey_enc = get_key(db, user_digest, BOX_SIGN_KEY);
	if (signkey_enc == NULL) {
		free(user_digest);
		return NULL;

	}
	
	unsigned char *signkey = decrypt_key(signkey_enc, passwd, BOX_SIGN_KEY);
	if (signkey == NULL) {
		multiple_free(2, user_digest, signkey_enc);
		return NULL;

	}

	unsigned char *buff = (unsigned char *)malloc(sizeof(unsigned char)*block_size);
	unsigned char *sig = (unsigned char *)malloc(sizeof(unsigned char)*crypto_sign_BYTES);
	if ((buff == NULL) || (sig == NULL)) {
		fputs("¡Parece que no hay más memoria u ocurrió un error inesperado!\n", stderr);
		multiple_free(5, user_digest, signkey_enc, signkey, buff, sig);
		return NULL;

	}

	size_t size;

	crypto_sign_state state;
	crypto_sign_init(&state);

	while ((size = fread(buff, sizeof(unsigned char), sizeof(unsigned char)*block_size, i)) > 0)
		crypto_sign_update(&state, buff, size);

	crypto_sign_final_create(&state, sig, NULL, signkey);

	multiple_free(4, user_digest, signkey_enc, signkey, buff);

	return sig;

}

void verify(sqlite3 *db, FILE *i, long block_size, char *username,
			unsigned char *sig_data) {
	unsigned char *user_digest = hash_sha3_224(username, -1);
	if (user_digest == NULL)
		return;

	if (is_user_exists(db, user_digest, false, TABLE_USERS) != 1) {
		_warning_user_exists(0, username);
		free(user_digest);
		return;

	}

	unsigned char *verifykey = get_key(db, user_digest, BOX_VERIFY_KEY);
	if (verifykey == NULL) {
		free(user_digest);
		return;

	}

	unsigned char *buff = (unsigned char *)malloc(sizeof(unsigned char)*block_size);
	if (buff == NULL) {
		multiple_free(2, user_digest, verifykey);
		return;

	}

	size_t size;

	crypto_sign_state state;
	crypto_sign_init(&state);

	while ((size = fread(buff, sizeof(unsigned char), sizeof(unsigned char)*block_size, i)) > 0)
		crypto_sign_update(&state, buff, size);

	if (crypto_sign_final_verify(&state, sig_data, verifykey) == 0)
		puts("OK");
	else
		puts("FAIL");

	multiple_free(3, buff, user_digest, verifykey);

}
