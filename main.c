#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <errno.h>
#include "strupper.h"
#include "opts.h"
#include "version.h"
#include "box.h"
#include "config.h"
#include "sp_parser.h"
#include "misc.h"
#include "read_all.h"
#include "trim.h"
#include "hash.h"

bool gflag;
bool tflag;
bool fflag;
bool cflag;
bool dflag;
bool eflag;
bool Eflag;
bool oflag;
bool iflag;
bool Iflag;
bool lflag;
bool pflag;
bool hflag;
bool kflag;
bool Kflag;
bool Cflag;
bool Dflag;
bool zflag;
bool Zflag;
bool uflag;
bool Uflag;
bool sflag;
bool vflag;
bool Vflag;
bool yflag;
bool Yflag, overwrite;
bool Nflag;

char *opt_configuration_file;
char *opt_to;
char *opt_from;
char *opt_sql_content;
char *opt_output_file;
char *opt_import_file;
unsigned char *opt_password;
char *opt_general_file;
char *opt_to_verify;
char *lineptr;
unsigned char *key;
char *key_hex;
unsigned char *key_pass;
unsigned char *key_enc;
char *opt_hash;
unsigned char *identity_ptr_dec;
unsigned char *opt_new_password;

FILE *out_stream;
FILE *sql_stream;
FILE *import_file;
FILE *general_file;
FILE *sign_file;

sqlite3 *db;

struct configuration {
	char *database;
	char *default_user;
	char *sql_file;
	long block_size;

};

typedef struct configuration configuration;
configuration config;

#define PTR_FILE 1
#define PTR_VOID 2

struct ptrNode {
	void *ptr;
	int type;
	struct ptrNode *next;

};

typedef struct ptrNode ptrNode;
ptrNode *root_node;

int init_parser(const char *key, const char *value, void *conf_dict);
void set_defaults_values();
void free_parser();
void release_function();
void check_for_memory(void *ptr);
FILE *fopen_secure(const char *pathname, const char *mode);
void *insert_pointer(void *ptr, int type);
static void quit();

int main(int argc, char **argv) {
	int opt, option_index = 0;
	int rc;
	int key_type = 0;

	if (sodium_init() == -1) {
		fputs("No se ha podido inicializar 'libsodium', por lo tanto, "
		      "no es seguro usarla en este momento", stderr);
		return EXIT_FAILURE;

	}

	/*
	 * Registra la función que liberará los datos del montón,
	 * archivos abiertos (que no sean stdin, stderr o stdout)
	 * y liberará la configuración.
	 */
	atexit(release_function);

	while ((opt = getopt_long(argc, argv, short_opts,
							  long_options, &option_index)) != -1) {
		switch (opt) {
			case 'H':
				show_help();
				quit();

			case 'x':
				show_examples();
				quit();

			case 'n':
				show_version();
				quit();

			case 'g':
				gflag = true;
				break;

			case 't':
				tflag = true;
				opt_to = insert_pointer(strdup(optarg), PTR_VOID);
				check_for_memory(opt_to);
				break;

			case 'f':
				fflag = true;
				opt_from = insert_pointer(strdup(optarg), PTR_VOID);
				check_for_memory(opt_from);
				break;

			case 'c':
				cflag = true;
				opt_configuration_file = insert_pointer(strdup(optarg), PTR_VOID);
				check_for_memory(opt_configuration_file);
				break;

			case 'd':
				dflag = true;
				break;

			case 'e':
				eflag = true;
				key_type = BOX_PUBLIC_KEY;
				break;

			case 'E':
				Eflag = true;
				key_type = BOX_SECRET_KEY;
				break;

			case 'z':
				zflag = true;
				key_type = BOX_VERIFY_KEY;
				break;

			case 'Z':
				Zflag = true;
				key_type = BOX_SIGN_KEY;
				break;

			case 'o':
				oflag = true;
				opt_output_file = insert_pointer(strdup(optarg), PTR_VOID);
				check_for_memory(opt_output_file);
				break;

			case 'i':
			case 'I':
			case 'u':
			case 'U':
				if (strcmp(optarg, "-") != 0) {
					opt_import_file = insert_pointer(strdup(optarg), PTR_VOID);
					check_for_memory(opt_import_file);
				}

				if (opt == 'i') {
					iflag = true;
					key_type = BOX_PUBLIC_KEY;
				} else if (opt == 'I') {
					Iflag = true;
					key_type = BOX_SECRET_KEY;
				} else if (opt == 'u') {
					uflag = true;
					key_type = BOX_VERIFY_KEY;
				} else {
					Uflag = true;
					key_type = BOX_SIGN_KEY;
				}

				break;

			case 'l':
				lflag = true;
				break;

			case 'p':
				pflag = true;
				opt_password = insert_pointer(hash_sha3_256(optarg, -1), PTR_VOID);
				check_for_memory(opt_password);
				break;

			case 'h':
				hflag = true;
				break;

			case 'k':
			case 'K':
			case 'C':
			case 'D':
			case 's':
			case 'v':
				if (strcmp(optarg, "-") != 0) {
					opt_general_file = insert_pointer(strdup(optarg), PTR_VOID);
					check_for_memory(opt_general_file);
				}
				
				if (opt == 'k')
					kflag = true;
				 else if (opt == 'K')
					Kflag = true;
				else if (opt == 'D')
					Dflag = true;
				else if (opt == 'C')
					Cflag = true;
				else if (opt == 's')
					sflag = true;
				else
					vflag = true;
				break;

			case 'V':
				if (strcmp(optarg, "-") != 0) {
					opt_to_verify = insert_pointer(strdup(optarg), PTR_VOID);
					check_for_memory(opt_to_verify);
				
				}
				Vflag = true;
				break;

			case 'y':
				opt_hash = insert_pointer(strdup(optarg), PTR_VOID);
				check_for_memory(opt_hash);
				if (strlen(opt_hash) != HASH32_SIZE_HEX) {
					fputs("La longitud de la huella dactilar no es correcta.\n", stderr);
					return EXIT_FAILURE;
				}
				yflag = true;
				break;

			case 'Y':
				overwrite = Yflag = true;
				break;

			case 'N':
				Nflag = true;
				opt_new_password = insert_pointer(hash_sha3_256(optarg, -1), PTR_VOID);
				check_for_memory(opt_new_password);
				break;
			
			default:
				show_error();
				return EXIT_FAILURE;

		}

	}

	if (!yflag && (iflag || Iflag || uflag || Uflag)) {
		fputs("Es necesario definir la huella dactilar "
              "para poder importar una clave.\n", stderr);
		return EXIT_FAILURE;

	}

	if ((vflag && !Vflag) || (!vflag && Vflag)) {
		fputs("Es necesario definir el archivo y la firma a verificar.\n", stderr);
		return EXIT_FAILURE;

	}

	if (!tflag && (Cflag || Dflag)) {
		fputs("Es necesario definir el destinatario.\n", stderr);
		return EXIT_FAILURE;

	}

	if (!pflag && gflag) {
		fputs("Es necesario definir una contraseña para "
			"poder generar el par de claves.\n", stderr);
		return EXIT_FAILURE;

	}

	int max_key_size;
	if (kflag)
		max_key_size = crypto_secretstream_xchacha20poly1305_KEYBYTES;
	else
		max_key_size = crypto_secretbox_KEYBYTES;

	if (!pflag && (Iflag || Uflag)) {
		fputs("Es necesario definir una contraseña para "
			"poder importar una clave privada.\n", stderr);
		return EXIT_FAILURE;

	}

	if (!pflag && (Kflag || kflag || Cflag || Dflag || sflag)) {
		fputs("Es necesario definir una contraseña para "
			"poder cifrar, descifrar o firmar.\n", stderr);
		return EXIT_FAILURE;

	}
	
	char *file_config = CONFIG_FILE;
	if (cflag)
		file_config = opt_configuration_file;

	general_file = DEFAULT_GENERAL_STREAM;
	if (opt_general_file != NULL && (vflag || sflag || kflag || Kflag || Cflag || Dflag))
		general_file = insert_pointer(fopen_secure(opt_general_file, "rb"), PTR_FILE);

	sign_file = DEFAULT_SIGN_FILE;
	if (opt_to_verify != NULL && (vflag && Vflag))
		sign_file = insert_pointer(fopen_secure(opt_to_verify, "rb"), PTR_FILE);

	import_file = DEFAULT_IMPORT_STREAM;
	if (opt_import_file != NULL && (iflag || Iflag || uflag || Uflag))
		import_file = insert_pointer(fopen_secure(opt_import_file, "rb"), PTR_FILE);

	out_stream = DEFAULT_OUT_STREAM;
	if (oflag)
		out_stream = insert_pointer(fopen_secure(opt_output_file, "wb"), PTR_FILE);

	errno = 0;
	if ((rc = simple_read_config(file_config, init_parser, NULL)) != 0) {
		if (errno != 0) {
			perror("Advertencia de simple_read_config");
			rc = errno;
		} else
			fprintf(stderr,
				"No se pudo interpretar correctamente el archivo "
				"de configuración. Código de salida: %d\n", rc);

	}

	/* En caso de no haberse ajustado anteriormente */
	set_defaults_values();

	char *from_email = config.default_user;
	if (fflag)
		from_email = opt_from;

	rc = sqlite3_open(config.database, &db);

	if (rc != SQLITE_OK) {
		fprintf(stderr,
			"No se pudo establecer una conexión con la base de datos: %s\n",
			sqlite3_errmsg(db));

		return EXIT_FAILURE;

	}

	sql_stream = insert_pointer(fopen_secure(config.sql_file, "rb"), PTR_FILE);
	if (!sql_stream) {
		perror("Error abriendo el archivo SQL inicial");

		return errno;

	}
	
	/* Se ejecuta el fichero SQL inicial  */
	opt_sql_content = insert_pointer(read_all(sql_stream, DEFAULT_MAX_SQL_SIZE), PTR_VOID);
	check_for_memory(opt_sql_content);

	char *errmsg = NULL;
	rc = sqlite3_exec(db, opt_sql_content, NULL, NULL, &errmsg);

	if (rc != SQLITE_OK) {
		fprintf(stderr,
			"Ocurrió un error ejecutando el archivo SQL inicial: %s\n",
			errmsg);
		sqlite3_free(errmsg);

		return EXIT_FAILURE;

	}

	if (gflag)
		return generate_keypair(db, from_email, opt_password);
	else if (dflag)
		return delete_user(db, from_email);
	else if (eflag || Eflag || zflag || Zflag) {
		unsigned char key_nonce[crypto_secretbox_NONCEBYTES];
		randombytes_buf(key_nonce, sizeof(key_nonce));
		int real_key_size = get_keysize(key_type, false);
		int key_size = crypto_secretbox_MACBYTES+sizeof(key_nonce)+real_key_size;

		key = insert_pointer(export_key(db, from_email, key_type), PTR_VOID);

		if (!key) {
			fputs("No se pudo exportar la clave.\n", stderr);
			return EXIT_FAILURE;

		}

		key += HASH_SIZE;
		key_pass = insert_pointer(hash_sha3_256(key, real_key_size-HASH_SIZE), PTR_VOID);
		key -= HASH_SIZE;
		key_enc = insert_pointer((unsigned char *)malloc(key_size), PTR_VOID);
		memcpy(key_enc, key_nonce, sizeof(key_nonce));
		key_enc += sizeof(key_nonce);
		crypto_secretbox_easy(key_enc, key, real_key_size, key_nonce, key_pass);
		key_enc -= sizeof(key_nonce);

		if (hflag && out_stream == DEFAULT_OUT_STREAM) {
			key_hex = insert_pointer((char *)malloc(key_size*2+1), PTR_VOID);
			sodium_bin2hex(key_hex, key_size*2+1, key_enc, key_size);

			fprintf(out_stream, "%s\n", str2upper(key_hex, -1));

		} else
			fwrite(key_enc, sizeof(unsigned char), key_size, out_stream);

	} else if (iflag || Iflag || uflag || Uflag) {
		unsigned char identity[SIGNKEY_SIZE_HEX_ID_MAC];
		unsigned char username[HASH_SIZE];
		unsigned char bin_buff[sizeof(identity)/2];
		unsigned char key[SIGNKEY_SIZE_BIN];
		unsigned char *identity_ptr;
		unsigned char hash2key[HASH32_SIZE];
		unsigned char key_nonce[crypto_secretbox_NONCEBYTES];
		size_t key_size = 0;

		if (sodium_hex2bin(hash2key, sizeof(hash2key), opt_hash, strlen(opt_hash),
			NULL, NULL, NULL) != 0) {
			fputs("No se pudo descodificar la huella dactilar.\n", stderr);
			return EXIT_FAILURE;

		}

		if (!hflag) {
			key_size = crypto_secretbox_MACBYTES+sizeof(key_nonce)+get_keysize(key_type, false);
			key_size = fread(identity, sizeof(unsigned char), key_size, import_file);

			if ((iflag && key_size != PUBLICKEY_SIZE_BIN_ID_MAC) ||
				(Iflag && key_size != SECRETKEY_SIZE_BIN_ID_MAC) ||
				(uflag && key_size != VERIFYKEY_SIZE_BIN_ID_MAC) ||
				(Uflag && key_size != SIGNKEY_SIZE_BIN_ID_MAC)) {
				fputs("(BIN) Longitud de la clave incorrecta.\n", stderr);
				return EXIT_FAILURE;
			} else
				identity_ptr = identity;

		} else {
			lineptr = NULL;
			key_size = getline(&lineptr, &key_size, import_file);
			insert_pointer(lineptr, PTR_VOID);

			trim(lineptr);
			key_size = strlen(lineptr);

			if ((iflag && key_size != PUBLICKEY_SIZE_HEX_ID_MAC) ||
				(Iflag && key_size != SECRETKEY_SIZE_HEX_ID_MAC) ||
				(uflag && key_size != VERIFYKEY_SIZE_HEX_ID_MAC) ||
				(Uflag && key_size != SIGNKEY_SIZE_HEX_ID_MAC)) {
				fputs("(HEX) Longitud de la clave incorrecta.\n", stderr);
				return EXIT_FAILURE;
			} else
				identity_ptr = bin_buff;

			if (sodium_hex2bin(bin_buff, sizeof(bin_buff), lineptr, key_size,
				NULL, NULL, NULL) != 0) {
				fputs("Error descodificando el identificador.\n", stderr);
				return EXIT_FAILURE;

			}

			key_size /= 2;

		}

		memcpy(key_nonce, identity_ptr, sizeof(key_nonce));
		identity_ptr += sizeof(key_nonce);
		key_size -= sizeof(key_nonce);
		identity_ptr_dec = (unsigned char *)malloc(key_size);
		if (crypto_secretbox_open_easy(identity_ptr_dec, identity_ptr, key_size, key_nonce, hash2key) != 0) {
			fputs("No se pudo importar la clave. ¡La huella dactilar debe ser la correcta!\n", stderr);
			return EXIT_FAILURE;

		}
		identity_ptr = identity_ptr_dec;

		memcpy(username, identity_ptr, sizeof(username));
		identity_ptr += sizeof(username);
		memcpy(key, identity_ptr, get_keysize(key_type, false)-sizeof(username));
		identity_ptr -= sizeof(username);

		rc = import_key(db, username, key_type, key, opt_password, opt_new_password, overwrite);
		if (rc == 1)
			puts("Clave importada con éxito.");
		else if (rc == 0) {
			fputs("No se pudo importar la clave.\n", stderr);
			return EXIT_FAILURE;
		} else {
			fputs("Ocurrió un error al importar la clave.\n", stderr);
			return EXIT_FAILURE;
		}

	} else if (lflag)
		list_keys(db, opt_from);
	else if (kflag)
		encrypt(general_file, out_stream, config.block_size,
				opt_password);
	else if (Kflag)
		decrypt(general_file, out_stream, config.block_size,
				opt_password);
	else if (Cflag)
		return aencrypt(db, general_file, out_stream, config.block_size,
				 opt_to, from_email, opt_password);
	else if (Dflag)
		return adecrypt(db, general_file, out_stream, config.block_size,
				 opt_to, from_email, opt_password);
	else if (sflag) {
		unsigned char *sig_data = insert_pointer(sign(db, general_file, out_stream, config.block_size,
									   from_email, opt_password), PTR_VOID);

		if (sig_data == NULL)
			return EXIT_FAILURE;

		if (hflag) {
			char hex_buff[129];
			sodium_bin2hex(hex_buff, sizeof(hex_buff), sig_data, 64);
			printf("%s\n", str2upper(hex_buff, -1));

		} else
			if (fwrite(sig_data, sizeof(unsigned char), 64, out_stream) <= 0)
				fputs("Ocurrió un error escribiendo el resultado de la firma.\n", stderr);

	} else if (vflag && Vflag) {
		int sig_size;
		unsigned char buff[128];
		unsigned char sig_data[crypto_sign_BYTES];
		size_t size;

		if (hflag)
			sig_size = 128;
		else
			sig_size = 64;

		if ((size = fread(buff, sizeof(unsigned char), sig_size, sign_file)) != sig_size) {
			fputs("La longitud de la firma es incorrecta.\n", stderr);
			return EXIT_FAILURE;

		}

		if (hflag) {
			if (sodium_hex2bin(sig_data, sizeof(sig_data), buff, sig_size,
				NULL, NULL, NULL) != 0) {
				fputs("Error descodificando la firma.\n", stderr);
				return EXIT_FAILURE;

			}

		} else
			memcpy(sig_data, buff, 64);

		return verify(db, general_file, config.block_size,
			   from_email, sig_data);
	} else
		show_help();

	return EXIT_SUCCESS;

}

void check_for_memory(void *ptr) {
	if (ptr == NULL) {
		fputs("No hay suficiente memoria para continuar.\n", stderr);
		quit();

	}

}

void set_defaults_values() {
	if (IS_NULL(config.database)) {
		config.database = insert_pointer(strdup(DEFAULT_DATABASE), PTR_VOID);
		check_for_memory(config.database);

	}

	if (IS_NULL(config.default_user)) {
		config.default_user = insert_pointer(strdup(DEFAULT_USER), PTR_VOID);
		check_for_memory(config.default_user);

	}

	if (IS_NULL(config.sql_file)) {
		config.sql_file = insert_pointer(strdup(DEFAULT_SQL_FILE), PTR_VOID);
		check_for_memory(config.sql_file);

	}

	if (config.block_size <= 0)
		config.block_size = DEFAULT_BLOCK_SIZE;

}

int init_parser(const char *key, const char *value, void *conf_dict) {
	if (IS_EQUAL(key, "database")) {
		config.database = insert_pointer(strdup(value), PTR_VOID);
		check_for_memory(config.database);
	} else if (IS_EQUAL(key, "default_user")) {
		config.default_user = insert_pointer(strdup(value), PTR_VOID);
		check_for_memory(config.default_user);
	} else if (IS_EQUAL(key, "sql_file")) {
		config.sql_file = insert_pointer(strdup(value), PTR_VOID);
		check_for_memory(config.sql_file);
	} else if (IS_EQUAL(key, "block_size")) {
		char *endptr = NULL;
		long block_size = strtol(value, &endptr, 10);

		if ((errno == ERANGE && (block_size == LONG_MAX || block_size == LONG_MIN)) \
			|| (errno != 0 && block_size == 0)) {
			perror("strtol");
			return -1;
		}

		config.block_size = block_size;

	}

	return 0;

}

void release_function() {
	ptrNode *aux = root_node;
	void *value;
	while (aux != NULL) {
		root_node = aux->next;
		value = aux->ptr;

		if (ISN_NULL(value)) {
			if (aux->type == PTR_FILE)
				if (value != stdout && \
					value != stdin  && \
					value != stderr)
					fclose(value);
			else if (aux->type == PTR_VOID)
				free(value);
			else
				; /* Error */

		}

		free(aux);
		aux = root_node;

	}

	if (ISN_NULL(db))
		sqlite3_close(db);

}

FILE *fopen_secure(const char *pathname, const char *mode) {
	FILE *f = fopen(pathname, mode);

	if (!f) {
		fprintf(stderr, "Ocurrió un error abriendo '%s': %s\n",
			pathname, strerror(errno));
		exit(errno);

	}

	return f;

}

void *insert_pointer(void *ptr, int type) {
	ptrNode *new_node = (ptrNode *)malloc(sizeof(ptrNode));
	check_for_memory(new_node);
	new_node->ptr = ptr;
	new_node->type = type;
	new_node->next = root_node;
	root_node = new_node;

	return ptr;

}

static void quit() {
	exit(0);

}
