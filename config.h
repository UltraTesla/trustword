#ifndef _CONFIG_H
#	define _CONFIG_H
#	define CONFIG_FILE                "config/trustword.sc"
#	define DEFAULT_DATABASE           "files/trustword.db"
#	define DEFAULT_USER               "user"
#	define DEFAULT_SQL_FILE           "config/trustword.sql"
#	define DEFAULT_MAX_SQL_SIZE       1024 /* Cero o menos es infinito */
#	define DEFAULT_OUT_STREAM         stdout
#	define DEFAULT_IMPORT_STREAM      stdin
#	define DEFAULT_GENERAL_STREAM     stdin
#	define DEFAULT_SIGN_FILE          stdin
#	define DEFAULT_BLOCK_SIZE         (1 << 16)
/* Argon2 */
#	define DEFAULT_ARGON2_HASHLEN     16
#	define DEFAULT_ARGON2_SALTLEN     16
#	define DEFAULT_ARGON2_T_COST      2
#	define DEFAULT_ARGON2_M_COST      102400
#	define DEFAULT_ARGON2_PARALLELISM 8
#	define DEFAULT_ARGON2_ENCODED_LEN (1 << 7)
#endif
