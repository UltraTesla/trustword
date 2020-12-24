#include <getopt.h>

static struct option long_options[] = {
	{ "to",                required_argument, NULL, 't' },
	{ "from",              required_argument, NULL, 'f' },
	{ "configuration",     required_argument, NULL, 'c' },
	{ "generate-keypair",  no_argument,       NULL, 'g' },
	{ "user",              required_argument, NULL, 'f' },
	{ "delete",            no_argument,       NULL, 'd' },
	{ "export",            no_argument,       NULL, 'e' },
	{ "export-secret-key", no_argument,       NULL, 'E' },
	{ "import",            required_argument, NULL, 'i' },
	{ "import-secret-key", required_argument, NULL, 'I' },
	{ "import-verify-key", required_argument, NULL, 'u' },
	{ "import-sign-key",   required_argument, NULL, 'U' },
	{ "output",            required_argument, NULL, 'o' },
	{ "version",           no_argument,       NULL, 'n' },
	{ "list",              no_argument,       NULL, 'l' },
	{ "password",          required_argument, NULL, 'p' },
	{ "human",             no_argument,       NULL, 'h' },
	{ "symmetric",         required_argument, NULL, 'k' },
	{ "symmetric-decrypt", required_argument, NULL, 'K' },
	{ "encrypt",           required_argument, NULL, 'C' },
	{ "decrypt",           required_argument, NULL, 'D' },
	{ "export-verify-key", no_argument,       NULL, 'z' },
	{ "export-sign-key",   no_argument,       NULL, 'Z' },
	{ "sign",              required_argument, NULL, 's' },
	{ "verify",            required_argument, NULL, 'v' },
	{ "to-verify",         required_argument, NULL, 'V' },
	{ "help",              no_argument,       NULL, 'H' },
	{ "examples",          no_argument,       NULL, 'x' },
	{  NULL,               0,                 NULL,  0  }

};

const char *short_opts = "gt:f:c:deo:Ei:I:lp:hk:K:C:D:zZu:u:U:s:v:V:";
