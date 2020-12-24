#ifndef _ARGON2_CUSTOM_H
#	define _ARGON2_CUSTOM_H
char *argon2_generate(const char *pwd, size_t pwdlen, int hashlen, int saltlen, int t_cost, int m_cost, int parallelism, int encoded_len);
#endif
