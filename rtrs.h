#ifndef __RTRS_H
#define __RTRS_H
#include <openssl/bn.h>
#include <openssl/ec.h>

struct RTRS_CTX {
	BN_CTX *bnctx;
	EC_GROUP *curve;
};

struct RTRS_challenge {
	EC_POINT **ki;
	size_t ki_len;
	EC_POINT ***pk[2];
	size_t pk_rows;
	size_t pk_cols;
	EC_POINT **co;
	size_t co_len;
	EC_POINT *co1;
	char *M;
	size_t m_len;
	int iasterisk;
	unsigned long l; // inputs
	unsigned long n; // ring size
};

extern struct RTRS_CTX *RTRS_init(BIGNUM *a, BIGNUM *b, BIGNUM *p, 
		char *generator, char *coefficient, 
		int montgomery);
extern void RTRS_free(struct RTRS_CTX *ctx);
extern int RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, EC_POINT **ki, EC_POINT **pk);
extern void RTRS_sub(struct RTRS_CTX *ctx, struct RTRS_challenge *fin, 
		EC_POINT ***ret, BIGNUM ***f_ret);
extern BIGNUM *RTRS_hash(char *data, size_t len);
extern int RTRS_challenge_serialize(struct RTRS_CTX *ctx, struct RTRS_challenge *c, 
		char **ret, char *M, size_t m_len);
extern int RTRS_spend(struct RTRS_CTX *ctx, BIGNUM ***sk, int sklen, BIGNUM *s, struct RTRS_challenge *f, int d[2]);
#endif
