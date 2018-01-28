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
	EC_POINT **pk;
	EC_POINT **co;
	EC_POINT *co1;
	unsigned long l; // inputs
	unsigned long n; // ring size
};
extern struct RTRS_CTX *RTRS_init(BIGNUM *a, BIGNUM *b, BIGNUM *p, 
		char *generator, char *coefficient, 
		int montgomery);
extern void RTRS_free(struct RTRS_CTX *ctx);
extern int RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, EC_POINT **ki, EC_POINT **pk);
extern void RTRS_sub(struct RTRS_CTX *ctx, struct RTRS_challenge *fin, EC_POINT **ret);
#endif
