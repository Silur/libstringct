#ifndef __RTRS_H
#define __RTRS_H
#include <openssl/bn.h>
#include <openssl/ec.h>
struct RTRS_CTX {
	BN_CTX *bnctx;
	BIGNUM *q;
	BIGNUM *g;
	EC_GROUP *curve;
};
extern struct RTRS_CTX *RTRS_init();
extern void RTRS_free(struct RTRS_CTX *ctx);
extern int RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, BIGNUM **ki, BIGNUM **pk);
#endif
