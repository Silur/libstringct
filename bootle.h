#ifndef __RTRS_BOOTLE_H
#define __RTRS_BOOTLE_H

#include <openssl/ec.h>
#include <openssl/bn.h>

struct BOOTLE_SIGMA1 {
	EC_POINT *A;
	EC_POINT *C;
	EC_POINT *D;
	BIGNUM ***trimmed_challenge;
	BIGNUM *za;
	BIGNUM *zc;
	BIGNUM ***a;
};

struct BOOTLE_SIGMA2 {
	struct BOOTLE_SIGMA1 *sig1;
	EC_POINT *B;
	EC_POINT **G;
	BIGNUM *z;
};

struct BOOTLE_SIGMA1 *BOOTLE_SIGMA1_new(EC_GROUP *group, BN_CTX *bnctx,
		BIGNUM ***b, size_t m, size_t n, BIGNUM *r);
char *BOOTLE_SIGMA1_serialize(struct BOOTLE_SIGMA1 *sig1, int dbase, int dexp);
char *BOOTLE_SIGMA2_serialize(struct BOOTLE_SIGMA2 *sig2, int dbase, int dexp);

#endif
