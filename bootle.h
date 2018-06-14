#ifndef __RTRS_BOOTLE_H
#define __RTRS_BOOTLE_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdlib.h>

struct BOOTLE_SIGMA1 {
	EC_GROUP *curve;
	EC_POINT *A;
	EC_POINT *C;
	EC_POINT *D;
	BIGNUM ***trimmed_challenge;
	BIGNUM *za;
	BIGNUM *zc;
	BIGNUM ***a;
	int a_n;
	int a_m;
};

struct BOOTLE_SIGMA2 {
	struct BOOTLE_SIGMA1 *sig1;
	EC_POINT *B;
	EC_POINT ***G;
	BIGNUM *z;
};

struct BOOTLE_SIGMA1 *BOOTLE_SIGMA1_new(EC_GROUP *group, BN_CTX *bnctx,
		BIGNUM ***b, size_t m, size_t n, BIGNUM *r);
struct BOOTLE_SIGMA2 *BOOTLE_SIGMA2_new(EC_GROUP *group, BN_CTX *bnctx,
		EC_POINT ***co, int asterisk, BIGNUM *r, int dbase, int dexp);
size_t BOOTLE_SIGMA1_serialize(unsigned char **ret, struct BOOTLE_SIGMA1 *sig1, int dbase, int dexp);
size_t BOOTLE_SIGMA2_serialize(unsigned char **ret, struct BOOTLE_SIGMA2 *sig2, int dbase, int dexp);
void BOOTLE_SIGMA1_free(struct BOOTLE_SIGMA1*);
void BOOTLE_SIGMA2_free(struct BOOTLE_SIGMA2*);
EC_POINT *COMb(EC_GROUP *group, BN_CTX *bnctx, BIGNUM ***x, size_t m, size_t n, BIGNUM *r);
EC_POINT *COMp(EC_GROUP *group, BN_CTX *bnctx, BIGNUM ***x, size_t m, size_t n, BIGNUM *r);
int *ndecompose(int base, int n, int dexp);
#endif
