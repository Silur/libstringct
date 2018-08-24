#include <openssl/bn.h>
#include <openssl/ec.h>
#include <math.h>
#include "rtrs.h"
#include "echash.h"
#include "multisig.h"
#include "bootle.h"

int main(void)
{
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *p = BN_new();

	BN_zero(a);
	BN_set_word(b, 7);
	BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	char *generator = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D9\
		               59F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD\
                       17B448A68554199C47D08FFB10D4B8";
	char *order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8C\
		           D0364141";
	char *cofactor = "01";
	struct RTRS_CTX *ctx = RTRS_init(a, b, p, generator, order, cofactor);
	
	BIGNUM **sk = malloc(2*sizeof(BIGNUM*));
	EC_POINT *ki = 0;
	EC_POINT **pk = malloc(2*sizeof(EC_POINT*));
	
	long dbase = 8;
	long dexp = 8;
	int inputs = 8;

	printf("Ring size %lf\n Inputs: %d\n", pow(dbase, dexp), inputs);

	printf("Keygen...");
	RTRS_keygen(ctx, sk, &ki, pk);
	puts("done");
	// sigma1 test
	printf("Sigma1...");
	{
		BIGNUM ***b = malloc(2*sizeof(BIGNUM**));
		b[0] = malloc(2*sizeof(BIGNUM*));
		b[1] = malloc(2*sizeof(BIGNUM*));
		b[0][0] = BN_new();
		b[0][1] = BN_new();
		b[1][0] = BN_new();
		b[1][1] = BN_new();
		BN_one(b[0][0]);
		BN_zero(b[0][1]);
		BN_zero(b[1][0]);
		BN_one(b[1][1]);
		BIGNUM *r = BN_new();
		BN_one(r);
		struct BOOTLE_SIGMA1 *P = BOOTLE_SIGMA1_new(ctx->curve, ctx->bnctx, b, 2, 2, r);
		BOOTLE_SIGMA1_free(P);
		BN_free(b[0][0]);
		BN_free(b[0][1]);
		BN_free(b[1][0]);
		BN_free(b[1][1]);
		free(b[0]);
		free(b[1]);
		free(b);
		BN_free(r);
	}
	puts("done");
	RTRS_free(ctx);
	BN_free(sk[0]);
	BN_free(sk[1]);
	EC_POINT_free(ki);
	EC_POINT_free(pk[0]);
	EC_POINT_free(pk[1]);
	BN_free(a);
	BN_free(b);
	BN_free(p);
	free(sk);
	free(pk);
	return 0;
}
