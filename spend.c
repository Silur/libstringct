#include "rtrs.h"
#include "bootle.h"
#include <openssl/ec.h>
#include <openssl/bn.h>

int 
RTRS_spend(struct RTRS_CTX *ctx, BIGNUM ***sk, int sklen, BIGNUM *s, struct RTRS_comm *f, int d[2])
{
	const EC_POINT *g = EC_GROUP_get0_generator(ctx->curve);
	EC_POINT *co1 = EC_POINT_new(ctx->curve);
	EC_POINT_mul(ctx->curve, co1, 0, g, s, ctx->bnctx);
	EC_POINT ***c = malloc(sizeof(EC_POINT*)*f->n);
	BIGNUM **fs = malloc(sizeof(BIGNUM*)*f->l);
	RTRS_sub(ctx, f, c, &fs);
	BIGNUM *s1 = BN_dup(s);
	BIGNUM *t1 = BN_new();
	int i;

	for(i=0; i<sklen; i++)
	{
		BN_mul(t1, sk[i][0], fs[i], ctx->bnctx);
		BN_add(s1, s1, t1);
	}

	struct BOOTLE_SIGMA2 *sigma2 = BOOTLE_SIGMA2_new(ctx->curve, ctx->bnctx, c, f->iasterisk, s1, d[0], d[1]);
	(void)sigma2; // HACK
	//TODO last multisig
	return 1;
}
