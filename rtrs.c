#include <gmp.h>
#include <stdlib.h>
#include "rtrs.h"

struct RTRS_CTX *RTRS_init(BIGNUM *a, BIGNUM *b, BIGNUM *p, 
		char *generator, char *coefficient, 
		int montgomery)
{
	struct RTRS_CTX *ctx = malloc(sizeof(struct RTRS_CTX));
	ctx->bnctx = BN_CTX_new();
	if(montgomery) 
	{
		ctx->curve = EC_GROUP_new(EC_GFp_mont_method());
	}
	else
	{
		ctx->curve = EC_GROUP_new(EC_GFp_simple_method());
	}

	EC_GROUP_set_curve_GFp(ctx->curve, p, a, b, ctx->bnctx);

	BIGNUM *q = BN_new(); 
	EC_POINT *g = EC_POINT_new(ctx->curve);
	BN_hex2bn(&q, coefficient);
	EC_POINT_hex2point(ctx->curve, generator, g, ctx->bnctx);
	BIGNUM *order = BN_new();
	BN_hex2bn(&order, "10000000000000000000000000000000000000000000000000000000000000000");
	EC_GROUP_set_generator(ctx->curve, g, order, q);

	EC_POINT_free(g);
	BN_free(q);
	BN_free(order);

	return ctx;
}


void RTRS_free(struct RTRS_CTX *ctx)
{
	BN_CTX_free(ctx->bnctx);
	EC_GROUP_clear_free(ctx->curve);
	free(ctx);
	ctx = 0;
}
