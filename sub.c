#include <openssl/ec.h>
#include <string.h>
#include <openssl/bn.h>
#include "rtrs.h"


extern void 
RTRS_sub(struct RTRS_CTX *ctx, struct RTRS_comm *fin, 
		EC_POINT ***ret, BIGNUM ***f_ret)
{
	EC_POINT ***pkz = malloc(sizeof(EC_POINT**)*fin->l);
	EC_POINT *inf = EC_POINT_new(ctx->curve);
	EC_POINT_set_to_infinity(ctx->curve, inf);
	unsigned long i, j;
	char *to_hash = calloc(8192, 1); // TODO more accurate size
	for(j=0; j<fin->l; j++)
	{
		pkz[j] = malloc(sizeof(EC_POINT*)*2);
		pkz[j][0] = fin->ki[j];
		pkz[j][1] = inf;
		unsigned char *ki_buf;
		int ki_len = EC_POINT_point2buf(ctx->curve, fin->ki[j], 
				POINT_CONVERSION_UNCOMPRESSED, &ki_buf, ctx->bnctx);
		char *ctx_serialized;
		int challenge_len = RTRS_comm_serialize(ctx, fin, &ctx_serialized, 0, 0);
		memcpy(to_hash, ki_buf, ki_len);
		memcpy(to_hash+ki_len, ctx_serialized, challenge_len);
		memcpy(to_hash+ki_len+challenge_len, &j, 8);
		*f_ret[j] = RTRS_hash(to_hash, ki_len+challenge_len+8);
	}
	EC_POINT *t1 = EC_POINT_new(ctx->curve);
	EC_POINT *t2 = EC_POINT_new(ctx->curve);

	for(i=0; i<fin->n; i++)
	{
		ret[i] = malloc(2*sizeof(EC_POINT*));
		ret[i][0] = fin->co[i];
		ret[i][1] = fin->co1;
		for(j=0; j<fin->l; j++)
		{
			t1 = EC_POINT_dup(pkz[j][0], ctx->curve);
			t2 = EC_POINT_dup(pkz[j][1], ctx->curve);
			EC_POINT_invert(ctx->curve, t1, ctx->bnctx);
			EC_POINT_add(ctx->curve, t1, fin->pk[j][i][0], t1, ctx->bnctx);
			EC_POINT_add(ctx->curve, t2, fin->pk[j][i][1], t2, ctx->bnctx);
			EC_POINT_mul(ctx->curve, t2, 0, t1, *f_ret[j], ctx->bnctx);
			EC_POINT_add(ctx->curve, *ret[i], *ret[i], t2, ctx->bnctx);
		}
	}

	for(i=0; i<fin->l; i++)
	{
		EC_POINT_clear_free(pkz[i][0]);
		EC_POINT_clear_free(pkz[i][1]);
		free(pkz[i]);
	}

	EC_POINT_clear_free(t1);
	EC_POINT_clear_free(t2);
	free(pkz);
	pkz = 0;
	EC_POINT_free(inf);
}
