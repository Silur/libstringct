#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include "rtrs.h"

struct RTRS_CTX *RTRS_init(BIGNUM *a, BIGNUM *b, BIGNUM *p, 
		char *generator, char *order,  char *cofactor)
{
	struct RTRS_CTX *ctx = malloc(sizeof(struct RTRS_CTX));
	ctx->bnctx = BN_CTX_new();
    ctx->curve = EC_GROUP_new(EC_GFp_mont_method());

	EC_GROUP_set_curve_GFp(ctx->curve, p, a, b, ctx->bnctx);

	BIGNUM *q = BN_new(); 
	EC_POINT *g = EC_POINT_new(ctx->curve);
	BN_hex2bn(&q, cofactor);
	EC_POINT_hex2point(ctx->curve, generator, g, ctx->bnctx);
	BIGNUM *o = BN_new();
	BN_hex2bn(&o, order);
	EC_GROUP_set_generator(ctx->curve, g, o, q);
    BN_free(q);
    BN_free(o);
    EC_POINT_free(g);
	return ctx;
}


void RTRS_free(struct RTRS_CTX *ctx)
{
	EC_GROUP_free(ctx->curve);
	BN_CTX_free(ctx->bnctx);
	free(ctx);
}

int
RTRS_comm_serialize(struct RTRS_CTX *ctx, struct RTRS_comm *c,
	 	char **ret, char *M, size_t m_len)
{
#define convert_point(p) { \
		len = EC_POINT_point2buf(ctx->curve, p,\
				POINT_CONVERSION_UNCOMPRESSED, &t, ctx->bnctx); \
		memcpy(*ret+pos, t, len); \
		pos += len; \
		free(t); \
}

	*ret = malloc(4096);
	size_t i = 0, j = 0;
	int pos = 0;
	int len = 0;
	unsigned char *t;
	for(i=0; i<c->ki_len; i++)
	{
		convert_point(c->ki[j]);
	}
	for(i=0; i<c->pk_rows; i++)
		for(j=0; i<c->pk_cols; i++)
		{
			convert_point(c->pk[i][j][0]);
			convert_point(c->pk[i][j][0]);
		}
	for(i=0; i<c->co_len; i++)
	{
		convert_point(c->co[i]);
	}
	convert_point(c->co1);
	if(M) memcpy(*ret+pos, M, m_len);
	return pos;
#undef convert_point
}
