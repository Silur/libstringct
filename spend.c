#include "rtrs.h"
#include "bootle.h"
#include "multisig.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>

size_t 
RTRS_spend(unsigned char **ret, struct RTRS_CTX *ctx, BIGNUM ***sk, int sklen, BIGNUM *s, struct RTRS_comm *f, int d[2])
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

	struct BOOTLE_SIGMA2 *sig2 = BOOTLE_SIGMA2_new(ctx->curve, ctx->bnctx, c, f->iasterisk, s1, d[0], d[1]);

	BIGNUM **privkeys = malloc(sizeof(BIGNUM*)*sklen);

	for(i=0; i<sklen; i++)
	{
		privkeys[i] = BN_dup(sk[i][1]);
	}

	unsigned char *sig2buf;
	size_t sig2buflen = BOOTLE_SIGMA2_serialize(&sig2buf, sig2, d[0], d[1]);
	
	
	EC_POINT **pubkeys = malloc(sizeof(EC_POINT*)*sklen);
	for(i=0; i<sklen; i++)
	{
		pubkeys[i] = EC_POINT_new(ctx->curve);
		EC_POINT_mul(ctx->curve, pubkeys[i], 0, g, privkeys[i], ctx->bnctx);
	}
	
	unsigned char *msig;
	size_t msig_len = RTRS_MS_sign(&msig, ctx->curve, sig2buf, sig2buflen,
		pubkeys, privkeys, sklen);
	
	
	/* serialize everyting (dbase, dexp, co1, sig2, msig) into a buffer */
	unsigned char *t;	
	size_t co1len = EC_POINT_point2buf(ctx->curve, co1,
			POINT_CONVERSION_UNCOMPRESSED, &t, 0);
	size_t retlen = (2*sizeof(int) + sig2buflen + msig_len + co1len);
	*ret = malloc(retlen);
	memcpy(*ret, &d[0], sizeof(int));
	memcpy(*ret, &d[1], sizeof(int));
	memcpy(*ret, t, co1len);
	memcpy(*ret, sig2buf, sig2buflen);
	memcpy(*ret, msig, msig_len);
	return retlen;
}
