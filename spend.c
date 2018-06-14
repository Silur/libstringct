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
	EC_POINT ***c = OPENSSL_malloc(sizeof(EC_POINT*)*f->n); // FIXME
	BIGNUM **fs = OPENSSL_malloc(sizeof(BIGNUM*)*f->l);
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

	BIGNUM **privkeys = OPENSSL_malloc(sizeof(BIGNUM*)*sklen);

	for(i=0; i<sklen; i++)
	{
		privkeys[i] = BN_dup(sk[i][1]);
	}

	unsigned char *sig2buf;
	uint32_t sig2buflen = BOOTLE_SIGMA2_serialize(&sig2buf, sig2, d[0], d[1]);
	
	
	EC_POINT **pubkeys = OPENSSL_malloc(sizeof(EC_POINT*)*sklen);
	for(i=0; i<sklen; i++)
	{
		pubkeys[i] = EC_POINT_new(ctx->curve);
		EC_POINT_mul(ctx->curve, pubkeys[i], 0, g, privkeys[i], ctx->bnctx);
	}
	
	unsigned char *msig;
	uint32_t msig_len = RTRS_MS_sign(&msig, ctx->curve, sig2buf, sig2buflen,
		pubkeys, privkeys, sklen);
	
	
	/* serialize everyting (dbase, dexp, co1, sig2, msig) into a buffer */
	unsigned char *t;	
	uint32_t co1len = EC_POINT_point2buf(ctx->curve, co1,
			POINT_CONVERSION_UNCOMPRESSED, &t, 0);
	uint32_t retlen = (128 + sig2buflen + msig_len + co1len);
	*ret = OPENSSL_malloc(retlen);
	uint32_t dfix[2] = {d[0], d[1]};
	memcpy(*ret, &dfix[0], 32);
	memcpy(*ret, &dfix[1], 32);
	memcpy(*ret, &co1len, 32);
	memcpy(*ret, t, co1len);
	memcpy(*ret, &sig2buflen, 32);
	memcpy(*ret, sig2buf, sig2buflen);
	memcpy(*ret, &msig_len, 32);
	memcpy(*ret, msig, msig_len);
	OPENSSL_free(t);
	OPENSSL_free(msig);
	for(i=0; i<sklen; i++) EC_POINT_free(pubkeys[i]);
	OPENSSL_free(pubkeys);
	OPENSSL_free(sig2buf);
	for(i=0; i<sklen; i++) BN_free(privkeys[i]);
	OPENSSL_free(privkeys);
	BOOTLE_SIGMA2_free(sig2);
	BN_free(t1);
	BN_free(s1);
	unsigned long j;
	for(j=0; j<f->l; j++) BN_free(fs[i]);
	OPENSSL_free(fs);
	OPENSSL_free(c); // FIXME leak
	return retlen;
}
