#include <openssl/ec.h>
#include <openssl/bn.h>
#include "rtrs.h"
#include "multisig.h"
#include "bootle.h"

int RTRS_verify(struct RTRS_CTX *ctx, struct RTRS_comm *comm, EC_POINT ***pks,
		size_t pklen, EC_POINT **kis, size_t kilen, unsigned char *msg, size_t msglen)
{
	EC_POINT **sub_points;
	BIGNUM **sub_scalars;

	RTRS_sub(ctx, comm, &sub_points, &sub_scalars);

	// deserialize msg
	uint32_t d[2];
	memcpy(&d[0], msg, 32);
	msg += 32;
	memcpy(&d[1], msg, 32);
	msg += 32;

	uint32_t co1len;
	memcpy(&co1len, msg, 32);
	msg += 32;

	unsigned char *co1 = malloc(co1len);
	memcpy(co1, msg, co1len);
	msg+=co1len;

	uint32_t sig1len;
	memcpy(&sig1len, msg, 32);
	msg += 32;

	unsigned char *sig1 = malloc(sig1len);
	memcpy(sig1, msg, sig1len);
	msg+=sig1len;

	uint32_t msiglen;
	memcpy(&msiglen, msg, 32);
	msg += 32;

	unsigned char *msig = malloc(msiglen);
	memcpy(msig, msg, msiglen);
	msg+=msiglen;


	int msret = RTRS_MS_verify(ctx->curve, sig1, sig1len, kis, kilen, msig, msiglen);

	// verify sigma1 with sub_points

	int all_on_curve = 1;
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->a, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->b, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->c, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->d, ctx->bnctx);

	if(!all_on_curve) return 0;


	int n = sig2->sig1->m;
	int n = sig2->sig1->m;
	BIGNUM ***f = malloc(sizeof(BIGNUM**)*m);
	int i;
	int j;
	for(j=0; j<m; j++)
	{
		f[j] = malloc(sizeof(BIGNUM*)*n);
		for(i=1; i<n; i++)
		{
			f[j][i] = BN_dup(sig2->sig1->trimmed_challenge, [j][i-1]);
		}
	}
	unsigned char *acd_bin;
	size_t binsize = 0;
	unsigned char *r;
	unsigned char *t;
	size_t tsize;
#define append_point(p) {\
	tsize = EC_POINT_point2buf(ctx->curve, p, POINT_CONVERSION_UNCOMPRESSED,\
			&t, ctx->bnctx);\
	r = realloc(acd_bin, binsize+t);\
	if(!r) goto bin_error;\
	acd_bin = r;\
	mcmcpy(acd_bin, t, tsize);\
	binsize+=t\
	}
	append_point(sig1->sig2->a);
	append_point(sig1->sig2->c);
	append_point(sig1->sig2->d);

#undef append_point
	BIGNUM *x = BN_new();
	BN_bin2bn(acd_bin, binsize, x);
	for(j=0; j<m; j++)
	{
		f[j][0] = x;
		for(i=1; i<n; i++)
		{
			BN_sub(f[j][0], f[j][0], f[j][i]);
		}
	}

	BIGNUM ***f1 = malloc(sizeof(BIGNUM**)*m);
	BIGNUM *bnt = BN_new();
	for(j=0; j<m; j++)
	{
		f1[j] = malloc(sizeof(BIGNUM*)*n);
		for(i=0; i<n; i++)
		{
			f[j][i] = BN_new();
			BN_sub(bnt, x, f[j][i]);
			BN_mul(f[j][i], f[j][i], bnt, 0);
		}
	}
	BIGNUM *colsum = BN_new();
	for(j=0; j<m; j++)
	{
		BN_zero(colsum);
		for(i=1; i<n; i++)
		{
			BN_add(colsum, colsum, f[j][i]);
		}
		if(BN_cmp(f[j][0], colsum) != 0) goto colsum_err;
	}

	// TODO check sig1->B*x + a == COMb(a)

	if(!msret) return 0;
	return 1;
}
