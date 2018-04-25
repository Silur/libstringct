#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#include "math.h"
#include "rtrs.h"
#include "multisig.h"
#include "bootle.h"

int RTRS_verify(struct RTRS_CTX *ctx, struct RTRS_comm *comm, EC_POINT **kis, size_t kilen, unsigned char *msg)
{
	int ret = 0;
	EC_POINT ***sub_points = malloc(sizeof(EC_POINT**)*comm->pk_cols);
	BIGNUM ***sub_scalars = malloc(sizeof(BIGNUM**)*comm->pk_cols);

	RTRS_sub(ctx, comm, sub_points, sub_scalars);

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

	uint32_t sig2len;
	memcpy(&sig2len, msg, 32);
	msg += 32;

	unsigned char *sig2buf = malloc(sig2len);
	memcpy(sig2buf, msg, sig2len);
	msg+=sig2len;
	struct BOOTLE_SIGMA2 *sig2 = malloc(sizeof(struct BOOTLE_SIGMA2));
	// FIXME
	memcpy(sig2, sig2buf, sig2len);
	uint32_t msiglen;
	memcpy(&msiglen, msg, 32);
	msg += 32;

	unsigned char *msig = malloc(msiglen);
	memcpy(msig, msg, msiglen);
	msg+=msiglen;

	// FIXME serialize sig1
	if (RTRS_MS_verify(ctx->curve, sig2buf, sig2len, kis, kilen, msig, msiglen) == 0)
		goto ms_err;

	// verify sigma1 with sub_points

	int all_on_curve = 1;
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->A, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->B, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->C, ctx->bnctx);
	all_on_curve &= EC_POINT_is_on_curve(ctx->curve, sig2->sig1->D, ctx->bnctx);

	if(!all_on_curve) return 0;


	unsigned int n = sig2->sig1->a_n;
	unsigned int m = sig2->sig1->a_m;
	BIGNUM ***f = malloc(sizeof(BIGNUM**)*m);
	unsigned int i;
	unsigned int j;
	for(j=0; j<m; j++)
	{
		f[j] = malloc(sizeof(BIGNUM*)*n);
		for(i=1; i<n; i++)
		{
			f[j][i] = BN_dup(sig2->sig1->trimmed_challenge[j][i-1]);
		}
	}
	unsigned char *acd_bin = 0;
	size_t binsize = 0;
	unsigned char *r;
	unsigned char *t;
	size_t tsize;
#define append_point(p) {\
	tsize = EC_POINT_point2buf(ctx->curve, p, POINT_CONVERSION_UNCOMPRESSED,\
			&t, ctx->bnctx);\
	r = realloc(acd_bin, binsize+tsize);\
	if(!r) goto bin_err;\
	acd_bin = r;\
	memcpy(acd_bin, t, tsize);\
	binsize+=tsize;\
	}
	append_point(sig2->sig1->A);
	append_point(sig2->sig1->C);
	append_point(sig2->sig1->D);

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
	// FIXME leak
	EC_POINT *tc = EC_POINT_new(ctx->curve);
	BN_free(bnt); bnt = BN_new();
	EC_POINT *check = EC_POINT_new(ctx->curve);
	EC_POINT_mul(ctx->curve, tc, 0, sig2->B, x, ctx->bnctx);
	EC_POINT_add(ctx->curve, check, tc, sig2->sig1->A, 0);
	EC_POINT *commitment = EC_POINT_new(ctx->curve);
	COMb(ctx->curve, ctx->bnctx, f, m, n, sig2->sig1->za);
	if(EC_POINT_cmp(ctx->curve, check, commitment, ctx->bnctx) != 0) goto commitment_err;

	EC_POINT_free(tc); BN_free(bnt); EC_POINT_free(check); EC_POINT_free(commitment);
	tc = EC_POINT_new(ctx->curve);
	bnt = BN_new();
	check = EC_POINT_new(ctx->curve);
	EC_POINT_mul(ctx->curve, tc, 0, sig2->sig1->C, x, ctx->bnctx);
	EC_POINT_add(ctx->curve, check, tc, sig2->sig1->D, 0);
	commitment = EC_POINT_new(ctx->curve);
	COMb(ctx->curve, ctx->bnctx, f1, m, n, sig2->sig1->zc);
	if(EC_POINT_cmp(ctx->curve, check, commitment, ctx->bnctx) != 0) goto commitment_err;

	// TODO validate sigma2 (409)
	size_t ring_size = (size_t)pow((double)m,(double)n);
	const EC_POINT *generator = EC_GROUP_get0_generator(ctx->curve);
	EC_POINT *gpowz = EC_POINT_new(ctx->curve);
	EC_POINT *c[2];
	EC_POINT_mul(ctx->curve, gpowz, 0, generator, sig2->z, ctx->bnctx);
	c[0] = gpowz;
	c[1] = gpowz;
	BIGNUM **g1 = malloc(sizeof(BIGNUM*)*ring_size);
	g1[0] = BN_dup(f[0][0]);
	for(i=1; i<m; i++)
	{
		BN_mul(g1[0], g1[0], f[j][0], 0);
	}
	EC_POINT *c1[2];
	c1[0] = c1[1] = EC_POINT_new(ctx->curve);
	EC_POINT *tempc[2];
	EC_POINT_mul(ctx->curve, c1[0], 0, sub_points[0][0], g1[0], ctx->bnctx); 
	EC_POINT_mul(ctx->curve, c1[1], 0, sub_points[0][1], g1[1], ctx->bnctx);
	for(i=1; i<ring_size; i++)
	{
		int *iseq = ndecompose(m, i, n);
		g1[i] = BN_dup(f[0][iseq[0]]);
		for(j=1; j<n; j++)
		{
			BN_mul(g1[i], g1[i], f[j][iseq[i]], 0);
		}
		tempc[0] = EC_POINT_new(ctx->curve);
		tempc[1] = EC_POINT_new(ctx->curve);
		EC_POINT_mul(ctx->curve, tempc[0], 0, sub_points[0][0], g1[0], ctx->bnctx);
		EC_POINT_mul(ctx->curve, tempc[1], 0, sub_points[0][1], g1[0], ctx->bnctx);
		EC_POINT_add(ctx->curve, c1[0], c1[0], tempc[0], ctx->bnctx);
		EC_POINT_add(ctx->curve, c1[1], c1[1], tempc[1], ctx->bnctx);
		free(iseq);
	}
	EC_POINT_free(tempc[0]);
	EC_POINT_free(tempc[1]);
	BIGNUM *xpowm = BN_new();
	BN_one(xpowm);
	EC_POINT *G_xpowm[2];
	G_xpowm[0] = EC_POINT_new(ctx->curve);
	G_xpowm[1] = EC_POINT_new(ctx->curve);
	for(i=0; i<m; i++)
	{
		BN_mul(xpowm, xpowm, xpowm, 0);
		EC_POINT_mul(ctx->curve, G_xpowm[0], 0, sig2->G[i][0], xpowm, ctx->bnctx);
		EC_POINT_mul(ctx->curve, G_xpowm[1], 0, sig2->G[i][1], xpowm, ctx->bnctx);
		EC_POINT_invert(ctx->curve, G_xpowm[0], ctx->bnctx);
		EC_POINT_invert(ctx->curve, G_xpowm[1], ctx->bnctx);
		EC_POINT_add(ctx->curve, c1[0], c1[0], G_xpowm[0], ctx->bnctx);
		EC_POINT_add(ctx->curve, c1[1], c1[1], G_xpowm[1], ctx->bnctx);
	}
	ret = ((EC_POINT_cmp(ctx->curve, gpowz, c1[0], 0) == 0) &&
		   (EC_POINT_cmp(ctx->curve, gpowz, c1[1], 0) == 0));

	EC_POINT_free(G_xpowm[0]);
	EC_POINT_free(G_xpowm[1]);
	EC_POINT_free(tempc[0]);
	EC_POINT_free(tempc[1]);
	EC_POINT_free(c[0]);
	EC_POINT_free(c[1]);
	for(i=0; i<m; i++) BN_free(g1[i]);
	free(g1);
	EC_POINT_free(gpowz);
commitment_err:
	EC_POINT_free(tc);
	EC_POINT_free(commitment);
	EC_POINT_free(check);
colsum_err:
	BN_free(colsum);
	BN_free(bnt);
	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			BN_free(f1[i][j]);
		}
		free(f1[i]);
	}
	free(f1);
	BN_free(x);
bin_err:
	free(r);
	free(t);
	free(acd_bin);
	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			BN_free(f1[i][j]);
		}
		free(f1[i]);
	}
	free(f);
ms_err:
	free(msig);
	free(sig2buf);
	free(co1);
	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			EC_POINT_free(sub_points[i][j]);
			BN_free(sub_scalars[i][j]);
		}
		free(sub_points[i]);
		free(sub_scalars[j]);
	}
	free(sub_points);
	free(sub_scalars);
	return ret;
}
