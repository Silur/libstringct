#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "bootle.h"
#include "echash.h"

static EC_POINT *COMb(EC_GROUP *group, BN_CTX *bnctx, 
		BIGNUM ***x, size_t m, size_t n, BIGNUM *r)
{
	EC_POINT *A = EC_POINT_new(group);
	const EC_POINT *g = EC_GROUP_get0_generator(group);

	EC_POINT_mul(group, A, 0, g, r, bnctx);

	size_t i, j;
	EC_POINT *gn = EC_POINT_new(group);
	EC_POINT *gnh = EC_POINT_new(group);
	BIGNUM *t = BN_new();
	unsigned char *gnbuf;
	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			BN_set_word(t, i*n+j+1);
			EC_POINT_mul(group, gn, 0, g, t, bnctx);
			int gnbuf_len = EC_POINT_point2buf(group, gn, 
				POINT_CONVERSION_UNCOMPRESSED, &gnbuf, bnctx);
			BIGNUM *h = BN_hash(gnbuf, gnbuf_len);
			EC_POINT_bn2point(group, h, gnh, bnctx);
			EC_POINT_mul(group, gnh, 0, gnh, x[i][j], bnctx); // TODO check whether gnh can be used as param
			EC_POINT_add(group, A, A, gnh, bnctx);
		}
	}
	if(gnbuf) free(gnbuf);
	EC_POINT_clear_free(gn);
	EC_POINT_clear_free(gnh);
	BN_clear_free(t);
	return A;
}

static int *ndecompose(int base, int n, int dexp)
{
	int *ret = malloc(sizeof(int)*dexp);
	int i;
	int basepow;
	for(i=dexp-1; i>=0; i--)
	{
		basepow = (int)pow((double)base,(double)i);
		ret[i] = n/basepow;
		n-=basepow*ret[i];
	}
	return ret;
}

static BIGNUM **COEFPROD(BIGNUM **c, int clen, BIGNUM **d, int dlen)
{
	int maxlen = dlen ^ ((clen ^ dlen) & -(clen < dlen));
	int rlen = 2*maxlen-1;
	BIGNUM **ret = malloc(sizeof(BIGNUM*)*rlen);
	int i;
	int j;
	BIGNUM *t = BN_new();
	for(i=0; i<rlen; i++) BN_zero(ret[i]);
	for(i=0; i<maxlen; i++)
		for(j=0; j<maxlen; j++)
		{
			
			BN_mul(t, c[i], d[i], 0);
			BN_add(ret[i+j], ret[i+j], t);
		}
	return ret;
}

static BIGNUM ***COEFS(BIGNUM ***a, int n, int m, int asterisk)
{
	int ring_size = (int)(pow((double)n, (double)m));
	int *asterisk_seq = ndecompose(n, asterisk, m);

	BIGNUM ***ret = malloc(sizeof(BIGNUM**)*ring_size);
	int i,j;
	for(i=0; i<ring_size; i++)
	{
		int *kseq = ndecompose(n, i, m);
		ret[i] = malloc(sizeof(BIGNUM*)*2);
		ret[i][0] = a[0][kseq[0]];
		asterisk_seq[0] == kseq[0] ? BN_one(ret[i][1]) : BN_zero(ret[i][1]);

		BIGNUM **cprodparam = malloc(2*sizeof(BIGNUM*));
		for(j=1; j<m; j++)
		{
			cprodparam[0] = BN_dup(a[j][kseq[j]]);
			asterisk_seq[j] == kseq[j] ? BN_one(cprodparam[1]) : BN_zero(cprodparam[1]);
			ret[i] = COEFPROD(ret[i], m, cprodparam, 2);
		}
	}
	
	for(i=0; i<ring_size; i++)
	{
		for(j=0; j<ring_size; j++)
		{
			if(i<m) ret[i][j] = a[i][j];
		}
	}
	
	return ret;
}

struct BOOTLE_SIGMA1 *
BOOTLE_SIGMA1_new(EC_GROUP *group, BN_CTX *bnctx,
		BIGNUM ***b, size_t m, size_t n, BIGNUM *r)
{
	BIGNUM *rA = BN_new();
	BIGNUM *rC = BN_new();
	BIGNUM *rD = BN_new();

	BN_rand(rA, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	BN_rand(rC, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	BN_rand(rD, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

	BIGNUM ***a = malloc(sizeof(BIGNUM**)*m);
	size_t i = 0;
	size_t j = 0;
	for(i=0; i<m; i++)
	{
		a[i] = malloc(sizeof(BIGNUM*)*n);
		for(j=1; j<n; j++)
		{
			a[i][j] = BN_new();
			BN_rand(a[i][j], 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
		}
	}

	for(i=0; i<m; i++)
	{
		BN_zero(a[i][0]);
		for(j=1; j<n; j++)
		{
			BN_sub(a[i][0], a[i][0], a[i][j]);
		}
	}
	EC_POINT *A = COMb(group, bnctx, a, m, n, rA);

	BIGNUM ***c = malloc(sizeof(BIGNUM**)*m);
	BIGNUM ***d = malloc(sizeof(BIGNUM**)*m);
	BIGNUM *t1 = BN_new();
	BN_one(t1);
	BIGNUM *t2 = BN_new();
	BN_set_word(t1, 2);
	for(i=0; i<m; i++)
	{
		c[i] = malloc(sizeof(BIGNUM*)*n);
		d[i] = malloc(sizeof(BIGNUM*)*n);
		for(j=0; i<n; j++)
		{
			c[i][j] = BN_new();
			d[i][j] = BN_new();

			BN_mul(t2, b[i][j], t2, bnctx);
			BN_sub(t1, t1, t2);
			BN_mul(c[i][j], a[i][j], t1, bnctx);

			BN_hex2bn(&t1, "-1");
			BN_sqr(t2, a[i][j], bnctx);

			BN_mul(d[i][j], t2, t1, bnctx);
		}
	}

	EC_POINT *C = COMb(group, bnctx, c, m, n, rC);
	EC_POINT *D = COMb(group, bnctx, d, m, n, rD);

	unsigned char *Abuf;
	unsigned char *Cbuf;
	unsigned char *Dbuf;
	size_t Alen = EC_POINT_point2buf(group, A,
				POINT_CONVERSION_UNCOMPRESSED, &Abuf, bnctx);
	size_t Clen = EC_POINT_point2buf(group, C,
				POINT_CONVERSION_UNCOMPRESSED, &Cbuf, bnctx);
	size_t Dlen = EC_POINT_point2buf(group, D,
				POINT_CONVERSION_UNCOMPRESSED, &Dbuf, bnctx);
	
	unsigned char *buf = malloc(Alen + Clen + Dlen);

	memcpy(buf, Abuf, Alen);
	memcpy(buf+Alen, Cbuf, Clen);
	memcpy(buf+Alen+Clen, Dbuf, Dlen);

	BIGNUM *x = BN_hash(buf, Alen + Clen + Dlen);

	BIGNUM ***f = malloc(sizeof(BIGNUM**)*m);
	for(i=0; i<m; i++)
	{
		f[i] = malloc(sizeof(BIGNUM*)*n);
		for(j=0; j<n; j++)
		{
			f[i][j] = BN_new();
			BN_mul(f[i][j], b[i][j], x, bnctx);
			BN_add(f[i][j], f[i][j], a[i][j]);
		}
	}

	BIGNUM ***f_trimmed = malloc(sizeof(BIGNUM**)*m);
	for(i=0; i<m; i++)
	{
		f[i] = malloc(sizeof(BIGNUM*)*n);
		for(j=1; j<n; j++)
		{
			f_trimmed[i][j-1] = BN_dup(f[i][j]);
		}
	}

	BIGNUM *zA = BN_new();
	BIGNUM *zC = BN_new();

	BN_mul(zA, r, x, bnctx);
	BN_add(zA, zA, rA);
	
	BN_mul(zC, rC, x, bnctx);
	BN_add(zC, zC, rD);

	struct BOOTLE_SIGMA1 *ret = malloc(sizeof(struct BOOTLE_SIGMA1));

	ret->A = A;	
	ret->C = C;	
	ret->D = D;
	ret->trimmed_challenge = f_trimmed;
	ret->za = zA;
	ret->zc = zC;
	ret->a = a;
	ret->a_n = m;
	ret->a_m = n;
	BN_clear_free(rA);
	BN_clear_free(rC);
	BN_clear_free(rD);
	BN_clear_free(x);

	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			BN_clear_free(c[i][j]);
			BN_clear_free(d[i][j]);
			BN_clear_free(f[i][j]);
		}
		free(c[i]);
		free(d[i]);
		free(f[i]);
	}
	free(c);
	free(d);
	free(f);
	free(t1);
	free(t2);
	free(Abuf);
	free(Cbuf);
	free(Dbuf);
	free(buf);
	return ret;
}

struct BOOTLE_SIGMA2 *BOOTLE_SIGMA2_new(EC_GROUP *group, BN_CTX *bnctx,
		EC_POINT ***co, int asterisk, BIGNUM *r, int dbase, int dexp)
{
	int i, j;
	int ring_size = (int)pow((double)dbase, (double)dexp);
	if(ring_size<0)
	{
		fprintf(stderr, "ring size overflow, try lowering decomposition params!\n");
		return 0;
	}
	BIGNUM **u = malloc(sizeof(BIGNUM*)*dexp);
	for(i=0; i<dexp; i++)
	{
		u[i] = BN_new();
		BN_rand(u[i], 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	}

	BIGNUM *rB = BN_new();
	BN_rand(rB, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

	int *asterisk_seq = ndecompose(dbase, asterisk, dexp);

	BIGNUM ***D = malloc(sizeof(BIGNUM**)*dexp);
	for(i=0; i<dexp; i++)
	{
		D[i] = malloc(sizeof(BIGNUM*)*dbase);
		for(j=0; j<dbase; j++)
		{
			D[i][j] = BN_new();
			asterisk_seq[i] == j ? BN_one(D[i][j]) : BN_zero(D[i][j]);
		}
	}

	EC_POINT *B = COMb(group, bnctx, D, dexp, dbase, rB);
	struct BOOTLE_SIGMA1 *P = BOOTLE_SIGMA1_new(group, bnctx, D, dexp, dbase, rB);

	BIGNUM ***coefs = COEFS(P->a, P->a_n, P->a_m,  asterisk);

	EC_POINT ***G = malloc(sizeof(EC_POINT**)*dexp);
	const EC_POINT *g = EC_GROUP_get0_generator(group);
	
	unsigned char *one = malloc(BN_num_bytes(BN_value_one()));
	BIGNUM *hashone = BN_hash(one, BN_num_bytes(BN_value_one()));
	BN_bn2bin(BN_value_one(), one);
	EC_POINT *econe =	EC_POINT_new(group);
	EC_POINT_bn2point(group, hashone, econe, bnctx);
	EC_POINT *t1 = EC_POINT_new(group);
	EC_POINT *t2 = EC_POINT_new(group);
	for(i=0; i<dexp; i++)
	{
		G[i] = malloc(sizeof(EC_POINT*)*2);
		EC_POINT_mul(group, t1, 0, econe, u[i], bnctx);
		EC_POINT_add(group, G[i][0], t1, g, bnctx);
		EC_POINT_mul(group, G[i][0], 0, g, u[i], bnctx);

		for(j=0; j<ring_size; j++)
		{
			EC_POINT_mul(group, t1, 0, co[j][0], coefs[j][i], bnctx);
			EC_POINT_mul(group, t2, 0, co[j][1], coefs[j][i], bnctx);
			EC_POINT_add(group, G[i][0], G[i][0], t1, bnctx);
			EC_POINT_add(group, G[i][1], G[i][1], t2, bnctx);
		}
	}
	
	unsigned char *Pa;
	unsigned char *Pc;
	unsigned char *Pd;
	int Pa_len = EC_POINT_point2buf(group, P->A, 
				POINT_CONVERSION_UNCOMPRESSED, &Pa, bnctx);
	int Pc_len = EC_POINT_point2buf(group, P->C, 
				POINT_CONVERSION_UNCOMPRESSED, &Pc, bnctx);
	int Pd_len = EC_POINT_point2buf(group, P->D, 
				POINT_CONVERSION_UNCOMPRESSED, &Pd, bnctx);
	unsigned char *bytes = malloc(Pa_len + Pc_len + Pd_len);
	memcpy(bytes, Pa, Pa_len);
	memcpy(bytes+Pa_len, Pc, Pc_len);
	memcpy(bytes+Pa_len+Pc_len, Pd, Pd_len);
	free(Pa);
	free(Pc);
	free(Pd);
	BIGNUM *x1 = BN_hash(bytes, Pa_len + Pc_len + Pd_len);
	BIGNUM *z = BN_new();
	BIGNUM *t3 = BN_new();
	BIGNUM *t4 = BN_new();
	BN_set_word(t3, dexp);
	BN_exp(t4, x1, t3, bnctx);
	BN_mul(z, r, t4, bnctx);

	for(i=0; i<dexp; i++)
	{
		BN_set_word(t4, i);
		BN_exp(t3, x1, t4, bnctx);
		BN_mul(t3, u[i], t3, bnctx);
		BN_sub(z, z, t3);
	}
	
	struct BOOTLE_SIGMA2 *ret = malloc(sizeof(struct BOOTLE_SIGMA2));
	if(!ret)
	{
		perror("memory allocation error: ");
		return 0;
	}
	ret->sig1 = P;
	ret->B = B;
	ret->G = G;
	ret->z = z;

	// cleanup
	for(i=0; i<dexp; i++)
	{
		for(j=0; j<dbase; j++)
		{
			BN_clear_free(D[i][j]);
			BN_clear_free(coefs[i][j]);
		}
		free(D[i]);
		free(u[i]);
		free(coefs[i]);
	}
	EC_POINT_clear_free(econe);
	EC_POINT_clear_free(t1);
	EC_POINT_clear_free(t2);
	BN_clear_free(rB);
	BN_clear_free(hashone);
	BN_clear_free(t3);
	BN_clear_free(t4);
	BN_clear_free(x1);
	free(asterisk_seq);
	free(D);
	free(coefs);
	free(one);
	free(bytes);
	return ret;
}
