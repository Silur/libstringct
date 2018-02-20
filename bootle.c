#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdlib.h>
#include <string.h>
#include "bootle.h"
#include "echash.h"

static EC_POINT *COMb(EC_GROUP *group, BN_CTX *bnctx, 
		BIGNUM ***x, size_t m, size_t n, BIGNUM *r)
{
	EC_POINT *A = EC_POINT_new(group);
	const EC_POINT *g = EC_GROUP_get0_generator(group);

	EC_POINT_mul(group, A, 0, g, r, bnctx);

	size_t i, j;
	for(i=0; i<m; i++)
	{
		for(j=0; j<n; j++)
		{
			// TODO lookup point hash in a map and add it to A
			BN_print_fp(stdout, x[i][j]); // HACK
		}
	}
	return A;
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
	
	char *buf = malloc(Alen + Clen + Dlen);

	memcpy(buf, Abuf, Alen);
	memcpy(buf+Alen, Cbuf, Clen);
	memcpy(buf+Alen+Clen, Dbuf, Dlen);

	BIGNUM *x = EC_hash(buf, Alen + Clen + Dlen);

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
