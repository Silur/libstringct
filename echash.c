#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include "echash.h"

static int legendre(BIGNUM *a, BIGNUM *p)
{
	BIGNUM *t[3];
	int i;
	for(i=0; i<3; i++) t[i] = BN_new();
	BN_set_word(t[1], 2);
	BN_sub(t[0], p, BN_value_one());
	BN_div(t[2], 0, t[0], t[1], 0);
	BIGNUM *r = BN_new();
	BN_mod_exp(r, a, t[2], p, 0);
	
	for(i=0; i<3; i++) BN_free(t[i]);

	if(BN_is_zero(r)) return 0;
	if(BN_is_one(r)) return 1;
	return -1;
}

static BIGNUM *substitute_right(const EC_GROUP *g, BIGNUM *x)
{
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *p = BN_new();
	EC_GROUP_get_curve_GFp(g, p, a, b, 0);

	BIGNUM *t[4];

	int i;
	for(i=0; i<4; i++) t[i] = BN_new();
	BN_set_word(t[0], 3);
	BN_mod_exp(t[1], x, t[0], p, 0);
	BN_mod_mul(t[2], x, a, p, 0);
	BN_mod_add(t[3], t[1], t[2], p, 0);

	BIGNUM *ret = BN_new();
	BN_mod_add(ret, t[3], b, p, 0);
	
	for(i=0; i<4; i++) BN_free(t[i]);
	return ret;
}

BIGNUM *BN_hash(unsigned char *data, size_t len)
{
	BIGNUM *ret = BN_new();
	unsigned char *norm = OPENSSL_malloc(32);
	if (len<32)
	{
		memcpy(norm, data, len);
		int i;
		for(i=len; i<32; i++)
		{
			norm[i] = 0x00;
		}
	}
	else
	{
		memcpy(norm, data, 32);
	}
	BN_bin2bn(norm, 32, ret);
	OPENSSL_free(norm);
	return ret;
}

EC_POINT *EC_hash(const EC_GROUP *g, unsigned char *data, size_t len)
{
	unsigned char is_on_curve = 0;
	
	EC_POINT *r = EC_POINT_new(g);
	BIGNUM *p = BN_new();
	EC_GROUP_get_curve_GFp(g, p, 0, 0, 0);
	unsigned int c = 1;
	unsigned char *hash_in = OPENSSL_malloc(len + sizeof(unsigned int));
	unsigned char *hash_out = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
	memcpy(hash_in, data, len);
	SHA256_CTX *sha_ctx = OPENSSL_malloc(sizeof(SHA256_CTX));
	BIGNUM *x;
	BIGNUM *sub;
	while(!is_on_curve)
	{
		memcpy(hash_in+len, &c, sizeof(unsigned int));
		SHA256_Init(sha_ctx);
		SHA256_Update(sha_ctx, hash_in, len+sizeof(unsigned int));
		SHA256_Final(hash_out, sha_ctx);
		x = BN_hash(hash_out, SHA256_DIGEST_LENGTH);
		sub = substitute_right(g,x);
		is_on_curve = legendre(sub, p) == 1;
		c++;
	}
	BIGNUM *y = BN_new();
	BN_mod_sqr(y, x, p, 0);
	
	EC_POINT_set_affine_coordinates_GFp(g, r, x, y, 0);
	if(!EC_POINT_is_on_curve(g, r, 0))
	{
		fprintf(stderr, "%s:%d:Curve hash arithmetic error occured\n", __FILE__, __LINE__);
		return 0;
	}
	return r;

}
