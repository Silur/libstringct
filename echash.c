#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "echash.h"

BIGNUM *BN_hash(unsigned char *data, size_t len)
{
	BIGNUM *ret = 0;
	unsigned char *norm = malloc(32);
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
	free(norm);
	return ret;
}

EC_POINT *EC_hash(const EC_GROUP *g, unsigned char *data, size_t len)
{
	unsigned char is_on_curve = 0;
	EC_POINT *p = EC_POINT_new(g);
	unsigned int c = 1;
	unsigned char *hash_in = malloc(len + sizeof(unsigned int));
	memcpy(hash_in, data, len);
	while(!is_on_curve)
	{
		memcpy(hash_in+len, &c, sizeof(unsigned int));
		EC_POINT_oct2point(g, p, hash_in, len, 0);
		is_on_curve = EC_POINT_is_on_curve(g, p, 0);
	}
	return p;

}
