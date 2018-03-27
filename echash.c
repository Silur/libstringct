#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
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
