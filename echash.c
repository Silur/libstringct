#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "rtrs.h"

BIGNUM *
RTRS_hash(char *data, size_t len)
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

int
RTRS_challenge_serialize(struct RTRS_CTX *ctx, struct RTRS_challenge *c,
	 	char **ret, char *M, size_t m_len)
{
#define convert_point(p) { \
		len = EC_POINT_point2buf(ctx->curve, p,\
				POINT_CONVERSION_UNCOMPRESSED, &t, ctx->bnctx); \
		memcpy(*ret, t, len); \
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
			convert_point(c->pk[i][j]);
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
