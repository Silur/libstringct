#include <stdlib.h>
#include "rtrs.h"
#include <stdio.h>
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>

int 
RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, EC_POINT **ki, EC_POINT **pk)
{
	sk[0] = BN_new();
	sk[1] = BN_new();
	*ki = EC_POINT_new(ctx->curve);
 	pk[0] = EC_POINT_new(ctx->curve);
	pk[1] = EC_POINT_new(ctx->curve);
	unsigned char r[2][32];
	int i;
	for(i=0; i<2; i++)
	{
		if(!RAND_bytes(r[i], 32)) 
		{
			char *errstr = malloc(256);
			ERR_error_string_n(ERR_get_error(), errstr, 256);
			fprintf(stderr, "error while random number generation: %s", errstr);
			return 0;
		}
	}
	BN_bin2bn(r[0], 32, sk[0]);
	BN_bin2bn(r[1], 32, sk[1]);
	EC_POINT *g = (EC_POINT*)EC_GROUP_get0_generator(ctx->curve);

	EC_POINT_mul(ctx->curve, *ki, 0, g, sk[1], ctx->bnctx);
	EC_POINT *h = EC_POINT_dup(g, ctx->curve);
	EC_POINT *hpowr = EC_POINT_new(ctx->curve);
	EC_POINT_mul(ctx->curve, hpowr, 0, h, sk[0], ctx->bnctx);
	EC_POINT_add(ctx->curve, pk[0], *ki, hpowr, ctx->bnctx);
	EC_POINT_mul(ctx->curve, pk[1], 0, g, sk[1], ctx->bnctx);

	EC_POINT_free(g);
	EC_POINT_free(h);
	EC_POINT_clear_free(hpowr);
	return 1;
}
