#include <stdlib.h>
#include "rtrs.h"
#include <stdio.h>
#include <errno.h>
#include <openssl/bn.h>
int 
RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, BIGNUM **ki, BIGNUM **pk)
{
	sk[0] = BN_new();
	sk[1] = BN_new();
	*ki = BN_new();
 	pk[0] = BN_new();
	pk[1] = BN_new();
	FILE *fd = fopen("/dev/urandom", "r");
	if(!fd)
	{
		perror("error opening rand source");
		return 0;
	}
	unsigned char r[2][32];
	if(fread(r, 2, 32, fd)<64)
	{
		fclose(fd);
		perror("error reading rand source");
		return 0;
	}
	BN_bin2bn(r[0], 32, sk[0]);
	BN_bin2bn(r[1], 32, sk[1]);
	BN_mod_exp(*ki, ctx->g, sk[1], ctx->q, ctx->bnctx);

	BIGNUM *h = BN_dup(ctx->q); // FIXME where to get H from?
	BIGNUM *hpowr = BN_new();
	BN_mod_exp(hpowr, h, sk[0], ctx->q, ctx->bnctx);
	BN_mod_mul(pk[0], *ki, hpowr, ctx->q, ctx->bnctx);
	BN_mod_exp(pk[1], ctx->g, sk[0], ctx->q, ctx->bnctx);
	BN_free(hpowr);
	return 1;
}
