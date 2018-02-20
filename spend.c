#include "rtrs.h"
#include "bootle.h"
#include <openssl/ec.h>
#include <openssl/bn.h>

int 
RTRS_spend(struct RTRS_CTX *ctx, BIGNUM **sk, struct RTRS_challenge f, 
		BIGNUM **co, struct BOOTLE_SIGMA1 s1, struct BOOTLE_SIGMA2 s2)
{
	return 1;
}
