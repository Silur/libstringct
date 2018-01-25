#include "rtrs.h"
#include <openssl/bn.h>
int main(void)
{
	struct RTRS_CTX *ctx = RTRS_init();
	
	BIGNUM **sk = malloc(2*sizeof(BIGNUM*));
	BIGNUM *ki = 0;
	BIGNUM **pk = malloc(2*sizeof(BIGNUM*));

	RTRS_keygen(ctx, sk, &ki, pk);

	BN_free(sk[0]);
	BN_free(sk[1]);
	BN_free(ki);
	BN_free(pk[0]);
	BN_free(pk[1]);
	free(sk);
	free(pk);
	RTRS_free(ctx);
	return 0;
}
