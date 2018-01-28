#include "rtrs.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

int main(void)
{
	//curve25519
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *p = BN_new();
	int is_montgomery = 1;

	BN_set_word(a, 486662);
	BN_zero(b);
	BN_hex2bn(&p, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");
	struct RTRS_CTX *ctx = RTRS_init(a, b, p, "\xde\xad", "\xbe\xef", is_montgomery);
	
	BIGNUM **sk = malloc(2*sizeof(BIGNUM*));
	EC_POINT *ki = 0;
	EC_POINT **pk = malloc(2*sizeof(EC_POINT*));

	RTRS_keygen(ctx, sk, &ki, pk);

	BN_free(sk[0]);
	BN_free(sk[1]);
	EC_POINT_free(ki);
	EC_POINT_free(pk[0]);
	EC_POINT_free(pk[1]);
	BN_free(a);
	BN_free(b);
	BN_free(p);
	free(sk);
	free(pk);
	RTRS_free(ctx);
	return 0;
}
