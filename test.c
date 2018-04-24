#include <openssl/bn.h>
#include <openssl/ec.h>
#include <math.h>
#include "rtrs.h"
#include "echash.h"
#include "multisig.h"

int main(void)
{
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
	
	long dbase = 2;
	long dexp = 8;
	int inputs = 2;

	printf("Ring size %lf\n Inputs: %d\n", pow(dbase, dexp), inputs);
	printf("Keygen...");
	RTRS_keygen(ctx, sk, &ki, pk);
	puts("done");
	RTRS_free(ctx);
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
	return 0;
}
