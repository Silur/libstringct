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

	BN_zero(a);
	BN_set_word(b, 7);
	BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	char *generator = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D9\
		               59F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD\
                       17B448A68554199C47D08FFB10D4B8";
	char *order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8C\
		           D0364141";
	char *cofactor = "01";
	struct RTRS_CTX *ctx = RTRS_init(a, b, p, generator, order, cofactor);
	
	BIGNUM **sk = malloc(2*sizeof(BIGNUM*));
	EC_POINT *ki = 0;
	EC_POINT **pk = malloc(2*sizeof(EC_POINT*));
	
	long dbase = 8;
	long dexp = 8;
	int inputs = 8;

	BIGNUM ***sk = malloc(2*sizeof(BIGNUM*)*inputs);
	EC_POINT **ki = 0;
	EC_POINT ***pk = malloc(2*sizeof(EC_POINT*)*inputs);

	printf("Ring size %lf\n Inputs: %d\n", pow(dbase, dexp), inputs);

	printf("Keygen...");
	RTRS_keygen(ctx, sk, &ki, pk);
	puts("done");
	
	struct RTRS_comm comm = {
		.ki = ki,
		.pk = pk,
		.pk_rows = dbase,
		.pk_cols = dexp,
		// TODO co
	};
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
