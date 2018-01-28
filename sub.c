#include <openssl/ec.h>
#include <openssl/bn.h>
#include "rtrs.h"


extern void **RTRS_sub(struct RTRS_CTX *ctx, struct RTRS_challenge *fin, EC_POINT **ret)
{
	EC_POINT ***pkz = malloc(sizeof(EC_POINT**)*fin->l);
	BIGNUM **f = malloc(sizeof(BIGNUM*)*fin->l);
	unsigned long j;
	for(j=0; j<fin->l; j++)
	{
		// TODO
	}
}
