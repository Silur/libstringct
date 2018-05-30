#ifndef __RTRS_ECHASH_H
#define __RTRS_ECHASH_H
#include <openssl/bn.h>
#include <openssl/ec.h>
BIGNUM *BN_hash(unsigned char *data, size_t len);
EC_POINT *EC_hash(const EC_GROUP *g, unsigned char *data, size_t len);
#endif
