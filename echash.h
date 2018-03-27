#ifndef __RTRS_ECHASH_H
#define __RTRS_ECHASH_H
#include <openssl/bn.h>
BIGNUM *BN_hash(unsigned char *data, size_t len);
#endif
