#ifndef RTRS_MULTISIG_H
#define RTRS_MULTISIG_H
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "echash.h"
int RTRS_MS_keygen(EC_GROUP *group, EC_POINT **pubkey, BIGNUM **privkey);
unsigned char *RTRS_MS_sign(EC_GROUP *group, unsigned char *msg, unsigned long msg_len, EC_POINT **pubkeys, BIGNUM **privkeys, unsigned long klen);
int RTRS_MS_verify(EC_GROUP *group, unsigned char *msg, unsigned long len, EC_POINT *pubkey, unsigned char *signature, unsigned long slen);
#endif
