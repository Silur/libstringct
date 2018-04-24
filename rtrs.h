#ifndef __RTRS_H
#define __RTRS_H
#include <openssl/bn.h>
#include <openssl/ec.h>

struct RTRS_CTX {
	BN_CTX *bnctx;
	EC_GROUP *curve;
};

struct RTRS_comm {
	EC_POINT **ki;
	size_t ki_len;
	EC_POINT ***pk[2];
	size_t pk_rows;
	size_t pk_cols;
	EC_POINT **co;
	size_t co_len;
	EC_POINT *co1;
	char *M;
	size_t m_len;
	int iasterisk;
	unsigned long l; // inputs
	unsigned long n; // ring size
};

extern struct RTRS_CTX *RTRS_init(BIGNUM *a, BIGNUM *b, BIGNUM *p, 
		char *generator, char *coefficient, 
		int montgomery);
extern void RTRS_free(struct RTRS_CTX *ctx);
extern int RTRS_keygen(struct RTRS_CTX *ctx, BIGNUM **sk, EC_POINT **ki, EC_POINT **pk);
extern void RTRS_sub(struct RTRS_CTX *ctx, struct RTRS_comm *fin, 
		EC_POINT ***ret, BIGNUM ***f_ret);
extern int RTRS_comm_serialize(struct RTRS_CTX *ctx, struct RTRS_comm *c, 
		char **ret, char *M, size_t m_len);
extern size_t RTRS_spend(unsigned char **ret, struct RTRS_CTX *ctx, BIGNUM ***sk, int sklen, BIGNUM *s, struct RTRS_comm *f, int d[2]);
extern int RTRS_verify(struct RTRS_CTX *ctx, struct RTRS_comm *comm, EC_POINT ***pks, EC_POINT **kis, unsigned char *msg, size_t msglen); 
#endif
