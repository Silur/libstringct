#include "multisig.h"
#include <stdio.h>
#include <string.h>

static EC_POINT **
sortkeys(EC_GROUP *group, EC_POINT **keys, unsigned long len)
{
	unsigned long i, j;
	EC_POINT *t;
	for(i=0; i<len; i++)
	{
		EC_POINT *a = keys[i];
		for(j=i+1; j<len; j++)
		{
			EC_POINT *b = keys[j];
			unsigned char *abuf;
			unsigned char *bbuf;
			int alen = EC_POINT_point2buf(group, a,	
					POINT_CONVERSION_UNCOMPRESSED, &abuf, 0);
			int blen = EC_POINT_point2buf(group, b,	
					POINT_CONVERSION_UNCOMPRESSED, &bbuf, 0);
			if(alen != blen)
			{
				fprintf(stderr, "ERROR: %s:%d key sizes are not equal\n", __FILE__, __LINE__);
				return 0;
			}
			int diff = memcmp(abuf, bbuf, alen);
			if(diff > 0)
			{
				t = EC_POINT_dup(keys[i], group);
				keys[i] = keys[j];
				keys[j] = EC_POINT_dup(t, group);
				EC_POINT_free(t);
			}
		}
	}
	return keys;
}

int
RTRS_MS_keygen(EC_GROUP *group, EC_POINT **pubkey, BIGNUM **privkey)
{
	if(*pubkey == 0 || *privkey == 0)
	{
		fprintf(stderr, "ERROR: %s:%d pubkey or privkey is not allocated!\n", __FILE__, __LINE__);
		return 0;
	}

	if(!BN_rand(*privkey, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
	{
		fprintf(stderr, "ERROR: %s:%d Could not set up secure random privkey!\n", __FILE__, __LINE__);
		return 0;
	}

	EC_POINT_mul(group ,*pubkey, 0, EC_GROUP_get0_generator(group), *privkey, 0);
	if(!*pubkey)
	{
		fprintf(stderr, "ERROR: %s:%d Could not set up secure pubkey!\n", __FILE__, __LINE__);
		return 0;
	}
	return 1;
}

unsigned char *
RTRS_MS_sign(EC_GROUP *group, unsigned char *msg, unsigned long msg_len,
		EC_POINT **pubkeys, BIGNUM **privkeys, unsigned long klen)
{
	unsigned long i;
	unsigned char *hash;
	unsigned char *t;
	unsigned long hlen = 0;
	EC_POINT **sorted_pubkeys = sortkeys(group, pubkeys, klen);
	for(i=0; i<klen; i++)
	{
		int tlen = EC_POINT_point2buf(group, sorted_pubkeys[i],	
				POINT_CONVERSION_UNCOMPRESSED, &t, 0);
		if(tlen == 0)
		{
			fprintf(stderr, "ERROR: point serialization error\n");
			return 0;
		}
		hlen += tlen;
		unsigned char *rhash = realloc(hash, hlen);
		if(!rhash)
		{
			perror("memory allocation error ");
			free(hash);
			return 0;
		}
		hash = rhash;
		memcpy(hash+hlen, t, tlen);
	}
	BIGNUM *xasterisk = BN_hash(hash, hlen);

	BIGNUM **r_array = malloc(sizeof(BIGNUM*)*klen);
	BIGNUM *r_sum = BN_new();
	BN_zero(r_sum);
	for(i=0; i<klen; i++)
	{
		r_array[i] = BN_new();
		BN_rand(r_array[i], 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
		BN_add(r_sum, r_sum, r_array[i]);
	}
	const EC_POINT *G = EC_GROUP_get0_generator(group);
	EC_POINT *R = EC_POINT_new(group);
	EC_POINT_mul(group, R, 0, G, r_sum, 0);

	BIGNUM **c = malloc(sizeof(BIGNUM*)*klen);
	BIGNUM **s_array = malloc(sizeof(BIGNUM*)*klen);
	BIGNUM *s_sum = BN_new();
	BN_zero(s_sum);
	free(hash); hash = 0;
	free(t);	t = 0;
	hlen = 0;
	unsigned char *XIbuf;
	unsigned char *Rbuf;
	int Rbuf_len = EC_POINT_point2buf(group, R,
			POINT_CONVERSION_UNCOMPRESSED, &Rbuf, 0);
	unsigned char *Xastbuf = malloc(BN_num_bytes(xasterisk));
	int Xastbuf_len = BN_bn2bin(xasterisk, Xastbuf);
	for(i=0; i<klen; i++)
	{
		int tlen = EC_POINT_point2buf(group, sorted_pubkeys[i],
				POINT_CONVERSION_UNCOMPRESSED, &XIbuf, 0);
		hlen = Rbuf_len + Xastbuf_len + tlen + msg_len;
		hash = malloc(hlen);
		memcpy(hash, XIbuf, tlen);
		memcpy(hash+tlen, Rbuf, Rbuf_len);
		memcpy(hash+tlen+Rbuf_len, Xastbuf, Xastbuf_len);
		memcpy(hash+tlen+Rbuf_len+Xastbuf_len, msg, msg_len);
		c[i] = BN_hash(hash, hlen);
		s_array[i] = BN_new();
		BN_mul(s_array[i], privkeys[i], c[i], 0);
		BN_add(s_array[i], r_array[i], s_array[i]);
		BN_add(s_sum, s_sum, s_array[i]);
	}
	unsigned char *ret = malloc(Rbuf_len + BN_num_bytes(s_sum));
	memcpy(ret, Rbuf, Rbuf_len);
	memcpy(ret, s_sum, BN_num_bytes(s_sum));
	return ret;

}
