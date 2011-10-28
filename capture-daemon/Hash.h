#ifndef hash_h
#define hash_h

#include <sys/types.h>
#include <string.h>

#include "md5.h"

typedef u_char HashKey[16];
typedef u_char HashDigest[16];

void hmac_md5(const HashKey key, size_t size, const u_char *bytes, HashDigest digest)
	{
	struct md5_state_s h;
	u_char k_ipad[64];
	u_char k_opad[64];

	bzero(k_ipad, sizeof(k_ipad));
	bcopy(key, k_ipad, sizeof(key));
	bzero(k_opad, sizeof(k_opad));
	bcopy(key, k_opad, sizeof(key));
    int i;
	for (i = 0; i < 64; i++ ) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	md5_init(&h);
	md5_append(&h, k_ipad, sizeof(k_ipad));
	md5_append(&h, bytes, size);
	md5_finish(&h, digest);

	digest[0] ^= (1 & 0xff);
	digest[1] ^= ((1 >> 8) & 0xff);

	md5_init(&h);
	md5_append(&h, k_opad, sizeof(k_opad));
	md5_append(&h, digest, sizeof(digest));
	md5_finish(&h, digest);
	}

#endif /* hash_h */
