#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <netinet/in.h>

#include "Hash.h"

#define KEY {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76}
// #define first_n_bit_mask(n)	(~(0xFFFFFFFFUL >> (n)))
in_addr_t first_n_bit_mask(int n)
	{
	return (n >= 32 ? 0xFFFFFFFFUL : ~(0xFFFFFFFFUL >> n));
	}

in_addr_t anonymize(in_addr_t a, u_char* anon_key)
	{

        //assume the provided ip address is in network byte order
        //since the original codes assumed the given ip address is
        //in local host byte order, for simplicity, switch a to 
        //local host byte order here.
	a = ntohl(a);

	// For each bit, we decide whether to flip the bit from the
	// input by hashing the prefix before the bit, so that the
	// flipping does not depend on the order of inputs given, and
	// with the same hash key, we can have a consistent mapping.
	// For details, see: J. Xu et.al.: "On the design and
	// performance of prefix-preserving IP traffic trace anonymization"

	struct { in_addr_t prefix; int len; } prefix;

	in_addr_t output = 0;

	int i;
	for (i = 0; i < 32; ++i )
		{
		// Note: apply htonl to insure the layout to be the
		// same on machines with different byte order

		prefix.prefix = htonl(a & first_n_bit_mask(i));
		prefix.len = htonl(i);

		u_char digest[16];
		if(anon_key == NULL){
		    u_char key[16];
		    anon_key = key;
		}
		hmac_md5(anon_key, sizeof(prefix), (u_char*)(&prefix), digest);
		int flip = digest[0] & 1;

		in_addr_t bit_mask = 1 << (31-i); //for retrieving the first i+1 bits
		output = output | ((flip << (31-i)) ^ (a & bit_mask));
		}

	return output;
	}
