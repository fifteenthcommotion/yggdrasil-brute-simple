/*
sk: 32 random bytes
sk[0] &= 248;
sk[31] &= 127;
sk[31] |= 64;

increment sk
pk = curve25519_scalarmult_base(mysecret)
hash = sha512(pk)

if besthash:
	bestsk = sk
	besthash = hash
*/


#include <sodium.h>
#include <stdio.h>  /* printf */
#include <string.h> /* memcpy */
#include <stdlib.h> /* atoi */
#include <time.h>


int main(int argc, char **argv) {

	unsigned char sk[32];
	unsigned char pk[32];
	unsigned char hash[64];
	unsigned char bestsk[32];
	unsigned char bestpk[32];
	unsigned char besthash[64] = {0};

	time_t starttime = time(NULL);
	time_t requestedtime;

	int ones;
	int mask;
	unsigned char c;
	unsigned char addr[16] = {2};
	int offset;

	int i;
	int j;


	if (argc != 2) {
		printf("usage: ./yggdrasil-brute-curve25519 <seconds>\n");
		return 1;
	}

	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		printf("sodium init failed!\n");
		return 1;
	}

	requestedtime = atoi(argv[1]);
	if (requestedtime < 0) requestedtime = 0;
	printf("Searching for yggdrasil curve25519 keys (this will take slightly longer than %ld seconds)\n", requestedtime);

	randombytes_buf(sk, 32);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;

	goto beginloop;
	while (time(NULL) - starttime < requestedtime) {
		/* generate pubkey, hash, compare, increment secret.
		 * this loop should take 4 seconds on modern hardware */
		beginloop:
		for (i = 0; i < (1 << 17); ++i) {

			if (crypto_scalarmult_curve25519_base(pk, sk)  != 0) {
				printf("scalarmult to create pub failed!\n");
				return 1;
			}

			crypto_hash_sha512(hash, pk, 32);

			/* update bestkey if new hash is larger (has more ones) */
			if (memcmp(hash, besthash, 64) > 0) {
				memcpy(bestpk, pk, 32);
				memcpy(bestsk, sk, 32);
				memcpy(besthash, hash, 64);
			}

			for (j = 1; j < 31; ++j) if (++sk[j]) break;
		}
	}

	/* validate */
	if (crypto_scalarmult_curve25519_base(pk, bestsk) != 0) {
		printf("scalarmult to validate public key failed!\n");
		return 1;
	}
	if (memcmp(pk, bestpk, 32) != 0) {
		printf("validate public key failed!\n");
		return 1;
	}

	/* count leading ones */
	ones = 0;
	for (i = 0; i < 64; ++i) {
		mask = 128;
		c = besthash[i];
		while (mask) {
			if (c & mask) ++ones;
			else goto endcount;
			mask >>= 1;
		}
	}
	endcount: ;

	/* addr[0] = 2; */
	addr[1] = ones;

	offset = ones + 1;
	for (i = 0; i < 14; ++i) {
		c = besthash[offset/8] << (offset%8);
		c |= besthash[offset/8 + 1] >> (8 - offset%8);
		addr[i + 2] = c;
		offset += 8;
	}

	printf("Number of leading ones: %d\n", ones);
	printf("Secret: ");
	for (i = 0; i < 32; ++i) {
		printf("%02x", bestsk[i]);
	}
	printf("\nPublic: ");
	for (i = 0; i < 32; ++i) {
		printf("%02x", bestpk[i]);
	}
	printf("\nHash: ");
	for (i = 0; i < 64; ++i) {
		printf("%02x", besthash[i]);
	}
	printf("\nAddress: ");
	for (i = 0; i < 16; ++i) {
		printf("%02x", addr[i]);
	}
	printf("\n");

	sodium_memzero(bestsk, 32);
	sodium_memzero(sk, 32);

	return 0;
}

