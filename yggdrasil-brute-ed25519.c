/*
seed: 32 random bytes
sk: sha512(seed)
sk[0] &= 248
sk[31] &= 127
sk[31] |= 64

pk: scalarmult_ed25519_base(sk)


increment seed
generate sk
generate pk
hash = sha512(mypub)

if besthash:
	bestseed = seed
	bestseckey = sk
	bestpubkey = pk
	besthash = hash
*/


#include <sodium.h>
#include <stdio.h>  /* printf */
#include <string.h> /* memcpy */
#include <stdlib.h> /* atoi */
#include <time.h>


int main(int argc, char **argv) {

	unsigned char seed[32];
	unsigned char sk[64];
	unsigned char pk[32];
	unsigned char hash[64];
	unsigned char bestseed[32];
	unsigned char bestsk[32];
	unsigned char bestpk[32];
	unsigned char besthash[64] = {0};

	time_t starttime = time(NULL);
	time_t requestedtime;

	int ones;
	int mask;
	unsigned char c;

	int i;
	int j;


	if (argc != 2) {
		printf("usage: ./yggdrasil-brute-simple-ed25519 [seconds]\n");
		return 1;
	}

	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		printf("sodium init failed!\n");
		return 1;
	}

	requestedtime = atoi(argv[1]);
	if (requestedtime < 0) requestedtime = 0;
	printf("Searching for yggdrasil keys (this will take slightly longer than %ld seconds)\n", requestedtime);

	randombytes_buf(seed, 32);

	goto beginloop;
	while (time(NULL) - starttime < requestedtime) {
		/* generate pubkey, hash, compare, increment secret
		 * this loop should take 4 seconds on modern hardware */
		beginloop:
		for (i = 0; i < (1 << 17); ++i) {
			
			crypto_hash_sha512(sk, seed, 32);

			if (crypto_scalarmult_ed25519_base(pk, sk) != 0) {
				printf("scalarmult to create pub failed!\n");
				return 1;
			}

			crypto_hash_sha512(hash, pk, 32);

			/* update bestkey if new hash is larger (has more ones) */
			if (memcmp(hash, besthash, 64) > 0) {
				memcpy(bestseed, seed, 32);
				memcpy(bestsk, sk, 32);
				memcpy(bestpk, pk, 32);
				memcpy(besthash, hash, 64);
			}

			for (j = 0; j < 32; ++j) if (++seed[j]) break;

		}
	}

	/* validate */
	crypto_hash_sha512(sk, bestseed, 32);
	if (crypto_scalarmult_ed25519_base(pk, sk) != 0) {
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

	printf("Number of leading ones: %d\n", ones);
	printf("Seed: ");
	for (i = 0; i < 32; ++i) {
		printf("%02x", bestseed[i]);
	}
	printf("\nPublic: ");
	for (i = 0; i < 32; ++i) {
		printf("%02x", bestpk[i]);
	}
	printf("\nHash: ");
	for (i = 0; i < 64; ++i) {
		printf("%02x", besthash[i]);
	}
	printf("\n");

	sodium_memzero(bestseed, 32);
	sodium_memzero(bestsk, 64);
	sodium_memzero(seed, 32);
	sodium_memzero(sk, 64);

	return 0;
}

