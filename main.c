/*
mysecret: 32 random bytes
mysecret[0] &= 248;
mysecret[31] &= 127;
mysecret[31] |= 64;

increment mysecret
mypub = curve25519(mysecret, 9)
myhash = sha512(mypub)

ones = count_ones(myhash)
if ones > max:
	bestseckey = mysecret
	max = ones
*/


#include <sodium.h>
#include <stdio.h>  // printf
#include <string.h> // memcpy
#include <stdlib.h> // atoi
#include <time.h>


int main(int argc, char **argv) {
	if (argc != 2) {
		printf("usage: ./yggdrasil-brute-simple [seconds]\n");
		return 1;
	}

	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		printf("sodium init failed!\n");
		return 1;
	}

	time_t requestedtime = atoi(argv[1]);
	time_t starttime = time(NULL);

	printf("Searching for yggdrasil keys (this will take %ld-%ld seconds)\n", requestedtime, requestedtime + 5);

	/* generate curve25519 secret key */
	unsigned char mysecret[32];
	randombytes_buf(mysecret, 32);
	mysecret[0] &= 248;
	mysecret[31] &= 127;
	mysecret[31] |= 64;

	unsigned char basepoint[32] = {9}; // 9 followed by zeroes
	if (basepoint[0] != 9 || basepoint[1] != 0) {
		printf("basepoint creation failed!\n");
		return 1;
	}

	/* generate curve25519 public key */
	unsigned char mypub[32];
	if (crypto_scalarmult_curve25519(mypub, mysecret, basepoint) != 0) {
		printf("scalarmult to create initial pub failed!\n");
		return 1;
	}

	int ones_max = 0;
	int ones_current = 0;
	unsigned char bestsecret[32];
	unsigned char bestpub[32];
	unsigned char myhash[64];

	memcpy(bestsecret, mysecret, 32);
	memcpy(bestpub, mypub, 32);

	while (time(NULL) - starttime < requestedtime) {
		/* hash, compare, increment secret, generate pubkey.
		 * this loop should take 4 seconds on modern hardware */
		for (int i = 0; i < (1 << 16); ++i) {
			crypto_hash_sha512(myhash, mypub, 32);

			/* count number of leading ones */
			ones_current = 0;
			for (int j = 0; j < 64; ++j) {
				unsigned char b = myhash[j];
				for (int k = 0; k < 8; ++k) {
					if (b & 128) {
						b <<= 1;
						++ones_current;
					} else {
						goto check;
					}
				}
			}

			check:
			if (ones_current > ones_max) {
				ones_max = ones_current;
				memcpy(bestpub, mypub, 32);
				memcpy(bestsecret, mysecret, 32);
			}
		

			for (int j = 1; j < 31; ++j) {
				if (++mysecret[j]) {
					break;
				}
			}

			if (crypto_scalarmult_curve25519(mypub, mysecret, basepoint) != 0) {
				printf("scalarmult to create pub failed!\n");
				return 1;
			}
		}
	}

	unsigned char validatepub[32];
	if (crypto_scalarmult_curve25519(validatepub, bestsecret, basepoint) != 0) {
		printf("scalarmult to validate public key failed!\n");
		return 1;
	}
	if (memcmp(validatepub, bestpub, 32) != 0) {
		printf("validate public key failed!\n");
		return 1;
	}

	unsigned char besthash[64];
	crypto_hash_sha512(besthash, bestpub, 32);

	unsigned char addr[16];
	addr[0] = 2;
	addr[1] = ones_max;

	unsigned char c;
	int offset = ones_max;
	for (int i = 0; i < 14; ++i) {
		c = besthash[offset/8] << (offset%8);
		c |= besthash[offset/8 + 1] >> (8 - offset%8);
		addr[i + 2] = c;
		offset += 8;
	}

	printf("Number of leading ones: %d\n", ones_max);
	printf("Secret: ");
	for (int i = 0; i < 32; ++i) {
		printf("%02x", bestsecret[i]);
	}
	printf("\nPublic: ");
	for (int i = 0; i < 32; ++i) {
		printf("%02x", bestpub[i]);
	}
	printf("\nHash: ");
	for (int i = 0; i < 64; ++i) {
		printf("%02x", besthash[i]);
	}
	printf("\nAddress: ");
	for (int i = 0; i < 16; ++i) {
		printf("%02x", addr[i]);
	}
	printf("\n");

	sodium_memzero(mysecret, 32);
	sodium_memzero(bestsecret, 32);

	return 0;
}
