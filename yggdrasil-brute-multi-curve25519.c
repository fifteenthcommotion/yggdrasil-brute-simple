/*
thread:
	maintain local bestlist
	merge into global bestlist
*/


#include <sodium.h>
#include <stdio.h>  /* printf */
#include <string.h> /* memcpy */
#include <stdlib.h> /* atoi */
#include <time.h>

#define NUMKEYS 10

void zero_lists(unsigned char sklist[NUMKEYS][32],
	unsigned char pklist[NUMKEYS][32],
	unsigned char hashlist[NUMKEYS][64]) {

	int i;
	int j;
	for (i = 0; i < NUMKEYS; ++i) {
		for (j = 0; j < 32; ++j) {
			sklist[i][j] = 0;
			pklist[i][j] = 0;
			hashlist[i][j] = 0;
			hashlist[i][32+j] = 0;
		}
	}
}

void make_addr(unsigned char addr[32], unsigned char hash[64]) {
	int i;
	int offset;
	unsigned char mask;
	unsigned char c;
	int ones = 0;
	for (i = 0; i < 64; ++i) {
		mask = 128;
		c = hash[i];
		while (mask) {
			if (c & mask) ++ones;
			else goto endcount;
			mask >>= 1;
		}
	}
	endcount: ;

	addr[0] = 2;
	addr[1] = ones;

	offset = ones + 1;
	for (i = 0; i < 14; ++i) {
		c = hash[offset/8] << (offset%8);
		c |= hash[offset/8 + 1] >> (8 - offset%8);
		addr[i + 2] = c;
		offset += 8;
	}
}



inline void seed(unsigned char sk[32]) {
	randombytes_buf(sk, 32);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;
}

	

int main(int argc, char **argv) {
	int numthreads;
	int i;
	int j;
	unsigned char addr[16];
	time_t starttime;
	time_t requestedtime;

	unsigned char bestsklist[NUMKEYS][32];
	unsigned char bestpklist[NUMKEYS][32];
	unsigned char besthashlist[NUMKEYS][64];

	unsigned char sk[32];
	unsigned char pk[32];
	unsigned char hash[64];

	unsigned int runs = 0;
	int where;


	if (argc != 2) {
		fprintf(stderr, "usage: ./yggdrasil-brute-multi-curve25519 <seconds>\n");
		return 1;
	}

	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		printf("sodium init failed!\n");
		return 1;
	}

	starttime = time(NULL);
	requestedtime = atoi(argv[1]);

	if (requestedtime < 0) requestedtime = 0;
	fprintf(stderr, "Searching for yggdrasil curve25519 keys (this will take up to a minute longer than %ld seconds)\n", requestedtime);

	zero_lists(bestsklist, bestpklist, besthashlist);
	seed(sk);

	goto beginloop;
	while (time(NULL) - starttime < requestedtime || runs < NUMKEYS) {
		/* generate pubkey, hash, compare, increment secret.
		 * this loop should take 4 seconds on modern hardware */
		beginloop:
		for (i = 0; i < (1 << 16); ++i) {
			++runs;
			if (crypto_scalarmult_curve25519_base(pk, sk) != 0) {
				printf("scalarmult to create pub failed!\n");
				return 1;
			}
			crypto_hash_sha512(hash, pk, 32);

			/* insert into local list of good key */
			where = -1;
			for (j = 0; j < NUMKEYS; ++j) {
				if (memcmp(hash, besthashlist[j], 64) > 0) ++where;
				else break;
			}
			if (where >= 0) {
				for (j = 0; j < where; ++j) {
					memcpy(bestsklist[j], bestsklist[j+1], 32);
					memcpy(bestpklist[j], bestpklist[j+1], 32);
					memcpy(besthashlist[j], besthashlist[j+1], 64);
				}
				memcpy(bestsklist[where], sk, 32);
				memcpy(bestpklist[where], pk, 32);
				memcpy(besthashlist[where], hash, 64);

				seed(sk);
			}
			for (j = 1; j < 31; ++j) if (++sk[j]) break;
		}
	}


	fprintf(stderr, "--------------addr-------------- -----------------------------secret----------------------------- -----------------------------public-----------------------------\n");
	for (i = 0; i < NUMKEYS; ++i) {
		make_addr(addr, besthashlist[i]);
		for (j = 0; j < 16; ++j) printf("%02x", addr[j]);
		printf(" ");
		for (j = 0; j < 32; ++j) printf("%02x", bestsklist[i][j]);
		printf(" ");
		for (j = 0; j < 32; ++j) printf("%02x", bestpklist[i][j]);
		printf("\n");
	}

	return 0;
}

