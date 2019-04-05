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
#include <pthread.h>

#define NUMKEYS 10

unsigned char bestsklist[NUMKEYS][32];
unsigned char bestpklist[NUMKEYS][32];
unsigned char besthashlist[NUMKEYS][64];

pthread_mutex_t mergelock;

time_t starttime;
time_t requestedtime;

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



void merge(unsigned char sklist[NUMKEYS][32],
	unsigned char pklist[NUMKEYS][32],
	unsigned char hashlist[NUMKEYS][64]) {

	/* big merged sorted lists */
	unsigned char bigsklist[NUMKEYS*2][32];
	unsigned char bigpklist[NUMKEYS*2][32];
	unsigned char bighashlist[NUMKEYS*2][64];
	
	int i;
	int l = 0;
	int r = 0;

	pthread_mutex_lock(&mergelock);
	for (i = 0; i < NUMKEYS*2; ++i) {
		if (r == NUMKEYS || memcmp(hashlist[l], besthashlist[r], 64) < 0) {
			/* local hashlist is smaller, insert element from local */
			memcpy(bigsklist[i], sklist[l], 32);
			memcpy(bigpklist[i], pklist[l], 32);
			memcpy(bighashlist[i], hashlist[l++], 64);
		} else {
			/* global hashlist is smaller, insert element from global */
			memcpy(bigsklist[i], bestsklist[r], 32);
			memcpy(bigpklist[i], bestpklist[r], 32);
			memcpy(bighashlist[i], besthashlist[r++], 64);
		}
	}
	for (i = 0; i < NUMKEYS; ++i) {
		/* copy over largest of sorted list to global */
		memcpy(bestsklist[i], bigsklist[NUMKEYS+i], 32);
		memcpy(bestpklist[i], bigpklist[NUMKEYS+i], 32);
		memcpy(besthashlist[i], bighashlist[NUMKEYS+i], 64);
	}
	pthread_mutex_unlock(&mergelock);
}

void* search(void *a) {
	unsigned char localsklist[NUMKEYS][32];
	unsigned char localpklist[NUMKEYS][32];
	unsigned char localhashlist[NUMKEYS][64];

	unsigned char sk[32];
	unsigned char pk[32];
	unsigned char hash[64];

	unsigned int runs = 0;
	int i;
	int j;
	int where;

	zero_lists(localsklist, localpklist, localhashlist);

	seed:
	randombytes_buf(sk, 32);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;

	goto beginloop;
	while (time(NULL) - starttime < requestedtime || runs < NUMKEYS) {
		/* generate pubkey, hash, compare, increment secret.
		 * this loop should take 4 seconds on modern hardware */
		beginloop:
		for (i = 0; i < (1 << 16); ++i) {
			++runs;
			if (crypto_scalarmult_curve25519_base(pk, sk) != 0) {
				printf("scalarmult to create pub failed!\n");
				return NULL;
			}
			crypto_hash_sha512(hash, pk, 32);

			/* insert into local list of good key */
			where = -1;
			for (j = 0; j < NUMKEYS; ++j) {
				if (memcmp(hash, localhashlist[j], 64) > 0) ++where;
				else break;
			}
			if (where >= 0) {
				for (j = 0; j < where; ++j) {
					memcpy(localsklist[j], localsklist[j+1], 32);
					memcpy(localpklist[j], localpklist[j+1], 32);
					memcpy(localhashlist[j], localhashlist[j+1], 64);
				}
				memcpy(localsklist[where], sk, 32);
				memcpy(localpklist[where], pk, 32);
				memcpy(localhashlist[where], hash, 64);

				goto seed;
			}
			for (j = 1; j < 31; ++j) if (++sk[j]) break;
		}
		merge(localsklist, localpklist, localhashlist); /* handle mutex inside function */
	}
	return NULL;
}

int main(int argc, char **argv) {
	int numthreads;
	int i;
	int j;
	unsigned char addr[16];

	if (argc != 3) {
		fprintf(stderr, "usage: ./yggdrasil-brute-multi-curve25519 <seconds> <threads>\n");
		return 1;
	}

	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		printf("sodium init failed!\n");
		return 1;
	}
	if (pthread_mutex_init(&mergelock, NULL) != 0) {
		printf("pthread mutex init failed!\n");
		return 1;
	}

	starttime = time(NULL);
	requestedtime = atoi(argv[1]);
	numthreads = atoi(argv[2]);

	if (requestedtime < 0) requestedtime = 0;
	if (numthreads <= 0) numthreads = 1;
	fprintf(stderr, "Searching for yggdrasil curve25519 keys (this will take slightly longer than %ld seconds)\n", requestedtime);
	fprintf(stderr, "Spinning up %d threads\n", numthreads);

	pthread_t threads[numthreads];
	pthread_attr_t attr;
	zero_lists(bestsklist, bestpklist, besthashlist);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (i = 0; i < numthreads; ++i) {
		pthread_create(&threads[i], &attr, search, NULL);
	}
	for (i = 0; i < numthreads; ++i) {
		pthread_join(threads[i], NULL);
	}


	fprintf(stderr, "-----------------------------secret----------------------------- -----------------------------public----------------------------- --------------addr-------------- --------------------------------------------------------------hash-------------------------------------------------------------- \n");
	for (i = 0; i < NUMKEYS; ++i) {
		make_addr(addr, besthashlist[i]);
		for (j = 0; j < 32; ++j) printf("%02x", bestsklist[i][j]);
		printf(" ");
		for (j = 0; j < 32; ++j) printf("%02x", bestpklist[i][j]);
		printf(" ");
		for (j = 0; j < 16; ++j) printf("%02x", addr[j]);
		printf(" ");
		for (j = 0; j < 64; ++j) printf("%02x", besthashlist[i][j]);
		printf("\n");
	}

	return 0;
}

