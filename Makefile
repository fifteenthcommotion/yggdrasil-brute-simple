.PHONY: all

CC = cc
CFLAGS = -Wall -std=c89 -O3 $$(pkg-config --cflags libsodium)
LIBS = $$(pkg-config --libs libsodium)

all: util yggdrasil-brute-multi-curve25519 yggdrasil-brute-multi-ed25519

util: util.c
	$(CC) $(CFLAGS) -c -o util.o util.c

yggdrasil-brute-multi-ed25519: yggdrasil-brute-multi-ed25519.c util.o
	$(CC) $(CFLAGS) $(LIBS) -o yggdrasil-brute-multi-ed25519 yggdrasil-brute-multi-ed25519.c util.o

yggdrasil-brute-multi-curve25519: yggdrasil-brute-multi-curve25519.c util.o
	$(CC) $(CFLAGS) $(LIBS) -o yggdrasil-brute-multi-curve25519 yggdrasil-brute-multi-curve25519.c util.o
