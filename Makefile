all: yggdrasil-brute-curve25519 yggdrasil-brute-ed25519

yggdrasil-brute-curve25519: yggdrasil-brute-curve25519.c
	gcc -O3 -o yggdrasil-brute-curve25519 -lsodium yggdrasil-brute-curve25519.c

yggdrasil-brute-ed25519: yggdrasil-brute-ed25519.c
	gcc -O3 -o yggdrasil-brute-ed25519 -lsodium yggdrasil-brute-ed25519.c
