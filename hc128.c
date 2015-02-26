/* 
 * This program implements the HC-128 algorithm. 
 * Developed Hongjun Wu Katholieke Universiteit Leuven.
 * The HC-128 home page - http://www.ecrypt.eu.org/stream/.
 * --------------------
 * Author: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab). 
 * Assistant project manager: Lipin Boris (dzruyk).
 * Project manager: Grisha Sitkarev.
 * --------------------
 * Russia, Komi Republic, Syktyvkar - 04.01.2014, version 1.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hc128.h"

#define HC128		128

#define ROTL32(v, n)	((v << n) | (v >> (32 - n)))
#define ROTR32(v, n)	((v >> n) | (v << (32 - n)))

// Selecting the byte order
#if __BYTE_ORDER == __BIG_ENDIAN
#define U32TO32(x)								\
	((x << 24) | ((x << 8) & 0xFF0000) | ((x >> 8) & 0xFF00) | (x >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define U32TO32(x)	(x)
#else
#error unsupported byte order
#endif

#define U8TO32_LITTLE(p)						\
	(((uint32_t)((p)[0])	  ) | ((uint32_t)((p)[1]) << 8) |	\
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// f1 and f2 function
#define F1(x)		(ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define F2(x)		(ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

// g1 and g2 function
#define G1(x, y, z, res) { 					\
	res = (ROTR32(x, 10) ^ ROTR32(z, 23)) + ROTR32(y, 8);	\
}

#define G2(x, y, z, res) {					\
	res = (ROTL32(x, 10) ^ ROTL32(z, 23)) + ROTL32(y, 8);	\
}

// h1 and h2 function
#define H1(ctx, x, res) {				\
	uint8_t a, b;					\
	a = (uint8_t)x;					\
	b = (uint8_t)(x >> 16);				\
	res = ctx->w[512 + a] + ctx->w[512 + 256 + b];	\
}

#define H2(ctx, x, res) {				\
	uint8_t a, b;					\
	a = (uint8_t)x;					\
	b = (uint8_t)(x >> 16);				\
	res = ctx->w[a] + ctx->w[256 + b];		\
}

// Update arrays P[512] and Q[512] (in this case - w[1024])
#define UPDATE_P(ctx, a, b, c, d, e, f) { 			\
	uint32_t res1, res2;					\
	G1(ctx->x[e], ctx->x[d], ctx->w[b], res1);		\
	H1(ctx, ctx->x[f], res2);				\
	ctx->w[a] = (ctx->w[a] + res1) ^ res2; 			\
	ctx->x[c] = ctx->w[a];					\
}

#define UPDATE_Q(ctx, a, b, c, d, e, f) {			\
	uint32_t res1, res2;					\
	G2(ctx->y[e], ctx->y[d], ctx->w[512+b], res1);		\
	H2(ctx, ctx->y[f], res2);				\
	ctx->w[512+a] = (ctx->w[512+a] + res1) ^ res2;		\
	ctx->y[c] = ctx->w[512+a];				\
}

// Generation of key sequence
#define GENERATE_P(ctx, a, b, c, d, e, f, res) {		\
	uint32_t res1, res2;					\
	G1(ctx->x[e], ctx->x[d], ctx->w[b], res1);		\
	H1(ctx, ctx->x[f], res2);				\
	ctx->w[a] += res1;					\
	ctx->x[c] = ctx->w[a];					\
	res = U32TO32((res2 ^ ctx->w[a]));			\
}

#define GENERATE_Q(ctx, a, b, c, d, e, f, res) {		\
	uint32_t res1, res2;					\
	G2(ctx->y[e], ctx->y[d], ctx->w[512+b], res1);		\
	H2(ctx, ctx->y[f], res2);				\
	ctx->w[512+a] += res1;					\
	ctx->y[c] = ctx->w[512+a];				\
	res = U32TO32((res2 ^ ctx->w[512+a]));			\
}

/* 
 * HC128 context
 * keylen - chiper key length
 * key - chiper key
 * iv - initialization vector
 * w - array with 1024 32-bit elements
 * x - array with 16 32-bit elements (for intermediate calculations)
 * y - array with 16 32-bit elements (for intermediate calculations)
 * counter - the counter system
*/
struct hc128_context {
	int keylen;
	uint8_t key[16];
	uint8_t iv[16];
	uint32_t w[1024];
	uint32_t x[16];
	uint32_t y[16];
	uint32_t counter;
};

// Allocates memory for the HC128 context
struct hc128_context *
hc128_context_new(void)
{
	struct hc128_context *ctx;
	ctx = malloc(sizeof(*ctx));

	if(ctx == NULL)
		return NULL;
	
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}

// Delete HC128 context
void
hc128_context_free(struct hc128_context **ctx)
{
	free(*ctx);
	*ctx = NULL;
}

// Function update array w[1024]
static void
hc128_setup_update(struct hc128_context *ctx)
{
	int i, a;
	
	for(i = 0; i < 64; i++) {

		a = ctx->counter & 0x1FF;
		
		if(ctx->counter < 512) {
			UPDATE_P(ctx, a +  0, a +  1,  0,  6, 13,  4);
			UPDATE_P(ctx, a +  1, a +  2,  1,  7, 14,  5);
			UPDATE_P(ctx, a +  2, a +  3,  2,  8, 15,  6);		
			UPDATE_P(ctx, a +  3, a +  4,  3,  9,  0,  7);
			UPDATE_P(ctx, a +  4, a +  5,  4, 10,  1,  8);
			UPDATE_P(ctx, a +  5, a +  6,  5, 11,  2,  9);
			UPDATE_P(ctx, a +  6, a +  7,  6, 12,  3, 10);
			UPDATE_P(ctx, a +  7, a +  8,  7, 13,  4, 11);
			UPDATE_P(ctx, a +  8, a +  9,  8, 14,  5, 12);
			UPDATE_P(ctx, a +  9, a + 10,  9, 15,  6, 13);
			UPDATE_P(ctx, a + 10, a + 11, 10,  0,  7, 14);
			UPDATE_P(ctx, a + 11, a + 12, 11,  1,  8, 15);
			UPDATE_P(ctx, a + 12, a + 13, 12,  2,  9,  0);
			UPDATE_P(ctx, a + 13, a + 14, 13,  3, 10,  1);
			UPDATE_P(ctx, a + 14, a + 15, 14,  4, 11,  2);
			UPDATE_P(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3);
		}
		else {
			UPDATE_Q(ctx, a +  0, a +  1,  0,  6, 13,  4);
			UPDATE_Q(ctx, a +  1, a +  2,  1,  7, 14,  5);
			UPDATE_Q(ctx, a +  2, a +  3,  2,  8, 15,  6);
			UPDATE_Q(ctx, a +  3, a +  4,  3,  9,  0,  7);
			UPDATE_Q(ctx, a +  4, a +  5,  4, 10,  1,  8);
			UPDATE_Q(ctx, a +  5, a +  6,  5, 11,  2,  9);
			UPDATE_Q(ctx, a +  6, a +  7,  6, 12,  3, 10);
			UPDATE_Q(ctx, a +  7, a +  8,  7, 13,  4, 11);
			UPDATE_Q(ctx, a +  8, a +  9,  8, 14,  5, 12);
			UPDATE_Q(ctx, a +  9, a + 10,  9, 15,  6, 13);
			UPDATE_Q(ctx, a + 10, a + 11, 10,  0,  7, 14);
			UPDATE_Q(ctx, a + 11, a + 12, 11,  1,  8, 15);
			UPDATE_Q(ctx, a + 12, a + 13, 12,  2,  9,  0);
			UPDATE_Q(ctx, a + 13, a + 14, 13,  3, 10,  1);
			UPDATE_Q(ctx, a + 14, a + 15, 14,  4, 11,  2);
			UPDATE_Q(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3);
		}
		
		ctx->counter = (ctx->counter + 16) & 0x3FF;
	}
}

// Function initialization process
// System is ready to generate keystream
static void
hc128_initialization_process(struct hc128_context *ctx)
{
	int i;

	for(i = 0; i < 8; i++) {
		ctx->w[i] = U8TO32_LITTLE(ctx->key + (i * 4) % 16);
		ctx->w[i + 8] = U8TO32_LITTLE(ctx->iv + (i * 4) % 16);
	}
	
	for(i = 16; i < (256 + 16); i++)
		ctx->w[i] = F2(ctx->w[i-2]) + ctx->w[i-7] + F1(ctx->w[i-15]) + ctx->w[i-16] + i;
	
	for(i = 0; i < 16; i++)
		ctx->w[i] = ctx->w[256 + i];
	
	for(i = 16; i < 1024; i++)
		ctx->w[i] = F2(ctx->w[i-2]) + ctx->w[i-7] + F1(ctx->w[i-15]) + ctx->w[i-16] + 256 + i;

	for(i = 0; i < 16; i++) {
		ctx->x[i] = ctx->w[496+i];
		ctx->y[i] = ctx->w[1008+i];
	}
	
	hc128_setup_update(ctx);
}

// Fill the HC128 context (key and iv)
// Return value: 0 (if all is well), -1 id all bad
int
hc128_set_key_and_iv(struct hc128_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16])
{
	if(keylen <= HC128)
		ctx->keylen = keylen;
	else
		return -1;
	
	memcpy(ctx->key, key, keylen);
	memcpy(ctx->iv, iv, 16);
	ctx->counter = 0;

	hc128_initialization_process(ctx);

	return 0;
}

// Function generate keystream
static void
hc128_generate_keystream(struct hc128_context *ctx, uint32_t *keystream)
{
	int a;
	a = ctx->counter & 0x1FF;

	if(ctx->counter < 512) {
		GENERATE_P(ctx, a +  0, a +  1,  0,  6, 13,  4, keystream[0]);
		GENERATE_P(ctx, a +  1, a +  2,  1,  7, 14,  5, keystream[1]);
		GENERATE_P(ctx, a +  2, a +  3,  2,  8, 15,  6, keystream[2]);
		GENERATE_P(ctx, a +  3, a +  4,  3,  9,  0,  7, keystream[3]);
		GENERATE_P(ctx, a +  4, a +  5,  4, 10,  1,  8, keystream[4]);
		GENERATE_P(ctx, a +  5, a +  6,  5, 11,  2,  9, keystream[5]);
		GENERATE_P(ctx, a +  6, a +  7,  6, 12,  3, 10, keystream[6]);
		GENERATE_P(ctx, a +  7, a +  8,  7, 13,  4, 11, keystream[7]);
		GENERATE_P(ctx, a +  8, a +  9,  8, 14,  5, 12, keystream[8]);
		GENERATE_P(ctx, a +  9, a + 10,  9, 15,  6, 13, keystream[9]);
		GENERATE_P(ctx, a + 10, a + 11, 10,  0,  7, 14, keystream[10]);
		GENERATE_P(ctx, a + 11, a + 12, 11,  1,  8, 15, keystream[11]);
		GENERATE_P(ctx, a + 12, a + 13, 12,  2,  9,  0, keystream[12]);
		GENERATE_P(ctx, a + 13, a + 14, 13,  3, 10,  1, keystream[13]);
		GENERATE_P(ctx, a + 14, a + 15, 14,  4, 11,  2, keystream[14]);
		GENERATE_P(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3, keystream[15]);
	}
	else {
		GENERATE_Q(ctx, a +  0, a +  1,  0,  6, 13,  4, keystream[0]);
		GENERATE_Q(ctx, a +  1, a +  2,  1,  7, 14,  5, keystream[1]);
		GENERATE_Q(ctx, a +  2, a +  3,  2,  8, 15,  6, keystream[2]);
		GENERATE_Q(ctx, a +  3, a +  4,  3,  9,  0,  7, keystream[3]);
		GENERATE_Q(ctx, a +  4, a +  5,  4, 10,  1,  8, keystream[4]);
		GENERATE_Q(ctx, a +  5, a +  6,  5, 11,  2,  9, keystream[5]);
		GENERATE_Q(ctx, a +  6, a +  7,  6, 12,  3, 10, keystream[6]);
		GENERATE_Q(ctx, a +  7, a +  8,  7, 13,  4, 11, keystream[7]);
		GENERATE_Q(ctx, a +  8, a +  9,  8, 14,  5, 12, keystream[8]);
		GENERATE_Q(ctx, a +  9, a + 10,  9, 15,  6, 13, keystream[9]);
		GENERATE_Q(ctx, a + 10, a + 11, 10,  0,  7, 14, keystream[10]);
		GENERATE_Q(ctx, a + 11, a + 12, 11,  1,  8, 15, keystream[11]);
		GENERATE_Q(ctx, a + 12, a + 13, 12,  2,  9,  0, keystream[12]);
		GENERATE_Q(ctx, a + 13, a + 14, 13,  3, 10,  1, keystream[13]);
		GENERATE_Q(ctx, a + 14, a + 15, 14,  4, 11,  2, keystream[14]);
		GENERATE_Q(ctx, a + 15, ((a + 16) & 0x1FF), 15,  5, 12,  3, keystream[15]);
	}
	
	ctx->counter = (ctx->counter + 16) & 0x3ff;
}

/*
 * HC128 encrypt algorithm.
 * ctx - pointer on HC128 context
 * buf - pointer on buffer data
 * buflen - length the data buffer
 * out - pointer on output array
*/
void
hc128_encrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	uint32_t keystream[16];
	int i;

	for(; buflen >= 64; buflen -= 64, buf += 64, out += 64) {
		hc128_generate_keystream(ctx, keystream);

		*(uint32_t *)(out +  0) = *(uint32_t *)(buf +  0) ^ keystream[ 0];
		*(uint32_t *)(out +  4) = *(uint32_t *)(buf +  4) ^ keystream[ 1];
		*(uint32_t *)(out +  8) = *(uint32_t *)(buf +  8) ^ keystream[ 2];
		*(uint32_t *)(out + 12) = *(uint32_t *)(buf + 12) ^ keystream[ 3];
		*(uint32_t *)(out + 16) = *(uint32_t *)(buf + 16) ^ keystream[ 4];
		*(uint32_t *)(out + 20) = *(uint32_t *)(buf + 20) ^ keystream[ 5];
		*(uint32_t *)(out + 24) = *(uint32_t *)(buf + 24) ^ keystream[ 6];
		*(uint32_t *)(out + 28) = *(uint32_t *)(buf + 28) ^ keystream[ 7];
		*(uint32_t *)(out + 32) = *(uint32_t *)(buf + 32) ^ keystream[ 8];
		*(uint32_t *)(out + 36) = *(uint32_t *)(buf + 36) ^ keystream[ 9];
		*(uint32_t *)(out + 40) = *(uint32_t *)(buf + 40) ^ keystream[10];
		*(uint32_t *)(out + 44) = *(uint32_t *)(buf + 44) ^ keystream[11];
		*(uint32_t *)(out + 48) = *(uint32_t *)(buf + 48) ^ keystream[12];
		*(uint32_t *)(out + 52) = *(uint32_t *)(buf + 52) ^ keystream[13];
		*(uint32_t *)(out + 56) = *(uint32_t *)(buf + 56) ^ keystream[14];
		*(uint32_t *)(out + 60) = *(uint32_t *)(buf + 60) ^ keystream[15];
	}
	
	if(buflen) {
		hc128_generate_keystream(ctx, keystream);
		
		for(i = 0; i < buflen; i++)
			out[i] = buf[i] ^ ((uint8_t *)keystream)[i];
	}
}

// HC128 decrypt function. See hc128_encrypt
void
hc128_decrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out)
{
	hc128_encrypt(ctx, buf, buflen, out);
}


#if __BYTE_ORDER == __BIG_ENDIAN
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x >> 24), ((x >> 16) & 0xFF), ((x >> 8) & 0xFF), (x & 0xFF)))
#else
#define PRINT_U32TO32(x) \
	(printf("%02x %02x %02x %02x ", (x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), (x >> 24)))
#endif

// Test vectors print
void
hc128_test_vectors(struct hc128_context *ctx)
{
	uint32_t keystream[16];
	int i;
	
	hc128_generate_keystream(ctx, keystream);

	printf("\nTest vectors for the HC-128\n");

	printf("\nKey:       ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->key[i]);

	printf("\nIV:        ");

	for(i = 0; i < 16; i++)
		printf("%02x ", ctx->iv[i]);
	
	printf("\nKeystream: ");

	for(i = 0; i < 16; i++) {
		PRINT_U32TO32((keystream[i]));
	}
	
	printf("\n\n");
}

