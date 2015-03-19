/* 
 * This library implements the HC-128 algorithm
 * Developed - Hongjun Wu, Katholieke Universiteit Leuven
 * HC-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef HC128_H
#define HC128_H

/* 
 * HC128 context
 * keylen - chiper key length in bytes
 * ivlen - vector initialization length in bytes
 * key - chiper key
 * iv - initialization vector
 * w - array with 1024 32-bit elements
 * x - array with 16 32-bit elements (for intermediate calculations)
 * y - array with 16 32-bit elements (for intermediate calculations)
 * counter - the counter system
*/
struct hc128_context {
	int keylen;
	int ivlen;
	uint8_t key[16];
	uint8_t iv[16];
	uint32_t w[1024];
	uint32_t x[16];
	uint32_t y[16];
	uint32_t counter;
};

void hc128_init(struct hc128_context *ctx);

int hc128_set_key_and_iv(struct hc128_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16], const int ivlen);

void hc128_encrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void hc128_decrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

void hc128_test_vectors(struct hc128_context *ctx);

#endif
