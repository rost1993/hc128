/* This library implements the HC-128 algorithm
 * Developed - Hongjun Wu, Katholieke Universiteit Leuven
 * HC-128 - the winner eSTREAM. Home page - http://www.ecrypt.eu.org/stream/
*/

#ifndef HC128_H_
#define HC128_H_

struct hc128_context;

struct hc128_context *hc128_context_new(void);
void hc128_context_free(struct hc128_context **ctx);

int hc128_set_key_and_iv(struct hc128_context *ctx, const uint8_t *key, const int keylen, const uint8_t iv[16]);

void hc128_encrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);
void hc128_decrypt(struct hc128_context *ctx, const uint8_t *buf, uint32_t buflen, uint8_t *out);

#endif
