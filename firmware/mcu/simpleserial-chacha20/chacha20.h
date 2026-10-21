/*
 * ChaCha20 (RFC 7539 / RFC 8439)
 *
 * Source: https://github.com/shiffthq/chacha20/tree/master (chacha20.h)
 * Taken unchanged except for this comment.
 */
#ifndef __CHACHA20_H
#define __CHACHA20_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *input, uint8_t *output, int inputlen);

#ifdef __cplusplus
}
#endif

#endif
