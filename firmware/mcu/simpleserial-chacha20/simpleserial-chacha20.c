/*
    SimpleSerial ChaCha20 target, based on simpleserial-base.

    Commands (SimpleSerial 1.1):
      'k' 32 bytes : set 256-bit key
      'n' 16 bytes : set counter (4 bytes, little endian) || nonce (12 bytes)
      'p' 16 bytes : encrypt 16 bytes of plaintext with the first 16 bytes
                     of the keystream block -> returns 'r' with 16 bytes
      'x'  0 bytes : reset key/nonce/counter to zero

    The trigger is high for the full ChaCha20XOR() call (state setup,
    20 rounds, XOR). ChaCha20 itself is taken from
    https://github.com/shiffthq/chacha20/tree/master (see chacha20.c).
*/

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>

#include "simpleserial.h"
#include "chacha20.h"

#define CHACHA20_KEY_LEN   32
#define CHACHA20_NONCE_LEN 12

static uint8_t key[CHACHA20_KEY_LEN];
static uint8_t nonce[CHACHA20_NONCE_LEN];
static uint32_t counter;

uint8_t set_key(uint8_t* k, uint8_t len)
{
	uint8_t i;
	for (i = 0; i < CHACHA20_KEY_LEN; i++)
		key[i] = k[i];
	return 0x00;
}

uint8_t set_nonce(uint8_t* n, uint8_t len)
{
	uint8_t i;
	counter = (uint32_t)n[0]
	        | ((uint32_t)n[1] << 8)
	        | ((uint32_t)n[2] << 16)
	        | ((uint32_t)n[3] << 24);
	for (i = 0; i < CHACHA20_NONCE_LEN; i++)
		nonce[i] = n[4 + i];
	return 0x00;
}

uint8_t encrypt(uint8_t* pt, uint8_t len)
{
	trigger_high();
	ChaCha20XOR(key, counter, nonce, pt, pt, 16);
	trigger_low();

	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
	uint8_t i;
	for (i = 0; i < CHACHA20_KEY_LEN; i++)
		key[i] = 0;
	for (i = 0; i < CHACHA20_NONCE_LEN; i++)
		nonce[i] = 0;
	counter = 0;
	return 0x00;
}

int main(void)
{
	platform_init();
	init_uart();
	trigger_setup();

	simpleserial_init();
	simpleserial_addcmd('k', CHACHA20_KEY_LEN, set_key);
	simpleserial_addcmd('n', 16, set_nonce);
	simpleserial_addcmd('p', 16, encrypt);
	simpleserial_addcmd('x', 0, reset);

	while(1)
		simpleserial_get();
}
