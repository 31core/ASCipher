#include <stdint.h>

typedef void * Cipher512;

Cipher512 new_cipher512(uint8_t[32]);
void cipher512_apply(Cipher512, void *, uint64_t);
