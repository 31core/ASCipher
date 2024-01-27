#include <stdint.h>

#define BLOCK_SIZE_512 64

typedef void * Cipher512;
typedef void * Hasher512;

Cipher512 new_cipher512(uint8_t[32]);
void cipher512_apply(Cipher512, const void *, uint64_t);
Hasher512 new_hasher512();
void hash512_update(Hasher512, const void *, uint64_t);
void hash512_digest(Hasher512, void *);
