#ifndef MERIT_MINER_SIPHASH_H
#define MERIT_MINER_SIPHASH_H

#include <stdint.h>    // for types uint32_t,uint64_t
#include <immintrin.h> // for _mm256_* intrinsics
#ifndef __APPLE__
#include <endian.h>    // for htole32/64
#else
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#endif

// siphash uses a pair of 64-bit keys,
typedef struct {
    uint64_t k0;
    uint64_t k1;
} siphash_keys;

#define U8TO64_LE(p) ((p))

// set siphash keys from 16 byte char array
void setkeys(siphash_keys *keys, const char *keybuf) {
  keys->k0 = htole64(((uint64_t *)keybuf)[0]);
  keys->k1 = htole64(((uint64_t *)keybuf)[1]);
}

#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )
#define SIPROUND \
  do { \
    v0 += v1; v2 += v3; v1 = ROTL(v1,13); \
    v3 = ROTL(v3,16); v1 ^= v0; v3 ^= v2; \
    v0 = ROTL(v0,32); v2 += v1; v0 += v3; \
    v1 = ROTL(v1,17);   v3 = ROTL(v3,21); \
    v1 ^= v2; v3 ^= v0; v2 = ROTL(v2,32); \
  } while(0)

// SipHash-2-4 specialized to precomputed key and 8 byte nonces
uint64_t siphash24(const siphash_keys *keys, const uint64_t nonce) {
  uint64_t v0 = keys->k0 ^ 0x736f6d6570736575ULL, v1 = keys->k1 ^ 0x646f72616e646f6dULL,
      v2 = keys->k0 ^ 0x6c7967656e657261ULL, v3 = keys->k1 ^ 0x7465646279746573ULL ^ nonce;
  SIPROUND; SIPROUND;
  v0 ^= nonce;
  v2 ^= 0xff;
  SIPROUND; SIPROUND; SIPROUND; SIPROUND;
  return (v0 ^ v1) ^ (v2  ^ v3);
}

// generate edge endpoint in cuckoo graph without partition bit
uint32_t _sipnode(const siphash_keys *keys, uint32_t mask, uint32_t nonce, uint32_t uorv)
{
    return siphash24(keys, 2 * nonce + uorv) & mask;
}

uint32_t sipnode(const siphash_keys *keys, uint32_t mask, uint32_t nonce, uint32_t uorv)
{
    auto node = _sipnode(keys, mask, nonce, uorv);

    return node << 1 | uorv;
}

#endif // ifndef MERIT_MINER_SIPHASH_H
