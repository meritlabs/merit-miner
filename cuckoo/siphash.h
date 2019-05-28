/*
 * Cuckoo Cycle, a memory-hard proof-of-work
 * Copyright (c) 2013-2018 John Tromp
 * Copyright (C) 2017-2019 The Merit Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the The FAIR MINING License and, alternatively, 
 * GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See LICENSE.md for more details.
 **/

#ifndef MERIT_MINER_SIPHASH_H
#define MERIT_MINER_SIPHASH_H

#include <stdint.h>    // for types uint32_t,uint64_t
#include <immintrin.h> // for _mm256_* intrinsics
#if defined(__linux__)
// Linux 
#include <endian.h>    // for htole32/64

#elif defined(__APPLE__)
// macOS
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)

#elif (defined(_WIN16) || defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__))
// Windows
#include <winsock2.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#define htole32(x) (x)
#define htole64(x) (x)
#elif BYTE_ORDER == BIG_ENDIAN

#define htole32(x) __builtin_bswap32(x)
#define htole64(x) __builtin_bswap64(x)

#else

#error byte order not supported

#endif

#define __BYTE_ORDER    BYTE_ORDER
#define __BIG_ENDIAN    BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN    PDP_ENDIAN

#else
// Nothing matched
#error platform not supported

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
