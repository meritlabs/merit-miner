// Cuckoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2017 John Tromp
// Copyright (c) 2017-2018 The Merit Foundation developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// inspired by https://github.com/tromp/cuckoo/commit/65cabf4651a8e572e99714699fbeb669565910af

#include "cuckoo.hpp"

#include "blake2/blake2.h"

#include <assert.h>
#include <string.h> // for functions strlen, memset
#include <sys/time.h>

#ifndef __APPLE__
#include <endian.h>    // for htole32/64
#else
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#endif

#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )
#define SIPROUND \
  do { \
    v0 += v1; v2 += v3; v1 = ROTL(v1,13); \
    v3 = ROTL(v3,16); v1 ^= v0; v3 ^= v2; \
    v0 = ROTL(v0,32); v2 += v1; v0 += v3; \
    v1 = ROTL(v1,17);   v3 = ROTL(v3,21); \
    v1 ^= v2; v3 ^= v0; v2 = ROTL(v2,32); \
  } while(0)

#define MAXPATHLEN 8192

/** Minimum number of edge bits for cuckoo miner - block.nEdgeBits value */
static const uint16_t MIN_EDGE_BITS = 16;
/** Maximum number of edge bits for cuckoo miner - block.nEdgeBits value */
static const uint16_t MAX_EDGE_BITS = 31;

// siphash uses a pair of 64-bit keys,
typedef struct {
    uint64_t k0;
    uint64_t k1;
} siphash_keys;

uint64_t siphash24(const siphash_keys* keys, const uint64_t nonce)
{
    uint64_t v0 = keys->k0 ^ 0x736f6d6570736575ULL,
             v1 = keys->k1 ^ 0x646f72616e646f6dULL,
             v2 = keys->k0 ^ 0x6c7967656e657261ULL,
             v3 = keys->k1 ^ 0x7465646279746573ULL ^ nonce;
    SIPROUND;
    SIPROUND;
    v0 ^= nonce;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return (v0 ^ v1) ^ (v2 ^ v3);
}

// convenience function for extracting siphash keys from header
void setKeys(const uint32_t* header, const uint32_t headerlen, siphash_keys* keys)
{
    char hdrkey[32];
    blake2b((void*)hdrkey, sizeof(hdrkey), (const void*)header, headerlen, nullptr, 0);

    keys->k0 = htole64(((uint64_t*)hdrkey)[0]);
    keys->k1 = htole64(((uint64_t*)hdrkey)[1]);
}

// generate edge endpoint in cuckoo graph without partition bit
uint32_t _sipnode(const siphash_keys* keys, uint32_t mask, uint32_t nonce, uint32_t uorv)
{
    return siphash24(keys, 2 * nonce + uorv) & mask;
}

uint32_t sipnode(const siphash_keys* keys, uint32_t mask, uint32_t nonce, uint32_t uorv)
{
    auto node = _sipnode(keys, mask, nonce, uorv);

    return node << 1 | uorv;
}

const char* errstr[] = {
    "OK",
    "wrong header length",
    "nonce too big",
    "nonces not ascending",
    "endpoints don't match up",
    "branch in cycle",
    "cycle dead ends",
    "cycle too short"};

class CuckooCtx
{
public:
    siphash_keys m_keys;
    uint32_t m_difficulty;
    uint32_t* m_cuckoo;

    CuckooCtx(const uint32_t* header, const uint32_t headerlen, uint32_t difficulty, uint32_t nodesCount)
    {
        setKeys(header, headerlen, &m_keys);

        m_difficulty = difficulty;
        m_cuckoo = (uint32_t*)calloc(1 + nodesCount, sizeof(uint32_t));

        assert(m_cuckoo != 0);
    }

    ~CuckooCtx()
    {
        free(m_cuckoo);
    }
};

int path(uint32_t* cuckoo, uint32_t u, uint32_t* us)
{
    int nu;
    for (nu = 0; u; u = cuckoo[u]) {
        if (++nu >= MAXPATHLEN) {
            printf("nu is %d\n", nu);
            while (nu-- && us[nu] != u)
                ;
            if (nu < 0)
                printf("maximum path length exceeded\n");
            else
                printf("illegal % 4d-cycle\n", MAXPATHLEN - nu);
            exit(0);
        }
        us[nu] = u;
    }
    return nu;
}

typedef std::pair<uint32_t, uint32_t> edge;

void solution(CuckooCtx* ctx, uint32_t* us, int nu, uint32_t* vs, int nv, std::set<uint32_t>& nonces, const uint32_t edgeMask)
{
    assert(nonces.empty());
    std::set<edge> cycle;

    unsigned n;
    cycle.insert(edge(*us, *vs));
    while (nu--) {
        cycle.insert(edge(us[(nu + 1) & ~1], us[nu | 1])); // u's in even position; v's in odd
    }
    while (nv--) {
        cycle.insert(edge(vs[nv | 1], vs[(nv + 1) & ~1])); // u's in odd position; v's in even
    }

    for (uint32_t nonce = n = 0; nonce < ctx->m_difficulty; nonce++) {
        edge e(sipnode(&ctx->m_keys, edgeMask, nonce, 0), sipnode(&ctx->m_keys, edgeMask, nonce, 1));
        if (cycle.find(e) != cycle.end()) {
            // printf("%x ", nonce);
            cycle.erase(e);
            nonces.insert(nonce);
        }
    }
    // printf("\n");
}

bool FindCycle(const uint32_t* hash, uint8_t edgeBits, uint8_t proofSize, std::set<uint32_t>& cycle)
{
    assert(edgeBits >= MIN_EDGE_BITS && edgeBits <= MAX_EDGE_BITS);

    // printf("Looking for %d-cycle on cuckoo%d(\"%s\") with 50% edges\n", proofSize, edgeBits + 1, hash);
    printf("Looking for %d-cycle on cuckoo%d(\"NaS\") with 50%% edges\n", proofSize, edgeBits + 1);

    uint32_t nodesCount = 1 << (edgeBits + 1);
    // edge mask is a max valid value of an edge.
    // edge mask is twice less then nodes count - 1
    // if nodesCount if 0x1000 then mask is 0x7ff
    uint32_t edgeMask = (1 << edgeBits) - 1;

    // set 50% difficulty - generate half of nodesCount number of edges
    uint32_t difficulty = (uint64_t)nodesCount / 2;

    CuckooCtx ctx(hash, 32, difficulty, nodesCount);

    uint32_t timems;
    struct timeval time0, time1;
    gettimeofday(&time0, 0);

    uint32_t* cuckoo = ctx.m_cuckoo;
    uint32_t us[MAXPATHLEN], vs[MAXPATHLEN];
    for (uint32_t nonce = 0; nonce < ctx.m_difficulty; nonce++) {
        uint32_t u0 = sipnode(&ctx.m_keys, edgeMask, nonce, 0);
        if (u0 == 0) continue; // reserve 0 as nil; v0 guaranteed non-zero
        uint32_t v0 = sipnode(&ctx.m_keys, edgeMask, nonce, 1);
        uint32_t u = cuckoo[u0], v = cuckoo[v0];
        us[0] = u0;
        vs[0] = v0;

        int nu = path(cuckoo, u, us), nv = path(cuckoo, v, vs);
        if (us[nu] == vs[nv]) {
            int min = nu < nv ? nu : nv;
            for (nu -= min, nv -= min; us[nu] != vs[nv]; nu++, nv++)
                ;
            int len = nu + nv + 1;
            printf("% 4d-cycle found at %d%%\n", len, (int)(nonce * 100L / difficulty));
            if (len == proofSize) {
                solution(&ctx, us, nu, vs, nv, cycle, edgeMask);

                gettimeofday(&time1, 0);
                timems = (time1.tv_sec - time0.tv_sec) * 1000 + (time1.tv_usec - time0.tv_usec) / 1000;
                printf("Time: %d ms\n", timems);

                return true;
            }
            continue;
        }
        if (nu < nv) {
            while (nu--)
                cuckoo[us[nu + 1]] = us[nu];
            cuckoo[u0] = v0;
        } else {
            while (nv--)
                cuckoo[vs[nv + 1]] = vs[nv];
            cuckoo[v0] = u0;
        }
    }

    gettimeofday(&time1, 0);
    timems = (time1.tv_sec - time0.tv_sec) * 1000 + (time1.tv_usec - time0.tv_usec) / 1000;
    printf("Time: %d ms\n", timems);

    return false;
}

extern "C" {
  bool findcycle(const uint32_t* hash, uint8_t edgeBits, uint8_t proofSize, uint32_t* cycle) {
    std::set<uint32_t> sCycle;

    FindCycle(hash, edgeBits, proofSize, sCycle);

    if (sCycle.size() != proofSize) {
        return false;
    }

    for(const auto& edge: sCycle) {
        *cycle = edge;
        ++cycle;
    }

    return true;
  }
}