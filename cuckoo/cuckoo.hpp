// Cuckoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2017 John Tromp
// Copyright (c) 2017-2018 The Merit Foundation developers

#ifndef MERIT_CUCKOO_CUCKOO_H
#define MERIT_CUCKOO_CUCKOO_H

#include <set>

enum verify_code {
    POW_OK,
    POW_HEADER_LENGTH,
    POW_TOO_BIG,
    POW_TOO_SMALL,
    POW_NON_MATCHING,
    POW_BRANCH,
    POW_DEAD_END,
    POW_SHORT_CYCLE
};

extern const char* errstr[];

// Find proofsize-length cuckoo cycle in random graph
bool FindCycle(const uint32_t* hash, uint8_t edgeBits, uint8_t proofSize, std::set<uint32_t>& cycle);

#endif // MERIT_CUCKOO_CUCKOO_H
