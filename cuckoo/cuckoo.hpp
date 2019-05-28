/*
 * Cuckoo Cycle, a memory-hard proof-of-work
 * Copyright (c) 2013-2017 John Tromp
 * Copyright (C) 2017-2019 The Merit Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the The FAIR MINING License and, alternatively, 
 * GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See LICENSE.md for more details.
 **/

#ifndef MERIT_MINER_CUCKOO_H
#define MERIT_MINER_CUCKOO_H

#include "ctpl/ctpl.h"
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
bool FindCycleAdvanced(const char *hash, uint8_t edgeBits, uint8_t proofSize, std::set<uint32_t>& cycle, ctpl::thread_pool&);

#endif // MERIT_MINER_CUCKOO_H
