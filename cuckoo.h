
/*
 * Copyright (C) 2017-2019 The Merit Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See LICENSE.md for more details.
 */

#ifndef MERIT_MINER_CUCKOO_H
#define MERIT_MINER_CUCKOO_H

#include <stdint.h>
#include <stdbool.h>

#define CUCKOO_CYCLE_LENGTH 42

bool findcycle(const char* hash, uint8_t edgeBits, uint8_t proofSize, uint32_t* cycle, int threads);

#endif // MERIT_MINER_CUCKOO_H
