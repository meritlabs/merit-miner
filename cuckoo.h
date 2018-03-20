
#ifndef MERIT_MINER_CUCKOO_H
#define MERIT_MINER_CUCKOO_H

#include <stdint.h>
#include <stdbool.h>

#define CUCKOO_CYCLE_LENGTH 42

bool findcycle(const char* hash, uint8_t edgeBits, uint8_t proofSize, uint32_t* cycle);

#endif // MERIT_MINER_CUCKOO_H
