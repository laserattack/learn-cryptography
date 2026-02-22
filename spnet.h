#ifndef SPNET_H
#define SPNET_H

#include <stdlib.h>

uint32_t SP_net32_enc(uint32_t block, uint32_t masterkey, uint32_t rounds);
uint32_t SP_net32_dec(uint32_t block, uint32_t masterkey, uint32_t rounds);

#ifdef SPNET_IMPL

// example: 00110100 -> [cyceshift8, shiftval=5] -> 00000001 | 1010000 -> 101001
static uint32_t right_cycleshift32(uint32_t num, uint32_t shiftval) {
    return (num >> (shiftval % 32)) | (num << (32 - (shiftval % 32)));
}

// -> 9 -> 0
// -> 10 -> 8
static const uint32_t S_block_straight[] = {
    4  , 2  , 12 , 6  , 15 , 9  , 5  , 1  ,
    7  , 0  , 8  , 3  , 11 , 13 , 14 , 10 ,
};

// -> 0 -> 9
// -> 8 -> 10
static const uint32_t S_block_reverse[] = {
    9  , 7  , 1  , 11 , 0  , 6  , 3  , 8  ,
    10 , 5  , 15 , 12 , 2  , 13 , 14 , 4  ,
};

// -> 0 -> 16
// -> 10 -> 23
static const uint32_t P_block_straight[] = {
    16 , 7  , 20 , 21 , 29 , 12, 28 , 17 ,
    1  , 15 , 23 , 26 , 5  , 18, 31 , 10 ,
    2  , 8  , 24 , 14 , 0  , 27, 3  , 9  ,
    19 , 13 , 30 , 6  , 22 , 11, 4  , 25 ,
};

// -> 16 -> 0
// -> 23 -> 10
static const uint32_t P_block_reverse[] = {
    20 , 8  , 16 , 22 , 30 , 12 , 27 , 1  ,
    17 , 23 , 15 , 29 , 5  , 25 , 19 , 9  ,
    0  , 7  , 13 , 24 , 2  , 3  , 28 , 10 ,
    18 , 31 , 11 , 21 , 6  , 4  , 26 , 14 ,
};

static void generate_round_keys(uint32_t masterkey, uint32_t *roundkeys, int rounds) {
    for (int i = 0; i < rounds; i++) {
        uint32_t shifted = right_cycleshift32(masterkey, i);
        roundkeys[i]     = shifted ^ (i * 0x9E3779B9);
    }
}

// substitution using table
static uint32_t do_S_block32(uint32_t bytes, const uint32_t *S_block) {
    uint32_t res = 0;
    for (int i = 0; i < 8; ++i) {
        res   |= (S_block[bytes & 0xF] << (i * 4));
        bytes >>= 4;
    }
    return res;
}

// permutation using table
static uint32_t do_P_block32(uint32_t bytes, const uint32_t *P_block) {
    uint32_t res = 0;
    for (int i = 0; i < 32; ++i) {
        uint32_t bit    = bytes & 0b1;       // take bit number i
        uint32_t bitval = bit << P_block[i]; // shift using pblock
        res             |= bitval;
        bytes           >>= 1;
    }
    return res;
}

static uint32_t SP_net32_round_enc(uint32_t block, uint32_t roundkey) {
    uint32_t res = block ^ roundkey;
    res          = do_S_block32(res, S_block_straight);
    res          = do_P_block32(res, P_block_straight);
    return res;
}

static uint32_t SP_net32_round_dec(uint32_t block, uint32_t roundkey) {
    uint32_t res = do_P_block32(block, P_block_reverse);
    res          = do_S_block32(res, S_block_reverse);
    res          = res ^ roundkey;
    return res;
}

uint32_t SP_net32_enc(uint32_t block, uint32_t masterkey, uint32_t rounds) {
    // generate round keys
    uint32_t *roundkeys = (uint32_t *)malloc(rounds*sizeof(uint32_t));
    generate_round_keys(masterkey, roundkeys, rounds);

    uint32_t state = block;
    for (int r = 0; r < rounds; ++r) {
        state = SP_net32_round_enc(state, roundkeys[r]);
    }

    // cleanup
    free(roundkeys);
    return state;
}

uint32_t SP_net32_dec(uint32_t block, uint32_t masterkey, uint32_t rounds) {
    // generate round keys
    uint32_t *roundkeys = (uint32_t *)malloc(rounds*sizeof(uint32_t));
    generate_round_keys(masterkey, roundkeys, rounds);

    uint32_t state = block;

    for (int r = rounds-1; r >= 0; --r) {
        state = SP_net32_round_dec(state, roundkeys[r]);
    }

    // cleanup
    free(roundkeys);
    return state;
}

#endif

#endif
