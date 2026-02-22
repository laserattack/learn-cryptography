#ifndef FEISTEL_SPNET_H
#define FEISTEL_SPNET_H

#include <stdlib.h>
#include <stdint.h>

uint32_t feistel_SP_net32_enc(uint32_t block, uint32_t masterkey, uint32_t rounds);
uint32_t feistel_SP_net32_dec(uint32_t block, uint32_t masterkey, uint32_t rounds);

#ifdef FEISTEL_SPNET_IMPL

static uint32_t feistel_SP_net32_right_cycleshift32(uint32_t num, uint32_t shiftval) {
    return (num >> (shiftval % 32)) | (num << (32 - (shiftval % 32)));
}

// 4bit fragments
static const uint16_t feistel_SP_net32_S_block_straight[] = {
    4  , 2  , 12 , 6  , 15 , 9  , 5  , 1  ,
    7  , 0  , 8  , 3  , 11 , 13 , 14 , 10 ,
};

static const uint16_t feistel_SP_net32_P_block_straight[] = {
    7 , 12, 1 , 15 , 5 , 10 , 2 , 8 ,
    14 , 0 , 3 , 9 , 13 , 6 , 11, 4 ,
};

// reverse blocks are not needed in this algorithm !! COOL

static void feistel_SP_net32_generate_round_keys(uint32_t masterkey, uint16_t *roundkeys, int rounds) {
    for (int i = 0; i < rounds; i++) {
        uint32_t shifted = feistel_SP_net32_right_cycleshift32(masterkey, i);
        roundkeys[i]     = shifted ^ (i * 0x9E3779B9);
    }
}

// substitution using table
static uint16_t feistel_SP_net32_do_S_block16(uint16_t bytes, const uint16_t *S_block) {
    uint16_t res = 0;
    for (int i = 0; i < 4; ++i) {
        res   |= (S_block[bytes & 0xF] << (i * 4));
        bytes >>= 4;
    }
    return res;
}

// permutation using table
static uint16_t feistel_SP_net32_do_P_block16(uint16_t bytes, const uint16_t *P_block) {
    uint16_t res = 0;
    for (int i = 0; i < 16; ++i) {
        uint16_t bit    = bytes & 0b1;       // take bit number i
        uint16_t bitval = bit << P_block[i]; // shift using pblock
        res             |= bitval;
        bytes           >>= 1;
    }
    return res;
}

static uint16_t feistel_SP_net32_SP_net16_round_enc(uint16_t block, uint16_t roundkey) {
    uint16_t res = block ^ roundkey;
    res          = feistel_SP_net32_do_S_block16(res, feistel_SP_net32_S_block_straight);
    res          = feistel_SP_net32_do_P_block16(res, feistel_SP_net32_P_block_straight);
    return res;
}

// this substitution = tau = involutive substitution
static uint32_t tau(uint32_t block) {
    uint16_t left = block >> 16;
    uint16_t right = block & 0xFFFF;
    return ((uint32_t)right << 16) | left;
}

// this substitution = tau-involutive substitution (Feistel-substitution)
static uint32_t feistel_SP_net32_round_encdec(uint32_t block, uint16_t roundkey) {
    uint16_t left  = block >> 16;
    uint16_t right = block & 0xFFFF;
    // in this case i use SP_net16_round_enc substitution, but there are no restrictions, you can use any function
    uint32_t res = left ^ feistel_SP_net32_SP_net16_round_enc(right, roundkey);
    res |= ((uint32_t)right << 16);
    return res;
}

uint32_t feistel_SP_net32_enc(uint32_t block, uint32_t masterkey, uint32_t rounds) {
    uint16_t *roundkeys = (uint16_t*)malloc(rounds * sizeof(uint16_t));
    feistel_SP_net32_generate_round_keys((uint16_t)masterkey, roundkeys, rounds);

    uint32_t state = block;
    for (int r = 0; r < rounds; ++r) {
        // round-substitution = tau-involutive substitution (Feistel-substitution)
        state = feistel_SP_net32_round_encdec(state, roundkeys[r]);
    }

    // last substitution = tau = involutive substitution
    state = tau(state);
    
    free(roundkeys);
    return state;
}

// encryption differs from decryption only in the order of the round keys

uint32_t feistel_SP_net32_dec(uint32_t block, uint32_t masterkey, uint32_t rounds) {
    uint16_t *roundkeys = (uint16_t*)malloc(rounds * sizeof(uint16_t));
    feistel_SP_net32_generate_round_keys((uint16_t)masterkey, roundkeys, rounds);

    uint32_t state = block;
    
    for (int r = rounds-1; r >= 0; --r) {
        // round-substitution = tau-involutive substitution (Feistel-substitution)
        state = feistel_SP_net32_round_encdec(state, roundkeys[r]);
    }
    
    // last substitution = tau = involutive substitution
    state = tau(state);

    free(roundkeys);
    return state;
}

#endif

#endif
