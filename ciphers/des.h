#ifndef DES_H
#define DES_H

#include <stdlib.h>
#include <stdint.h>

uint64_t des_enc(uint64_t block, uint64_t masterkey, uint32_t rounds);
uint64_t des_dec(uint64_t block, uint64_t masterkey, uint32_t rounds);

#ifdef DES_IMPL

#define DES_MASK6  ((1ULL << 6)  - 1)
#define DES_MASK28 ((1ULL << 28) - 1)
#define DES_MASK32 ((1ULL << 32) - 1)
#define DES_MASK48 ((1ULL << 48) - 1)
#define DES_MASK56 ((1ULL << 56) - 1)

// Initial permutation
static const uint64_t des_initial_permutation_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2 ,
    60, 52, 44, 36, 28, 20, 12, 4 ,
    62, 54, 46, 38, 30, 22, 14, 6 ,
    64, 56, 48, 40, 32, 24, 16, 8 ,
    57, 49, 41, 33, 25, 17, 9 , 1 ,
    59, 51, 43, 35, 27, 19, 11, 3 ,
    61, 53, 45, 37, 29, 21, 13, 5 ,
    63, 55, 47, 39, 31, 23, 15, 7 ,
};

// Final permutation
static const uint64_t des_final_permutation_table[64] = {
    40, 8 , 48, 16, 56, 24, 64, 32,
    39, 7 , 47, 15, 55, 23, 63, 31,
    38, 6 , 46, 14, 54, 22, 62, 30,
    37, 5 , 45, 13, 53, 21, 61, 29,
    36, 4 , 44, 12, 52, 20, 60, 28,
    35, 3 , 43, 11, 51, 19, 59, 27,
    34, 2 , 42, 10, 50, 18, 58, 26,
    33, 1 , 41, 9 , 49, 17, 57, 25,
};

static uint64_t des_do_permutation(uint64_t bits, uint64_t bits_count, uint64_t input_width, const uint64_t *P_block) {
    uint64_t res = 0;
    for (uint64_t i = 0; i < bits_count; ++i) {
        int src_bit  = (P_block[i] - 1) % input_width;
        uint64_t bit = (bits >> src_bit) & 1;
        res          |= (bit << i);
    }
    return res;
}

static void des_generate_round_keys(uint64_t masterkey, uint64_t *roundkeys, uint32_t rounds) {
    // tables using in generation round keys from standard
    static const uint64_t des_key_permutation_table[56] = {
        57, 49, 41, 33, 25, 17, 9 , 1 ,
        58, 50, 42, 34, 26, 18, 10, 2 ,
        59, 51, 43, 35, 27, 19, 11, 3 ,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7 , 62, 54, 46, 38,
        30, 22, 14, 6 , 61, 53, 45, 37,
        29, 21, 13, 5 , 28, 20, 12, 4 ,
    };
    static const uint64_t des_key_compression_table[48] = {
        14, 17, 11, 24, 1 , 5 , 3 , 28,
        15, 6 , 21, 10, 23, 19, 12, 4 ,
        26, 8 , 16, 7 , 27, 20, 13, 2 ,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32,
    };
    static const uint64_t des_key_shifts[16] = {
        1 , 1 , 2 , 2 , 2 , 2 , 2 , 2 ,
        1 , 2 , 2 , 2 , 2 , 2 , 2 , 1 ,
    };

    /* 1. A 56-bit key arrives (in DES it's stored in a 64-bit container where every 8th bit is a parity bit.
    This is for error detection, like integrity control. But I'll just use the lower 56 bits in a 64-bit container) */    
    masterkey &= DES_MASK56;

    // 2. Undergoes bit permutation
    masterkey = des_do_permutation(masterkey, 56, 56, des_key_permutation_table);

    // 3. Divided into 2 halves of 28 bits each
    uint64_t right = masterkey         & DES_MASK28;
    uint64_t left  = (masterkey >> 28) & DES_MASK28;

    for (uint64_t i = 0; i < rounds; ++i) {
        // 4. For each of the 16 rounds, the halves are shifted cyclically left by 1 or 2 bits depending on the round number
        uint64_t shift = des_key_shifts[i];
        left           = ((left << shift)  | (left >> (28 - shift)))  & DES_MASK28;
        right          = ((right << shift) | (right >> (28 - shift))) & DES_MASK28;

        // 5. After shifting for the corresponding round number (previous step), the halves are glued back to 56 bits
        uint64_t res = (left << 28) | right;

        // 6. The result is subjected to a narrowing fixed substitution (independent of the key) and 48 bits are obtained
        res = des_do_permutation(res, 48, 56, des_key_compression_table) & DES_MASK48;
        roundkeys[i] = res;
    }
}

static uint32_t _des_round_encdec(uint32_t block, uint64_t roundkey) {
    // 1. The round function receives a 32-bit half-block
    // 2. A fixed expansion permutation is applied to it, resulting in a 48-bit value
    static const uint64_t des_expansion_table[48] = {
        32, 1 , 2 , 3 , 4 , 5 ,
        4 , 5 , 6 , 7 , 8 , 9 ,
        8 , 9 , 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1 ,
    };
    uint64_t state = block;
    state          = des_do_permutation(state, 48, 32, des_expansion_table) & DES_MASK48;

    // 3. The result from the previous step is XORed with the 48-bit round key
    state ^= roundkey;

    /* 4. The resulting 48-bit word is split into 8 fragments of 6 bits each,
    which pass through narrowing S-boxes and are transformed into 4-bit words
    
    Narrowing S-boxes from the standard */
    static const uint8_t des_s_blocks[8][4][16] = {
        {
            {14, 4 , 13, 1 , 2 , 15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0 , 7 },
            {0 , 15, 7 , 4 , 14, 2 , 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3 , 8 },
            {4 , 1 , 14, 8 , 13, 6 , 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5 , 0 },
            {15, 12, 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6 , 13},
        },
        {
            {15, 1 , 8 , 14, 6 , 11, 3 , 4 , 9 , 7 , 2 , 13, 12, 0 , 5 , 10},
            {3 , 13, 4 , 7 , 15, 2 , 8 , 14, 12, 0 , 1 , 10, 6 , 9 , 11, 5 },
            {0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8 , 12, 6 , 9 , 3 , 2 , 15},
            {13, 8 , 10, 1 , 3 , 15, 4 , 2 , 11, 6 , 7 , 12, 0 , 5 , 14, 9 },
        },
        {
            {10, 0 , 9 , 14, 6 , 3 , 15, 5 , 1 , 13, 12, 7 , 11, 4 , 2 , 8 },
            {13, 7 , 0 , 9 , 3 , 4 , 6 , 10, 2 , 8 , 5 , 14, 12, 11, 15, 1 },
            {13, 6 , 4 , 9 , 8 , 15, 3 , 0 , 11, 1 , 2 , 12, 5 , 10, 14, 7 },
            {1 , 10, 13, 0 , 6 , 9 , 8 , 7 , 4 , 15, 14, 3 , 11, 5 , 2 , 12},
        },
        {
            {7 , 13, 14, 3 , 0 , 6 , 9 , 10, 1 , 2 , 8 , 5 , 11, 12, 4 , 15},
            {13, 8 , 11, 5 , 6 , 15, 0 , 3 , 4 , 7 , 2 , 12, 1 , 10, 14, 9 },
            {10, 6 , 9 , 0 , 12, 11, 7 , 13, 15, 1 , 3 , 14, 5 , 2 , 8 , 4 },
            {3 , 15, 0 , 6 , 10, 1 , 13, 8 , 9 , 4 , 5 , 11, 12, 7 , 2 , 14},
        },
        {
            {2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0 , 14, 9 },
            {14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9 , 8 , 6 },
            {4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3 , 0 , 14},
            {11, 8 , 12, 7 , 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4 , 5 , 3 }
        },
        {
            {12, 1 , 10, 15, 9 , 2 , 6 , 8 , 0 , 13, 3 , 4 , 14, 7 , 5 , 11},
            {10, 15, 4 , 2 , 7 , 12, 9 , 5 , 6 , 1 , 13, 14, 0 , 11, 3 , 8 },
            {9 , 14, 15, 5 , 2 , 8 , 12, 3 , 7 , 0 , 4 , 10, 1 , 13, 11, 6 },
            {4 , 3 , 2 , 12, 9 , 5 , 15, 10, 11, 14, 1 , 7 , 6 , 0 , 8 , 13},
        },
        {
            {4 , 11, 2 , 14, 15, 0 , 8 , 13, 3 , 12, 9 , 7 , 5 , 10, 6 , 1 },
            {13, 0 , 11, 7 , 4 , 9 , 1 , 10, 14, 3 , 5 , 12, 2 , 15, 8 , 6 },
            {1 , 4 , 11, 13, 12, 3 , 7 , 14, 10, 15, 6 , 8 , 0 , 5 , 9 , 2 },
            {6 , 11, 13, 8 , 1 , 4 , 10, 7 , 9 , 5 , 0 , 15, 14, 2 , 3 , 12},
        },
        {
            {13, 2 , 8 , 4 , 6 , 15, 11, 1 , 10, 9 , 3 , 14, 5 , 0 , 12, 7 },
            {1 , 15, 13, 8 , 10, 3 , 7 , 4 , 12, 5 , 6 , 11, 0 , 14, 9 , 2 },
            {7 , 11, 4 , 1 , 9 , 12, 14, 2 , 0 , 6 , 10, 13, 15, 3 , 5 , 8 },
            {2 , 1 , 14, 7 , 4 , 10, 8 , 13, 15, 12, 9 , 0 , 3 , 5 , 6 , 11},
        }
    };

    uint32_t res = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t six_bits = (state >> (i * 6)) & DES_MASK6;
        uint8_t row      = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        uint8_t col      = (six_bits >> 1) & 0x0F;
        res              |= (des_s_blocks[i][row][col] << (i * 4));
    }

    // 5. Next follows a fixed P-block (just permutation)
    static const uint64_t des_p_block[32] = {
        16, 7 , 20, 21,
        29, 12, 28, 17,
        1 , 15, 23, 26,
        5 , 18, 31, 10,
        2 , 8 , 24, 14,
        32, 27, 3 , 9 ,
        19, 13, 30, 6 ,
        22, 11, 4 , 25,
    };
    res = des_do_permutation(res, 32, 32, des_p_block);

    // 6. The result is passed to the next round
    return res;
}

// des = feistel network => the round function is the same for encryption and decryption
// and this is tau-involutive substitution
static uint64_t des_round_encdec(uint64_t block, uint64_t roundkey) {
    uint32_t left  = block >> 32;
    uint32_t right = block & DES_MASK32;
    uint64_t res   = left ^ _des_round_encdec(right, roundkey);
    res            |= ((uint64_t)right << 32);
    return res;
}

// tau = involutive substitution
static uint64_t des_tau(uint64_t block) {
    uint32_t left  = block >> 32;
    uint32_t right = block & DES_MASK32;
    return ((uint64_t)right << 32) | left;
}

uint64_t des_enc(uint64_t block, uint64_t masterkey, uint32_t rounds) {
    if (rounds != 16) {
        fprintf(stderr, "des need 16 rounds (standard)\n");
        exit(1);
    }
    uint64_t *roundkeys = (uint64_t *)malloc(rounds*sizeof(uint64_t));
    des_generate_round_keys(masterkey, roundkeys, rounds);

    uint64_t state = block;

    state = des_do_permutation(state, 64, 64, des_initial_permutation_table);
    
    for (uint32_t i = 0; i < rounds; ++i) {
        state = des_round_encdec(state, roundkeys[i]);
    }
    state = des_tau(state);
    
    state = des_do_permutation(state, 64, 64, des_final_permutation_table);
    
    free(roundkeys);
    return state;
}

uint64_t des_dec(uint64_t block, uint64_t masterkey, uint32_t rounds) {
    if (rounds != 16) {
        fprintf(stderr, "des need 16 rounds (standard)\n");
        exit(1);
    }
    uint64_t *roundkeys = (uint64_t *)malloc(rounds*sizeof(uint64_t));
    des_generate_round_keys(masterkey, roundkeys, rounds);

    uint64_t state = block;

    state = des_do_permutation(state, 64, 64, des_initial_permutation_table);
    for (int i = rounds-1; i >= 0; --i) {
        state = des_round_encdec(state, roundkeys[i]);
    }
    state = des_tau(state);
    
    state = des_do_permutation(state, 64, 64, des_final_permutation_table);
    
    free(roundkeys);
    return state;
}

#endif

#endif
