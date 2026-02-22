#ifndef DES_H
#define DES_H

#include <stdlib.h>
#include <stdint.h>

uint64_t des_dec(uint64_t block, uint64_t masterkey, uint32_t rounds);

#ifdef DES_IMPL

static void des_generate_round_keys(uint64_t masterkey, uint64_t *roundkeys, uint32_t rounds) {

}

uint64_t des_dec(uint64_t block, uint64_t masterkey, uint32_t rounds) {
    if (rounds != 16) {
        fprintf(stderr, "des need 16 rounds (standard)\n");
        exit(1);
    }
    uint64_t *roundkeys = (uint64_t *)malloc(rounds*sizeof(uint64_t));
    des_generate_round_keys(masterkey, roundkeys, rounds);
    
    free(roundkeys);
}

#endif

#endif
