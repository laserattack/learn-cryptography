#ifndef DES_H
#define DES_H

#include <stdlib.h>
#include <stdint.h>

uint64_t des_dec(uint64_t block, uint64_t masterkey);

#ifdef DES_IMPL

#define ROUNDS 16 // in standard

static void des_generate_round_keys(uint64_t masterkey, uint64_t *roundkeys) {

}

uint64_t des_dec(uint64_t block, uint64_t masterkey) {
    uint64_t *roundkeys = (uint64_t *)malloc(ROUNDS*sizeof(uint64_t));
    des_generate_round_keys(masterkey, roundkeys);
    
    free(roundkeys);
}

#endif

#endif
