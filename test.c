#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#define MODES_IMPL
#define SPNET_IMPL
#define FEISTEL_SPNET_IMPL
#define DES_IMPL

#include "modes.h"
#include "ciphers/spnet.h"
#include "ciphers/feistel_spnet.h"
#include "ciphers/des.h"

#define RUN_TEST(test_fn) \
    do { \
        fprintf(stderr, "Running %s... ", #test_fn); \
        test_fn(); \
        fprintf(stderr, "OK\n"); \
    } while(0)

void test_feistel_spnet32() {
    // data
    char text[16]        = "hello, sailor!!"; // 16/4=4 blocks

    // parameters
    char encrypted[16], decrypted[16];
    uint32_t key         = 0xCAFEBABE;
    uint32_t blockscount = sizeof(text)/4;
    uint32_t rounds      = 5;
    uint32_t iv          = 0xDEADBEEF;

    // ecb
    ecb_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, feistel_SP_net32_enc);
    ecb_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, feistel_SP_net32_dec);
    assert(!strcmp(text, decrypted) && "feistel spnet32 ecb failed");

    // cbc
    cbc_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, iv, feistel_SP_net32_enc);
    cbc_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, iv, feistel_SP_net32_dec);
    assert(!strcmp(text, decrypted) && "feistel spnet32 cbc failed");

    // cfb
    cfb_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, iv, feistel_SP_net32_enc);
    cfb_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, iv, feistel_SP_net32_enc);
    assert(!strcmp(text, decrypted) && "feistel spnet32 cfb failed");
}

void test_spnet32() {
    // data
    char text[16]        = "hello, sailor!!"; // 16/4=4 blocks

    // parameters
    char encrypted[16], decrypted[16];
    uint32_t key         = 0xCAFEBABE;
    uint32_t blockscount = sizeof(text)/4;
    uint32_t rounds      = 5;
    uint32_t iv          = 0xDEADBEEF;

    // ecb
    ecb_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, SP_net32_enc);
    ecb_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, SP_net32_dec);
    assert(!strcmp(text, decrypted) && "spnet32 ecb failed");

    // cbc
    cbc_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, iv, SP_net32_enc);
    cbc_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, iv, SP_net32_dec);
    assert(!strcmp(text, decrypted) && "spnet32 cbc failed");

    // cfb
    cfb_enc((uint32_t *)encrypted, (uint32_t *)text, blockscount, key, rounds, iv, SP_net32_enc);
    cfb_dec((uint32_t *)decrypted, (uint32_t *)encrypted, blockscount, key, rounds, iv, SP_net32_enc);
    assert(!strcmp(text, decrypted) && "spnet32 cfb failed");
}

int main() {
    RUN_TEST(test_spnet32);
    RUN_TEST(test_feistel_spnet32);
    return 0;
}
