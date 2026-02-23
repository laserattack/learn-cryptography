#ifndef MODES_H
#define MODES_H

#include <stdint.h>

typedef uint32_t (*cipher32_func_t)(uint32_t block, uint32_t key, uint32_t rounds);
typedef uint64_t (*cipher64_func_t)(uint64_t block, uint64_t key, uint32_t rounds);

// 32-BIT VERSIONS DECLARATIONS

void ecb_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher32_func_t enc);

void ecb_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher32_func_t dec);

void cbc_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc);

void cbc_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t dec);

void cfb_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc);

void cfb_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc);

// 64-BIT VERSIONS DECLARATIONS

void ecb_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
cipher64_func_t enc);

void ecb_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
cipher64_func_t dec);

void cbc_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc);

void cbc_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t dec);

void cfb_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc);

void cfb_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc);

#ifdef MODES_IMPL

// ==================== 32-BIT IMPLEMENTATIONS ====================

void ecb_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher32_func_t enc) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = enc(data[i], masterkey, rounds);
    }
}

void ecb_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher32_func_t dec) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = dec(data_encrypted[i], masterkey, rounds);
    }
}

void cbc_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint32_t input = data[i] ^ prev;
        data_encrypted[i] = enc(input, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cbc_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t dec) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint32_t decrypted = dec(data_encrypted[i], masterkey, rounds);
        data_decrypted[i] = decrypted ^ prev;
        prev = data_encrypted[i];
    }
}

void cfb_enc32(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = data[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cfb_dec32(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher32_func_t enc) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = data_encrypted[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

// ==================== 64-BIT IMPLEMENTATIONS ====================

void ecb_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
cipher64_func_t enc) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = enc(data[i], masterkey, rounds);
    }
}

void ecb_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
cipher64_func_t dec) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = dec(data_encrypted[i], masterkey, rounds);
    }
}

void cbc_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc) {
    uint64_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint64_t input = data[i] ^ prev;
        data_encrypted[i] = enc(input, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cbc_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t dec) {
    uint64_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint64_t decrypted = dec(data_encrypted[i], masterkey, rounds);
        data_decrypted[i] = decrypted ^ prev;
        prev = data_encrypted[i];
    }
}

void cfb_enc64(
uint64_t *data_encrypted,
uint64_t *data,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc) {
    uint64_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = data[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cfb_dec64(
uint64_t *data_decrypted,
uint64_t *data_encrypted,
uint32_t blockscount,
uint64_t masterkey,
uint32_t rounds,
uint64_t iv,
cipher64_func_t enc) {
    uint64_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = data_encrypted[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

#endif

#endif
