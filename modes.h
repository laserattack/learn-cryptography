#ifndef MODES_H
#define MODES_H

typedef uint32_t (*cipher_func_t)(uint32_t block, uint32_t key, uint32_t rounds);

void ecb_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher_func_t enc);

void ecb_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher_func_t dec);

void cbc_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t enc);

void cbc_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t dec);

void cfb_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t enc);

void cfb_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t dec);

#ifdef MODES_IMPL

// ecb mode

void ecb_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher_func_t enc) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = enc(data[i], masterkey, rounds);
    }
}

void ecb_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
cipher_func_t dec) {
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = dec(data_encrypted[i], masterkey, rounds);
    }
}

// cbc mode

void cbc_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t enc) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint32_t input = data[i] ^ prev;
        data_encrypted[i] = enc(input, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cbc_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t dec) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        uint32_t decrypted = dec(data_encrypted[i], masterkey, rounds);
        data_decrypted[i] = decrypted ^ prev;
        prev = data_encrypted[i];
    }
}

// cfb mode

void cfb_enc(
uint32_t *data_encrypted,
uint32_t *data,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t enc) {
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_encrypted[i] = data[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

void cfb_dec(
uint32_t *data_decrypted,
uint32_t *data_encrypted,
uint32_t blockscount,
uint32_t masterkey,
uint32_t rounds,
uint32_t iv,
cipher_func_t enc) { // yes, enc! not dec
    uint32_t prev = iv;
    for (uint32_t i = 0; i < blockscount; ++i) {
        data_decrypted[i] = data_encrypted[i] ^ enc(prev, masterkey, rounds);
        prev = data_encrypted[i];
    }
}

#endif

#endif
