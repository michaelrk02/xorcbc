#include "xorcbc.h"

void init_random_generator(struct random_generator *rg, unsigned long long seed) {
    unsigned long long factor = 0xDEADBEEF;
    unsigned long long offset = 0xBADF00D5;
    unsigned long long modulus = 0xFFFFFFFF;

    init_random_generator_ex(rg, factor, offset, modulus, seed);
}

void init_random_generator_ex(struct random_generator *rg, unsigned long long factor, unsigned long long offset, unsigned long long modulus, unsigned long long seed) {
    rg->state = seed;
    rg->factor = factor;
    rg->offset = offset;
    rg->modulus = modulus;
}

unsigned int random_dword(struct random_generator *rg) {
    rg->state = (rg->factor * rg->state + rg->offset) % rg->modulus;

    return (unsigned int)(rg->state & 0xFFFFFFFF);
}

void random_block(struct random_generator *rg, struct block *blk) {
    unsigned int i;

    for (i = 0; i < 8; i++) {
        blk->u.dwords[i] = random_dword(rg);
    }
}

void block_encrypt(const struct block *plain, const struct block *key, const struct block *iv, struct block *cipher) {
    unsigned int i;

    for (i = 0; i < 4; i++) {
        cipher->u.qwords[i] = plain->u.qwords[i];
        cipher->u.qwords[i] = cipher->u.qwords[i] ^ iv->u.qwords[i];
        cipher->u.qwords[i] = cipher->u.qwords[i] ^ key->u.qwords[i];
    }
}

void block_decrypt(const struct block *cipher, const struct block *key, const struct block *iv, struct block *plain) {
    unsigned int i;

    for (i = 0; i < 4; i++) {
        plain->u.qwords[i] = cipher->u.qwords[i];
        plain->u.qwords[i] = plain->u.qwords[i] ^ key->u.qwords[i];
        plain->u.qwords[i] = plain->u.qwords[i] ^ iv->u.qwords[i];
    }
}

void stream_encrypt(const unsigned char *plain, unsigned int size, const struct block *key, const struct block *iv, unsigned char *cipher) {
    unsigned int i, blocks;
    struct block prev;

    prev = *iv;
    blocks = size / 32 + (unsigned int)(blocks % 32 != 0);
    for (i = 0; i < blocks; i++) {
        unsigned int j;
        struct block blkp, blkc;

        for (j = 0; j < 32; j++) {
            unsigned int pos;

            pos = 32 * i + j;
            if (pos < size) {
                blkp.u.bytes[j] = plain[pos];
            } else {
                break;
            }
        }

        block_encrypt(&blkp, key, &prev, &blkc);
        prev = blkc;

        for (j = 0; j < 32; j++) {
            unsigned int pos;

            pos = 32 * i + j;
            if (pos < size) {
                cipher[pos] = blkc.u.bytes[j];
            } else {
                break;
            }
        }
    }
}

void stream_decrypt(const unsigned char *cipher, unsigned int size, const struct block *key, const struct block *iv, unsigned char *plain) {
    unsigned int i, blocks;
    struct block prev;

    prev = *iv;
    blocks = size / 32 + (unsigned int)(blocks % 32 != 0);
    for (i = 0; i < blocks; i++) {
        unsigned int j;
        struct block blkc, blkp;

        for (j = 0; j < 32; j++) {
            unsigned int pos;

            pos = 32 * i + j;
            if (pos < size) {
                blkc.u.bytes[j] = cipher[pos];
            } else {
                break;
            }
        }

        block_decrypt(&blkc, key, &prev, &blkp);
        prev = blkc;

        for (j = 0; j < 32; j++) {
            unsigned int pos;

            pos = 32 * i + j;
            if (pos < size) {
                plain[pos] = blkp.u.bytes[j];
            } else {
                break;
            }
        }
    }
}
