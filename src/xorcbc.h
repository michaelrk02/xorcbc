#ifndef XORCBC_H
#define XORCBC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 256-bit cryptographic block
 */
struct block {
    union {
        unsigned char bytes[32];
        unsigned short words[16];
        unsigned int dwords[8];
        unsigned long long qwords[4];
    } u;
};

struct random_generator {
    unsigned long long state;
    unsigned long long factor;
    unsigned long long offset;
    unsigned long long modulus;
};

void init_random_generator(struct random_generator *rg, unsigned long long seed);
void init_random_generator_ex(struct random_generator *rg, unsigned long long factor, unsigned long long offset, unsigned long long modulus, unsigned long long seed);

unsigned int random_dword(struct random_generator *rg);
void random_block(struct random_generator *rg, struct block *blk);

void block_encrypt(const struct block *plain, const struct block *key, const struct block *iv, struct block *cipher);
void block_decrypt(const struct block *cipher, const struct block *key, const struct block *iv, struct block *plain);

void stream_encrypt(const unsigned char *plain, unsigned int size, const struct block *key, const struct block *iv, unsigned char *cipher);
void stream_decrypt(const unsigned char *cipher, unsigned int size, const struct block *key, const struct block *iv, unsigned char *plain);

#ifdef __cplusplus
}
#endif

#endif
