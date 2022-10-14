#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <xorcbc.h>

int main(int argc, char **argv) {
    struct random_generator rg;
    FILE *key_file, *in_file, *out_file, *iv_file;
    struct block key_block, iv_block;
    char input[500], iv[500], output[500];
    unsigned char *in_stream, *out_stream;
    unsigned int size;
    int mode;

    init_random_generator(&rg, time(NULL));

    printf("Loading key file ...\n");
    key_file = fopen("key.dat", "rb");
    if (key_file == NULL) {
        printf("Unable to open key file (%s). Creating a new key\n", "key.dat");

        key_file = fopen("key.dat", "wb");
        if (key_file == NULL) {
            printf("Unable to create key file\n");
            exit(EXIT_FAILURE);
        }

        random_block(&rg, &key_block);
        if (fwrite(&key_block, sizeof(struct block), 1, key_file) != 1) {
            printf("Unable to write key file\n");
            fclose(key_file);
            exit(EXIT_FAILURE);
        }

        printf("Key created\n");

        fclose(key_file);
        printf("Reloading key file ...\n");
    }

    key_file = fopen("key.dat", "rb");
    if (key_file == NULL) {
        printf("Unable to reload key file\n");
        exit(EXIT_FAILURE);
    }

    if (fread(&key_block, sizeof(struct block), 1, key_file) != 1) {
        printf("Unable to read key\n");
        fclose(key_file);
        exit(EXIT_FAILURE);
    }

    fclose(key_file);

    printf("Enter input file: ");
    scanf("%500[^\n]%*c", input);

    in_file = fopen(input, "rb");
    if (in_file == NULL) {
        printf("Unable to open input file\n");
        exit(EXIT_FAILURE);
    }

    printf("Enter mode:\n [1] Encrypt\n [2] Decrypt\nYour choice? ");
    scanf("%d%*c", &mode);

    printf("Enter output file: ");
    scanf("%500[^\n]%*c", output);

    out_file = fopen(output, "wb");
    if (out_file == NULL) {
        printf("Unable to create output file\n");
        exit(EXIT_FAILURE);
    }

    fseek(in_file, 0, SEEK_END);
    size = ftell(in_file);
    in_stream = (unsigned char *)malloc(sizeof(unsigned char) * size);
    out_stream = (unsigned char *)malloc(sizeof(unsigned char) * size);

    fseek(in_file, 0, SEEK_SET);
    if (fread(in_stream, sizeof(unsigned char), size, in_file) != size) {
        printf("Unable to read input\n");
        fclose(in_file);
        fclose(out_file);
        exit(EXIT_FAILURE);
    }

    fclose(in_file);

    if (mode == 1) {
        sprintf(iv, "%s.iv", output);
        iv_file = fopen(iv, "wb");
        if (iv_file == NULL) {
            printf("Unable to create initialization vector file for output\n");
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        random_block(&rg, &iv_block);
        if (fwrite(&iv_block, sizeof(struct block), 1, iv_file) != 1) {
            printf("Unable to write initialization vector file for output\n");
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        stream_encrypt(in_stream, size, &key_block, &iv_block, out_stream);
        if (fwrite(out_stream, sizeof(unsigned char), size, out_file) != size) {
            printf("Unable to write output\n");
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        printf("Output successfully written\n");
    }

    if (mode == 2) {
        sprintf(iv, "%s.iv", input);
        iv_file = fopen(iv, "rb");
        if (iv_file == NULL) {
            printf("Unable to open initialization vector file for input (%s)\n", iv);
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        if (fread(&iv_block, sizeof(struct block), 1, iv_file) != 1) {
            printf("Unable to read initialization vector file for input");
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        stream_decrypt(in_stream, size, &key_block, &iv_block, out_stream);
        if (fwrite(out_stream, sizeof(unsigned char), size, out_file) != size) {
            printf("Unable to write output\n");
            fclose(out_file);
            exit(EXIT_FAILURE);
        }

        printf("Output successfully written\n");
    }

    return 0;
}
