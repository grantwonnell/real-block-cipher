#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* 32 bit blocks */

#define ROTL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

typedef struct {
    uint32_t *blocks;
    size_t block_size;
} blocks_t;

/* used to make key shuffle as random as possible */
uint8_t shuffle_index_array[] = {
    0x7C, 0x23, 0xA9, 0x5F,
    0xD4, 0x3E, 0x81, 0x17,
    0xB2, 0x6A, 0xC8, 0x90,
    0x4D, 0x1B, 0xFE, 0x39,
    0x74, 0xE1, 0x0C, 0xAA,
    0x5D, 0xCB, 0x19, 0x82,
    0xF3, 0x60, 0x2A, 0x96,
    0xDE, 0x48, 0x13, 0xBD
};

/* string -> block */
static void SetBlock(uint32_t *block, uint8_t *bytes, size_t *offset) {
    memcpy(block, bytes + *offset, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
}

/*string -> all blocks */
static blocks_t *SetBlocks(uint8_t *bytes, size_t len) {
    blocks_t *block = calloc(1, sizeof(blocks_t));

    block->block_size = len / sizeof(uint32_t);
    size_t modulus = len % sizeof(uint32_t);

    if(modulus > 0)
        block->block_size++;

    block->blocks = calloc(sizeof(uint32_t), block->block_size);

    size_t offset = 0;
    for(int i = 0; i < block->block_size; i++) {
        if(modulus > 0 && i == (block->block_size - 1))
            memcpy(&block->blocks[i], bytes + offset, modulus);
        
        SetBlock(&block->blocks[i], bytes, &offset);
    }

    return block;
}

/* Hashes key (can be changed to anything) */
static uint64_t HashKey(uint8_t *key, size_t key_len) {
    uint64_t key_sum = 0;

    uint32_t key_int_1 = 0;
    uint32_t key_int_2 = 0;

    for(int i = 0; i < key_len; i++) {
        key_int_1 *= (key[i] + 1);
        key_int_2 += (key[i] + 2);

        key_int_1 ^= key_int_2;
        key_int_2 ^= key_int_1;

        key_int_1 ^= ((key[(i + 24) % key_len] << 24) | (key[(i + 16) % key_len] << 16) | (key[(i + 8) % key_len] << 8) | (key[(i) % key_len]));
    }

    key_sum |= key_int_1;
    key_sum |= ((uint64_t)key_int_2 << 32);

    return key_sum;
}

/* creates an as random as possible integer to randomly index key bytes to shuffle the key */
static uint32_t CreateShuffleVector(int i) {
    i |= (i ^ (shuffle_index_array[i % sizeof(shuffle_index_array)]));
    i |= (shuffle_index_array[i % sizeof(shuffle_index_array)]) << 8;
    i |= (shuffle_index_array[i % sizeof(shuffle_index_array)]) << 16;
    i |= (shuffle_index_array[i % sizeof(shuffle_index_array)]) << 24;

    i = ROTR32(i, 13);

    return (uint32_t)i;
}

/* shuffles the key after creating the shuffle vector */
static uint32_t ShuffleKeyArray(int i, uint32_t key_half_int) {
    uint32_t shuffled_key = 0;

    uint32_t vector = CreateShuffleVector(i);

    uint8_t *bytes = (uint8_t *)&key_half_int;
    uint8_t *vbytes = (uint8_t *)&vector;

    uint8_t tmp_bytes[4];

    memcpy(tmp_bytes, bytes, sizeof(uint32_t));

    bytes[0] = tmp_bytes[vbytes[3] % sizeof(uint32_t)];
    bytes[1] = tmp_bytes[vbytes[2] % sizeof(uint32_t)];
    bytes[2] = tmp_bytes[vbytes[1] % sizeof(uint32_t)];
    bytes[3] = tmp_bytes[vbytes[0] % sizeof(uint32_t)];

    return *(uint32_t *)bytes;
}

/* implements cipher block chaining and minor key scheduling */
void Encrypt(blocks_t *blocks, uint64_t key_hash, uint32_t iv) {
    uint8_t *key_array = (uint8_t *)&key_hash;

    uint32_t tmp_key1, tmp_key2, shuffled_key1, shuffled_key2;

    uint32_t prev_cipher = iv;

    for(int i = 0; i < blocks->block_size; i++) {
        blocks->blocks[i] ^= prev_cipher;

        tmp_key1 = (i % 2) == 0 ? *(uint32_t *)key_array : *(uint32_t *)(key_array + sizeof(uint32_t));
        tmp_key2 = (i % 2) == 0 ? *(uint32_t *)(key_array + sizeof(uint32_t)) : *(uint32_t *)key_array;

        tmp_key1 = ROTL32(tmp_key1, (shuffle_index_array[tmp_key1 % sizeof(shuffle_index_array)] % 32));
        tmp_key2 = ROTL32(tmp_key2, (shuffle_index_array[tmp_key2 % sizeof(shuffle_index_array)] % 32));

        shuffled_key1 = ShuffleKeyArray(i, tmp_key1);
        shuffled_key2 = ShuffleKeyArray(i, tmp_key2);

        blocks->blocks[i] ^= shuffled_key1;
        blocks->blocks[i] ^= shuffled_key2;

        prev_cipher = blocks->blocks[i];
    }
}

void Decrypt(blocks_t *blocks, uint64_t key_hash, uint32_t iv) {
    uint8_t *key_array = (uint8_t *)&key_hash;

    uint32_t tmp_key1, tmp_key2, shuffled_key1, shuffled_key2;
    uint32_t prev_cipher = iv, current_cipher;

    for(int i = 0; i < blocks->block_size; i++) {
        current_cipher = blocks->blocks[i];

        tmp_key1 = (i % 2) == 0 ? *(uint32_t *)key_array : *(uint32_t *)(key_array + sizeof(uint32_t));
        tmp_key2 = (i % 2) == 0 ? *(uint32_t *)(key_array + sizeof(uint32_t)) : *(uint32_t *)key_array;

        tmp_key1 = ROTL32(tmp_key1, (shuffle_index_array[tmp_key1 % sizeof(shuffle_index_array)] % 32));
        tmp_key2 = ROTL32(tmp_key2, (shuffle_index_array[tmp_key2 % sizeof(shuffle_index_array)] % 32));

        shuffled_key1 = ShuffleKeyArray(i, tmp_key1);
        shuffled_key2 = ShuffleKeyArray(i, tmp_key2);

        blocks->blocks[i] ^= shuffled_key2;
        blocks->blocks[i] ^= shuffled_key1;

        blocks->blocks[i] ^= prev_cipher;

        prev_cipher = current_cipher;
    }
}

uint8_t *SerializeBlocks(blocks_t *blocks) {
    uint8_t *str = calloc(1, (blocks->block_size * sizeof(uint32_t)) + 1);

    for(int i = 0; i < blocks->block_size; i++)
        memcpy(str + (i * sizeof(uint32_t)), (uint8_t *)&blocks->blocks[i], sizeof(uint32_t));

    return str;
}

int main(int argc, char **argv) {
    char *arg = strdup(argv[1]);
    size_t len = strlen(arg);

    srand(getpid() << 16 | time(NULL));

    blocks_t *blocks = SetBlocks(arg, len);

    uint8_t key[] = "340qutjpewgfnvqerwinjhtqp3489htqp34tq#$TQ#$TW#%Y)Q#IU$OFJAEWLFJMAWERONFAW($HTQ#$)THQ#$)GFARWOE)WEGF$earlkaerwhoigh";
    size_t key_len = sizeof(key);

    uint64_t key_hash = HashKey(key, key_len);

    uint8_t *key_sections = (uint8_t *)&key_hash;

    uint8_t *str;

    uint32_t iv = rand() & 0xffffffff;

    str = SerializeBlocks(blocks);

    printf("Before: %s\r\n", str);

    free(str);

    for(int i = 0; i < blocks->block_size; i++)
        printf("0x%02x [%d], ", blocks->blocks[i], i);

    Encrypt(blocks, key_hash, iv);

    str = SerializeBlocks(blocks);

    printf("\r\nEncrypted: %s\r\n", str);

    free(str);

    for(int i = 0; i < blocks->block_size; i++)
        printf("0x%02x [%d], ", blocks->blocks[i], i);

    Decrypt(blocks, key_hash, iv);

    str = SerializeBlocks(blocks);

    printf("\r\nDecrypted: %s\r\n", str);
    
    for(int i = 0; i < blocks->block_size; i++)
        printf("0x%02x [%d], ", blocks->blocks[i], i);

    printf("\r\n");
}
