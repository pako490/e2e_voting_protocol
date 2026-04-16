#ifndef KEYLOADER_H
#define KEYLOADER_H

#include <stdint.h>

#define MAX_KEYS 1000

typedef struct {
    uint32_t key_id;
    uint64_t n;
    uint64_t e;
} RSAPublicKey;

typedef struct {
    uint32_t key_id;
    uint64_t n;
    uint64_t d;
} RSAPrivateKey;

typedef struct {
    RSAPublicKey keys[MAX_KEYS];
    uint32_t count;
} PublicKeyList;

typedef struct {
    RSAPrivateKey keys[MAX_KEYS];
    uint32_t count;
} PrivateKeyList;

int load_public_key_list_bin(const char *filename, PublicKeyList *list);
int load_private_key_list_bin(const char *filename, PrivateKeyList *list);

const RSAPublicKey *find_public_key(const PublicKeyList *list, uint32_t key_id);
const RSAPrivateKey *find_private_key(const PrivateKeyList *list, uint32_t key_id);

#endif