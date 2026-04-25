#ifndef KEY_H
#define KEY_H

#include <stdint.h>
#include "rsa_openssl.h"

#define MAX_KEYS 1000

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

int save_public_key_list_bin(const char *filename, const PublicKeyList *list);
int save_private_key_list_bin(const char *filename, const PrivateKeyList *list);

int save_public_key_list_txt(const char *filename, const PublicKeyList *list);
int save_private_key_list_txt(const char *filename, const PrivateKeyList *list);

const RSAPublicKey *find_public_key(const PublicKeyList *list, uint32_t key_id);
const RSAPrivateKey *find_private_key(const PrivateKeyList *list, uint32_t key_id);

#endif