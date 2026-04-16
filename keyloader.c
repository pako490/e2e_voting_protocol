#include "keyloader.h"

#include <stdio.h>
#include <string.h>

int load_public_key_list_bin(const char *filename, PublicKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        return -1;
    }

    memset(list, 0, sizeof(*list));

    if (fread(list, sizeof(PublicKeyList), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int load_private_key_list_bin(const char *filename, PrivateKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        return -1;
    }

    memset(list, 0, sizeof(*list));

    if (fread(list, sizeof(PrivateKeyList), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

const RSAPublicKey *find_public_key(const PublicKeyList *list, uint32_t key_id) {
    uint32_t i;

    if (list == NULL) {
        return NULL;
    }

    for (i = 0; i < list->count; i++) {
        if (list->keys[i].key_id == key_id) {
            return &list->keys[i];
        }
    }

    return NULL;
}

const RSAPrivateKey *find_private_key(const PrivateKeyList *list, uint32_t key_id) {
    uint32_t i;

    if (list == NULL) {
        return NULL;
    }

    for (i = 0; i < list->count; i++) {
        if (list->keys[i].key_id == key_id) {
            return &list->keys[i];
        }
    }

    return NULL;
}