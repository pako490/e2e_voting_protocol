#include "key.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void ensure_keys_directory(void) {
    /* Creates ./keys if it does not already exist */
    mkdir("keys", 0777);
}

static void write_hex_bytes(FILE *fp, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02X", bytes[i]);
    }
}

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

int save_public_key_list_bin(const char *filename, const PublicKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    ensure_keys_directory();

    fp = fopen(filename, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (fwrite(list, sizeof(PublicKeyList), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int save_private_key_list_bin(const char *filename, const PrivateKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    ensure_keys_directory();

    fp = fopen(filename, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (fwrite(list, sizeof(PrivateKeyList), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int save_public_key_list_txt(const char *filename, const PublicKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    ensure_keys_directory();

    fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "count=%u\n", list->count);
    fprintf(fp, "key_id,n,e\n");

    for (uint32_t i = 0; i < list->count; i++) {
        fprintf(fp, "%u,", list->keys[i].key_id);
        write_hex_bytes(fp, list->keys[i].n_bytes, list->keys[i].n_len);
        fprintf(fp, ",");
        write_hex_bytes(fp, list->keys[i].e_bytes, list->keys[i].e_len);
        fprintf(fp, "\n");
    }

    fclose(fp);
    return 0;
}

int save_private_key_list_txt(const char *filename, const PrivateKeyList *list) {
    FILE *fp;

    if (filename == NULL || list == NULL) {
        return -1;
    }

    ensure_keys_directory();

    fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "count=%u\n", list->count);
    fprintf(fp, "key_id,d\n");

    for (uint32_t i = 0; i < list->count; i++) {
        fprintf(fp, "%u,", list->keys[i].key_id);
        write_hex_bytes(fp, list->keys[i].d_bytes, list->keys[i].d_len);
        fprintf(fp, "\n");
    }

    fclose(fp);
    return 0;
}

const RSAPublicKey *find_public_key(const PublicKeyList *list, uint32_t key_id) {
    if (list == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < list->count; i++) {
        if (list->keys[i].key_id == key_id) {
            return &list->keys[i];
        }
    }

    return NULL;
}

const RSAPrivateKey *find_private_key(const PrivateKeyList *list, uint32_t key_id) {
    if (list == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < list->count; i++) {
        if (list->keys[i].key_id == key_id) {
            return &list->keys[i];
        }
    }

    return NULL;
}
