#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "key.h"
#include "rsa_openssl.h"

#define DEFAULT_KEY_COUNT 100

static int generate_key_list(uint32_t count,
                             PublicKeyList *public_list,
                             PrivateKeyList *private_list) {
    BN_CTX *ctx = BN_CTX_new();

    if (ctx == NULL || public_list == NULL || private_list == NULL) {
        return -1;
    }

    public_list->count = 0;
    private_list->count = 0;

    for (uint32_t i = 0; i < count; i++) {
        RSAPublicKey pub = {0};
        RSAPrivateKey priv = {0};

        pub.key_id = i + 1;
        priv.key_id = i + 1;

        if (rsa_generate_keys(&pub, &priv, ctx) < 0) {
            BN_CTX_free(ctx);
            return -1;
        }

        pub.key_id = i + 1;
        priv.key_id = i + 1;

        public_list->keys[public_list->count++] = pub;
        private_list->keys[private_list->count++] = priv;
    }

    BN_CTX_free(ctx);
    return 0;
}

int main(int argc, char *argv[]) {
    uint32_t key_count = DEFAULT_KEY_COUNT;

    PublicKeyList auth_public_keys = {0};
    PrivateKeyList auth_private_keys = {0};

    PublicKeyList ballot_public_keys = {0};
    PrivateKeyList ballot_private_keys = {0};

    if (argc > 1) {
        int parsed = atoi(argv[1]);
        if (parsed > 0 && parsed <= MAX_KEYS) {
            key_count = (uint32_t)parsed;
        }
    }

    if (generate_key_list(key_count, &auth_public_keys, &auth_private_keys) < 0) {
        fprintf(stderr, "Failed to generate auth key list\n");
        return 1;
    }

    if (generate_key_list(key_count, &ballot_public_keys, &ballot_private_keys) < 0) {
        fprintf(stderr, "Failed to generate ballot key list\n");
        return 1;
    }

    if (save_public_key_list_bin("keys/public_auth_keys.bin", &auth_public_keys) < 0 ||
        save_private_key_list_bin("keys/private_auth_keys.bin", &auth_private_keys) < 0 ||
        save_public_key_list_txt("keys/public_auth_keys.txt", &auth_public_keys) < 0 ||
        save_private_key_list_txt("keys/private_auth_keys.txt", &auth_private_keys) < 0) {
        fprintf(stderr, "Failed to save auth key files\n");
        return 1;
    }

    if (save_public_key_list_bin("keys/public_ballot_keys.bin", &ballot_public_keys) < 0 ||
        save_private_key_list_bin("keys/ballot_priv_keys.bin", &ballot_private_keys) < 0 ||
        save_public_key_list_txt("keys/public_ballot_keys.txt", &ballot_public_keys) < 0 ||
        save_private_key_list_txt("keys/ballot_priv_keys.txt", &ballot_private_keys) < 0) {
        fprintf(stderr, "Failed to save ballot key files\n");
        return 1;
    }

    printf("Generated %u auth key pairs\n", key_count);
    printf("Generated %u ballot key pairs\n", key_count);
    printf("Wrote all key files into ./keys/\n");

    return 0;
}