#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

//rewritten so that it takes care of public/private pairs

#define MAX_KEYS 1000
#define DEFAULT_KEY_COUNT 100

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

static uint64_t gcd_uint64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    int64_t x1 = 0;
    int64_t y1 = 0;
    int64_t g = extended_gcd(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

static uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    int64_t x = 0;
    int64_t y = 0;
    int64_t g = extended_gcd((int64_t)e, (int64_t)phi, &x, &y);

    if (g != 1) {
        return 0;
    }

    int64_t result = x % (int64_t)phi;
    if (result < 0) {
        result += (int64_t)phi;
    }

    return (uint64_t)result;
}

static int is_prime(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if ((n % 2) == 0) return 0;

    for (uint64_t i = 3; i * i <= n; i += 2) {
        if ((n % i) == 0) {
            return 0;
        }
    }

    return 1;
}

static uint64_t random_in_range(uint64_t min, uint64_t max) {
    return min + ((uint64_t)rand() % (max - min + 1));
}

static uint64_t generate_prime(uint64_t min, uint64_t max) {
    while (1) {
        uint64_t candidate = random_in_range(min, max);

        if ((candidate % 2) == 0) {
            candidate++;
        }

        while (candidate <= max) {
            if (is_prime(candidate)) {
                return candidate;
            }
            candidate += 2;
        }
    }
}

static int generate_rsa_keypair(uint32_t key_id, RSAPublicKey *pub, RSAPrivateKey *priv) {
    if (pub == NULL || priv == NULL) {
        return -1;
    }

    uint64_t p = generate_prime(2000, 5000);
    uint64_t q = generate_prime(5001, 9000);

    while (q == p) {
        q = generate_prime(5001, 9000);
    }

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 65537;
    if (e >= phi || gcd_uint64(e, phi) != 1) {
        e = 3;
        while (e < phi && gcd_uint64(e, phi) != 1) {
            e += 2;
        }
    }

    if (e >= phi) {
        return -1;
    }

    uint64_t d = mod_inverse(e, phi);
    if (d == 0) {
        return -1;
    }

    pub->key_id = key_id;
    pub->n = n;
    pub->e = e;

    priv->key_id = key_id;
    priv->n = n;
    priv->d = d;

    return 0;
}

static int save_public_keys_bin(const char *filename, const PublicKeyList *list) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        return -1;
    }

    size_t written = fwrite(list, sizeof(PublicKeyList), 1, fp);
    fclose(fp);

    return (written == 1) ? 0 : -1;
}

static int save_private_keys_bin(const char *filename, const PrivateKeyList *list) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        return -1;
    }

    size_t written = fwrite(list, sizeof(PrivateKeyList), 1, fp);
    fclose(fp);

    return (written == 1) ? 0 : -1;
}

static int save_public_keys_txt(const char *filename, const PublicKeyList *list) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "count=%u\n", list->count);
    fprintf(fp, "key_id,n,e\n");

    for (uint32_t i = 0; i < list->count; i++) {
        fprintf(fp, "%u,%llu,%llu\n",
                list->keys[i].key_id,
                (unsigned long long)list->keys[i].n,
                (unsigned long long)list->keys[i].e);
    }

    fclose(fp);
    return 0;
}

static int save_private_keys_txt(const char *filename, const PrivateKeyList *list) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "count=%u\n", list->count);
    fprintf(fp, "key_id,n,d\n");

    for (uint32_t i = 0; i < list->count; i++) {
        fprintf(fp, "%u,%llu,%llu\n",
                list->keys[i].key_id,
                (unsigned long long)list->keys[i].n,
                (unsigned long long)list->keys[i].d);
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    PublicKeyList public_list = {0};
    PrivateKeyList private_list = {0};

    uint32_t key_count = DEFAULT_KEY_COUNT;
    if (argc > 1) {
        int parsed = atoi(argv[1]);
        if (parsed > 0 && parsed <= MAX_KEYS) {
            key_count = (uint32_t)parsed;
        }
    }

    srand((unsigned int)time(NULL));

    for (uint32_t i = 0; i < key_count; i++) {
        RSAPublicKey pub;
        RSAPrivateKey priv;

        if (generate_rsa_keypair(i + 1, &pub, &priv) < 0) {
            fprintf(stderr, "Failed to generate keypair for key_id=%u\n", i + 1);
            return 1;
        }

        public_list.keys[public_list.count++] = pub;
        private_list.keys[private_list.count++] = priv;
    }

    if (save_public_keys_bin("public_keys.bin", &public_list) < 0) {
        fprintf(stderr, "Failed to save public_keys.bin\n");
        return 1;
    }

    if (save_private_keys_bin("private_keys.bin", &private_list) < 0) {
        fprintf(stderr, "Failed to save private_keys.bin\n");
        return 1;
    }

    if (save_public_keys_txt("public_keys.txt", &public_list) < 0) {
        fprintf(stderr, "Failed to save public_keys.txt\n");
        return 1;
    }

    if (save_private_keys_txt("private_keys.txt", &private_list) < 0) {
        fprintf(stderr, "Failed to save private_keys.txt\n");
        return 1;
    }

    printf("Generated %u RSA keypairs\n", key_count);
    printf("Wrote public_keys.bin and public_keys.txt\n");
    printf("Wrote private_keys.bin and private_keys.txt\n");

    return 0;
}