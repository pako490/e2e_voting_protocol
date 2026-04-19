#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

#define KEY_BITS 1024
#define MAX_BYTES 256  // supports up to 2048-bit keys

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
} RSAPublicKey;

typedef struct {
    BIGNUM *n;
    BIGNUM *d;
} RSAPrivateKey;

/* =========================
   Utility Functions
   ========================= */

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void print_bn(const char *label, BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/* =========================
   Key Generation
   ========================= */

int rsa_generate_keys(RSAPublicKey *pub, RSAPrivateKey *priv, BN_CTX *ctx) {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    if (!p || !q || !n || !phi || !e || !d || !p1 || !q1)
        return -1;

    // Generate primes
    BN_generate_prime_ex(p, KEY_BITS / 2, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, KEY_BITS / 2, 0, NULL, NULL, NULL);

    // n = p * q
    BN_mul(n, p, q, ctx);

    // phi = (p-1)(q-1)
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(phi, p1, q1, ctx);

    // e = 65537
    BN_set_word(e, 65537);

    // d = e^-1 mod phi
    BN_mod_inverse(d, e, phi, ctx);

    pub->n = BN_dup(n);
    pub->e = BN_dup(e);

    priv->n = BN_dup(n);
    priv->d = BN_dup(d);

    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(phi);
    BN_free(e);
    BN_free(d);
    BN_free(p1);
    BN_free(q1);

    return 0;
}

/* =========================
   Core RSA (BIGNUM)
   ========================= */

BIGNUM *rsa_encrypt_bn(BIGNUM *m, const RSAPublicKey *pub, BN_CTX *ctx) {
    BIGNUM *c = BN_new();
    BN_mod_exp(c, m, pub->e, pub->n, ctx);
    return c;
}

BIGNUM *rsa_decrypt_bn(BIGNUM *c, const RSAPrivateKey *priv, BN_CTX *ctx) {
    BIGNUM *m = BN_new();
    BN_mod_exp(m, c, priv->d, priv->n, ctx);
    return m;
}

/* =========================
   Byte-based API (YOUR DESIGN)
   ========================= */

int rsa_encrypt_bytes(
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len,
    const RSAPublicKey *pub,
    BN_CTX *ctx
) {
    BIGNUM *m = BN_bin2bn(in, in_len, NULL);
    if (!m) return -1;

    BIGNUM *c = rsa_encrypt_bn(m, pub, ctx);
    if (!c) {
        BN_free(m);
        return -1;
    }

    int key_bytes = BN_num_bytes(pub->n);

    memset(out, 0, key_bytes);
    BN_bn2bin(c, out + (key_bytes - BN_num_bytes(c)));

    *out_len = key_bytes;

    BN_free(m);
    BN_free(c);

    return 0;
}

int rsa_decrypt_bytes(
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len,
    const RSAPrivateKey *priv,
    BN_CTX *ctx
) {
    BIGNUM *c = BN_bin2bn(in, in_len, NULL);
    if (!c) return -1;

    BIGNUM *m = rsa_decrypt_bn(c, priv, ctx);
    if (!m) {
        BN_free(c);
        return -1;
    }

    int len = BN_num_bytes(m);
    BN_bn2bin(m, out);

    *out_len = len;

    BN_free(c);
    BN_free(m);

    return 0;
}

/* =========================
   Cleanup
   ========================= */

void rsa_free_keys(RSAPublicKey *pub, RSAPrivateKey *priv) {
    BN_free(pub->n);
    BN_free(pub->e);
    BN_free(priv->n);
    BN_free(priv->d);
}

/* =========================
   MAIN (Test)
   ========================= */

int main() {
    BN_CTX *ctx = BN_CTX_new();

    RSAPublicKey pub;
    RSAPrivateKey priv;

    printf("Generating RSA keys...\n");
    rsa_generate_keys(&pub, &priv, ctx);

    print_bn("Modulus n", pub.n);
    print_bn("Public exponent e", pub.e);
    print_bn("Private exponent d", priv.d);

    // Test message
    unsigned char message[] = {87}; // 'W'
    size_t message_len = 1;

    unsigned char ciphertext[MAX_BYTES];
    size_t ciphertext_len;

    unsigned char decrypted[MAX_BYTES];
    size_t decrypted_len;

    printf("\nOriginal message: %d\n", message[0]);

    // Encrypt
    rsa_encrypt_bytes(
        message, message_len,
        ciphertext, &ciphertext_len,
        &pub,
        ctx
    );

    printf("Ciphertext (%zu bytes):\n", ciphertext_len);
    print_hex(ciphertext, ciphertext_len);

    // Decrypt
    rsa_decrypt_bytes(
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len,
        &priv,
        ctx
    );

    printf("Decrypted message: %d\n", decrypted[0]);

    // Cleanup
    rsa_free_keys(&pub, &priv);
    BN_CTX_free(ctx);

    return 0;
}