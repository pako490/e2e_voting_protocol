#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>

#include "rsa_openssl.h"

// Debug helpers

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}

void print_bn(const char *label, BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

// Key gen

int rsa_generate_keys(RSAPublicKey *pub, RSAPrivateKey *priv, BN_CTX *ctx) {
    BIGNUM *p   = BN_new();
    BIGNUM *q   = BN_new();
    BIGNUM *n   = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *e   = BN_new();
    BIGNUM *d   = BN_new();
    BIGNUM *p1  = BN_new();
    BIGNUM *q1  = BN_new();
    int     ret = -1;

    if (!p || !q || !n || !phi || !e || !d || !p1 || !q1)
        goto cleanup;

    BN_generate_prime_ex(p, KEY_BITS / 2, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, KEY_BITS / 2, 0, NULL, NULL, NULL);

    BN_mul(n, p, q, ctx);

    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(phi, p1, q1, ctx);

    BN_set_word(e, 65537);
    BN_mod_inverse(d, e, phi, ctx);

    /* Public key */
    pub->n = BN_dup(n);
    pub->e = BN_dup(e);

    pub->n_len = (size_t)BN_num_bytes(pub->n);
    BN_bn2bin(pub->n, pub->n_bytes);

    pub->e_len = (size_t)BN_num_bytes(pub->e);
    BN_bn2bin(pub->e, pub->e_bytes);

    /* Private key */
    priv->n = BN_dup(n);
    priv->d = BN_dup(d);

    priv->n_len = (size_t)BN_num_bytes(priv->n);
    BN_bn2bin(priv->n, priv->n_bytes);

    priv->d_len = (size_t)BN_num_bytes(priv->d);
    BN_bn2bin(priv->d, priv->d_bytes);

    /* Store e in private key too (handy for sending ballot public info) */
    priv->e_len = (size_t)BN_num_bytes(e);
    BN_bn2bin(e, priv->e_bytes);

    ret = 0;

cleanup:
    BN_free(p);  BN_free(q);
    BN_free(n);  BN_free(phi);
    BN_free(e);  BN_free(d);
    BN_free(p1); BN_free(q1);
    return ret;
}

void rsa_free_keys(RSAPublicKey *pub, RSAPrivateKey *priv) {
    if (pub)  { BN_free(pub->n);  BN_free(pub->e); }
    if (priv) { BN_free(priv->n); BN_free(priv->d); }
}

// Internal mod-exp helper
static int mod_exp_bytes(
    const uint8_t *base_bytes, size_t base_len,
    const uint8_t *exp_bytes,  size_t exp_len,
    const uint8_t *mod_bytes,  size_t mod_len,
    uint8_t       *out,        size_t *out_len
) {
    BN_CTX *ctx  = BN_CTX_new();
    BIGNUM *base = BN_bin2bn(base_bytes, (int)base_len, NULL);
    BIGNUM *exp  = BN_bin2bn(exp_bytes,  (int)exp_len,  NULL);
    BIGNUM *mod  = BN_bin2bn(mod_bytes,  (int)mod_len,  NULL);
    BIGNUM *res  = BN_new();
    int     ret  = -1;

    if (!ctx || !base || !exp || !mod || !res)
        goto cleanup;

    if (!BN_mod_exp(res, base, exp, mod, ctx))
        goto cleanup;

    // Zero-pad the result to the same width as the modulus
    int key_bytes = BN_num_bytes(mod);
    memset(out, 0, (size_t)key_bytes);
    BN_bn2bin(res, out + (key_bytes - BN_num_bytes(res)));
    *out_len = (size_t)key_bytes;
    ret = 0;

cleanup:
    BN_CTX_free(ctx);
    BN_free(base);
    BN_free(exp);
    BN_free(mod);
    BN_free(res);
    return ret;
}

// Public API

//  c = m^e mod n
int rsa_encrypt_bytes(
    const uint8_t *in,      size_t in_len,
    const uint8_t *n_bytes, size_t n_len,
    const uint8_t *e_bytes, size_t e_len,
    uint8_t       *out,     size_t *out_len
) {
    return mod_exp_bytes(in, in_len, e_bytes, e_len, n_bytes, n_len, out, out_len);
}

// m = c^d mod n
int rsa_decrypt_bytes(
    const uint8_t *in,      size_t in_len,
    const uint8_t *n_bytes, size_t n_len,
    const uint8_t *d_bytes, size_t d_len,
    uint8_t       *out,     size_t *out_len
) {
    return mod_exp_bytes(in, in_len, d_bytes, d_len, n_bytes, n_len, out, out_len);
}