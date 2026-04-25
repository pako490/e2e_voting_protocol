#ifndef RSA_OPENSSL_H
#define RSA_OPENSSL_H

#include "protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <openssl/bn.h>


#define KEY_BITS 1024

// Key structs

typedef struct {
    uint32_t key_id;

    BIGNUM  *n;
    BIGNUM  *e;

    uint8_t  n_bytes[RSA_MAX_BYTES];
    size_t   n_len;

    uint8_t  e_bytes[RSA_MAX_BYTES];
    size_t   e_len;
} RSAPublicKey;

typedef struct {
    uint32_t key_id;

    BIGNUM  *n;
    BIGNUM  *d;

    uint8_t  n_bytes[RSA_MAX_BYTES];
    size_t   n_len;

    uint8_t  d_bytes[RSA_MAX_BYTES];
    size_t   d_len;

    uint8_t  e_bytes[RSA_MAX_BYTES];   /* optional but useful */
    size_t   e_len;
} RSAPrivateKey;

// Key generation
int rsa_generate_keys(RSAPublicKey *pub, RSAPrivateKey *priv, BN_CTX *ctx);
void rsa_free_keys(RSAPublicKey *pub, RSAPrivateKey *priv);

// RSA encryption/decryption of byte buffers
int rsa_encrypt_bytes(
    const uint8_t *in,      size_t in_len,
    const uint8_t *n_bytes, size_t n_len,
    const uint8_t *e_bytes, size_t e_len,
    uint8_t       *out,     size_t *out_len
);

int rsa_decrypt_bytes(
    const uint8_t *in,      size_t in_len,
    const uint8_t *n_bytes, size_t n_len,
    const uint8_t *d_bytes, size_t d_len,
    uint8_t       *out,     size_t *out_len
);

// Debug helpers
void print_hex(const unsigned char *buf, size_t len);
void print_bn (const char *label, BIGNUM *bn);

#endif