#ifndef RSA_H
#define RSA_H

#include <stdint.h>

int rsa_encrypt_bytes(
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len,
    const RSAPublicKey *pub,
    BN_CTX *ctx
);

int rsa_decrypt_bytes(
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len,
    const RSAPrivateKey *priv,
    BN_CTX *ctx
);

#endif