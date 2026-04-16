#ifndef RSA_H
#define RSA_H

#include <stdint.h>

uint64_t rsa_encrypt_uint64(uint64_t message, uint64_t e, uint64_t n);
uint64_t rsa_decrypt_uint64(uint64_t ciphertext, uint64_t d, uint64_t n);

#endif