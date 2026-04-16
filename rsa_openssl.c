/* Overview: RSA Encryption/Decryption using OpenSSL BIGNUM
- ~512-bit modulus (256-bit primes)
- Uses struct-based keys
- 256 bit message and key
*/

#include <stdio.h>
#include <openssl/bn.h>

// Key struct
typedef struct {
    BIGNUM *n;
    BIGNUM *e;
} PublicKey;

typedef struct {
    BIGNUM *n;
    BIGNUM *d;
} PrivateKey;

// Key init and free funcs
void init_public_key(PublicKey *pub) {
    pub->n = BN_new();
    pub->e = BN_new();
}

void init_private_key(PrivateKey *priv) {
    priv->n = BN_new();
    priv->d = BN_new();
}

void free_public_key(PublicKey *pub) {
    BN_free(pub->n);
    BN_free(pub->e);
}

void free_private_key(PrivateKey *priv) {
    BN_free(priv->n);
    BN_free(priv->d);
}

// Key gen (will move to another file)
void generate_keys(PublicKey *pub, PrivateKey *priv, BN_CTX *ctx) {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    // e = 65537 is pretty standard i guess (Wikipedia)
    BN_set_word(pub->e, 65537);

    while (1) {
        // Generate 256-bit primes
        // Use Miller-Rabin primality test (# round = optimized internally by OpenSSL)
        BN_generate_prime_ex(p, 256, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(q, 256, 0, NULL, NULL, NULL);

        // n = p * q
        BN_mul(pub->n, p, q, ctx);

        // phi = (p-1)(q-1)
        BN_sub(p1, p, BN_value_one());
        BN_sub(q1, q, BN_value_one());
        BN_mul(phi, p1, q1, ctx);

        // d = e^-1 mod phi
        if (BN_mod_inverse(priv->d, pub->e, phi, ctx) != NULL) {
            // success
            BN_copy(priv->n, pub->n);
            break;
        }
    }

    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(p1);
    BN_free(q1);
}

// Encrypt and Decrypt
// void encrypt(BIGNUM *c, BIGNUM *m, PublicKey *pub, BN_CTX *ctx) {
//     BN_mod_exp(c, m, pub->e, pub->n, ctx);
// }

// Refined to return BIGNUM ciphertext (must free c later)
BIGNUM* encrypt(BIGNUM *m, PublicKey *pub, BN_CTX *ctx) {
    BIGNUM *c = BN_new();

    BN_mod_exp(c, m, pub->e, pub->n, ctx);

    return c;  // caller must free
}

// void decrypt(BIGNUM *m, BIGNUM *c, PrivateKey *priv, BN_CTX *ctx) {
//     BN_mod_exp(m, c, priv->d, priv->n, ctx);
// }

// Refined to return BIGNUM msg (must free m later)
BIGNUM* decrypt(BIGNUM *c, PrivateKey *priv, BN_CTX *ctx) {
    BIGNUM *m = BN_new();

    BN_mod_exp(m, c, priv->d, priv->n, ctx);

    return m;  // caller must free
}

// Helper func to print BIGNUMS to decimal (for testing only)
void print_bn(const char *label, BIGNUM *bn) {
    char *s = BN_bn2dec(bn);
    printf("%s: %s\n", label, s);
    OPENSSL_free(s);
}

// #################### MAIN TESTING ####################
// int main() {
//     BN_CTX *ctx = BN_CTX_new();

//     PublicKey pub;
//     PrivateKey priv;

//     init_public_key(&pub);
//     init_private_key(&priv);

//     BIGNUM *m = BN_new();
//     BIGNUM *c = BN_new();
//     BIGNUM *r = BN_new();

//     // Generate keys
//     generate_keys(&pub, &priv, ctx);

//     // Message
//     char msg[] = "We had 4 days";
//     BN_set_word(m, (unsigned char)msg[0]);  // 'W' = 87

//     // Just wanted to check original message
//     print_bn("Original Message", m);

//     // Encrypt
//     encrypt(c, m, &pub, ctx);
//     print_bn("Ciphertext", c);

//     // Decrypt
//     decrypt(r, c, &priv, ctx);
//     print_bn("Decrypted Result", r);

//     // Clean up
//     BN_free(m);
//     BN_free(c);
//     BN_free(r);

//     free_public_key(&pub);
//     free_private_key(&priv);

//     BN_CTX_free(ctx);

//     return 0;
// }

int main() {
    BN_CTX *ctx = BN_CTX_new();

    // Key init
    PublicKey pub;
    PrivateKey priv;
    init_public_key(&pub);
    init_private_key(&priv);

    // Key gen (server)
    generate_keys(&pub, &priv, ctx);

    // msg (client)
    BIGNUM *m = BN_new();
    char msg[] = "We had 4 days";
    BN_set_word(m, (unsigned char)msg[0]);  // 'W' = 87

    // Encrypt (client - testing)
    BIGNUM *c = encrypt(m, &pub, ctx);

    // Decrypt (server - testing)
    BIGNUM *r = decrypt(c, &priv, ctx);

    // Print stuff to console
    print_bn("Original", m);
    print_bn("Ciphertext", c);
    print_bn("Decrypted", r);

    // Cleanup: free m, c, r, pub/priv keys, and ctx
    BN_free(m);
    BN_free(c);
    BN_free(r);

    free_public_key(&pub);
    free_private_key(&priv);

    BN_CTX_free(ctx);

    return 0;
}