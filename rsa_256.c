#include <stdio.h>
#include <gmp.h>
#include <time.h>

/*
========================
RANDOM STATE
========================
*/
gmp_randstate_t state;

/*
========================
KEY GENERATION
========================
*/
void generate_keys(mpz_t n, mpz_t e, mpz_t d) {
    mpz_t p, q, phi, gcd, tmp;

    mpz_inits(p, q, phi, gcd, tmp, NULL);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // Fixed public exponent (standard RSA choice)
    mpz_set_ui(e, 65537);

    while (1) {
        // Generate 256-bit primes
        mpz_urandomb(p, state, 256);
        mpz_nextprime(p, p);

        mpz_urandomb(q, state, 256);
        mpz_nextprime(q, q);

        if (mpz_cmp(p, q) == 0)
            continue;

        // n = p * q
        mpz_mul(n, p, q);

        // phi = (p-1)(q-1)
        mpz_sub_ui(tmp, p, 1);
        mpz_sub_ui(phi, q, 1);
        mpz_mul(phi, phi, tmp);

        // check gcd(e, phi) == 1
        mpz_gcd(gcd, e, phi);

        if (mpz_cmp_ui(gcd, 1) == 0) {
            // compute private key
            mpz_invert(d, e, phi);
            break;
        }
    }

    mpz_clears(p, q, phi, gcd, tmp, NULL);
}

/*
========================
ENCRYPT / DECRYPT
========================
*/
void encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    mpz_powm(c, m, e, n);
}

void decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    mpz_powm(m, c, d, n);
}

/*
========================
MAIN TEST
========================
*/
int main() {
    mpz_t n, e, d;
    mpz_t m, c, r;

    mpz_inits(n, e, d, m, c, r, NULL);

    generate_keys(n, e, d);

    // message (must be < n)
    mpz_set_ui(m, 42);

    encrypt(c, m, e, n);
    decrypt(r, c, d, n);

    gmp_printf("Public key (e, n):\n");
    gmp_printf("e = %Zd\nn = %Zd\n\n", e, n);

    gmp_printf("Private key (d, n):\n");
    gmp_printf("d = %Zd\nn = %Zd\n\n", d, n);

    gmp_printf("Original:  %Zd\n", m);
    gmp_printf("Encrypted: %Zd\n", c);
    gmp_printf("Decrypted: %Zd\n", r);

    mpz_clears(n, e, d, m, c, r, NULL);
    gmp_randclear(state);

    return 0;
}