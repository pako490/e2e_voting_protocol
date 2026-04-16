#include <stdio.h>
#include <stdint.h>

typedef uint64_t u64;    // Kinda lazy to type the entire thing every time LOL

// SAFE MODULAR MULTIPLICATION
// Sort of prevents overflow by using addition instead of multiplication
u64 modmul(u64 a, u64 b, u64 mod) {
    u64 result = 0;
    a %= mod;

    while (b > 0) {
        if (b & 1) {
            result = (result + a) % mod;
        }
        a = (a << 1) % mod;
        b >>= 1;
    }

    return result;
}

// (Kinda safe) modular exponentation using the square-and-multiply algorithm
u64 modexp(u64 base, u64 exp, u64 mod) {
    u64 result = 1;
    base %= mod;

    while (exp > 0) {
        if (exp & 1) {
            result = modmul(result, base, mod);
        }
        base = modmul(base, base, mod);
        exp >>= 1;
    }

    return result;
}

// GCD using Euclid's algo
u64 gcd(u64 a, u64 b) {
    while (b != 0) {
        u64 t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Extended GCD (reverse GCD)
long long egcd(long long a, long long b, long long *x, long long *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }

    long long x1, y1;
    long long g = egcd(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return g;
}

// Mod inverse using extended GCD
u64 modinv(u64 e, u64 phi) {
    long long x, y;
    egcd(e, phi, &x, &y);
    return (x % (long long)phi + phi) % phi;
}

// ######## [TEMP] KEYS ######## 
// Should be moved to a separate file i guess

/* Rules for key gen:

1. Pick prime p and q such that
    - p and q are large
    - p != q
2. Find n = p * q
3. Compute phi = (p - 1) * (q - 1)
4. Choose e such that 1 < e < phi and gcd(e, phi) = 1
5. Compute d such that d ≡ e^(-1) (mod phi)

*/

u64 e, d, n;

void generate_keys() {
    u64 p = 999331;
    u64 q = 115249;

    n = p * q;
    u64 phi = (p - 1) * (q - 1);

    e = 65537; // Common choice for e (i guess?)

    while (gcd(e, phi) != 1) {
        e += 2; // try next odd number
    }

    // Hmm, the more correct approach for this is to regenerate the prime until gcd(e, phi) == 1
    // This is just testing --> but will be crucial for separate key gen in the future
    d = modinv(e, phi);
}

// RSA main stuff
u64 encrypt(u64 m, u64 e_, u64 n_) {
    return modexp(m, e_, n_);
}

u64 decrypt(u64 c, u64 d_, u64 n_) {
    return modexp(c, d_, n_);
}


//for testing
uint64_t rsa_encrypt_uint64(uint64_t message, uint64_t e, uint64_t n){

    return message;
}

uint64_t rsa_decrypt_uint64(uint64_t ciphertext, uint64_t d, uint64_t n){
    return ciphertext;
}


// // Local Testing
// int main() {
//     generate_keys();

//     // Message
//     u64 m = "We had 4 days"[0];

//     // Placeholder for testing
//     u64 a = encrypt(m, e, n);
//     u64 b = decrypt(a, d, n);

//     printf("m = %llu\n", m);
//     printf("a = %llu\n", a);
//     printf("b = %llu\n", b);

//     return 0;
// }