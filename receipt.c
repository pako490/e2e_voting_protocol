#include "receipt.h"
#include <stdio.h>
#include <string.h>
#include "codecard.h"

static const char ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// ciphertext hash used to bind receipt to encrypted vote
void simple_hash(const unsigned char *data, size_t len, unsigned char out[HASH_LEN]) {
    for (int i = 0; i < HASH_LEN; i++) out[i] = 0;

    for (size_t i = 0; i < len; i++) {
        out[i % HASH_LEN] ^= data[i];
        out[(i * 7) % HASH_LEN] += data[i];
    }
}

void derive_fake_code(const unsigned char *seed, int candidate_id,
                      const unsigned char *hash, char *out) {

    for (int i = 0; i < 4; i++) {
        unsigned int v = (unsigned int)candidate_id * 31 + i * 17;

        for (int j = 0; j < HASH_LEN; j++) {
            v += hash[j] * (j + 1);
            v += seed[(i + j) % SEED_LENGTH];
            v ^= (v << 3);
            v ^= (v >> 2);
        }

        out[i] = ALPHABET[v % 32];
    }

    out[4] = '\0';
}

void generate_receipt(const CodeCard *card,
                      uint32_t  selected_candidate_id,
                      const unsigned char *ciphertext,
                      size_t ciphertext_len,
                      VoteReceipt *receipt) {
    memset(receipt, 0, sizeof(*receipt));
    simple_hash(ciphertext, ciphertext_len, receipt->ciphertext_hash);

    for (int i = 0; i < NUM_CANDIDATES; i++) {
        receipt->entries[i].candidate_id = card->entries[i].candidate_id;

        if ((int)card->entries[i].candidate_id == selected_candidate_id) {
            strcpy(receipt->entries[i].verification_code, card->confirm_code);
        } else {
            derive_fake_code(card->receipt_seed,
                             card->entries[i].candidate_id,
                             receipt->ciphertext_hash,
                             receipt->entries[i].verification_code);
        }
    }
}

void print_receipt(const VoteReceipt *receipt) {
    printf("Vote Receipt\n");
    for (int i = 0; i < NUM_CANDIDATES; i++) {
        printf("%u -> %s\n",
               receipt->entries[i].candidate_id,
               receipt->entries[i].verification_code);
    }
}