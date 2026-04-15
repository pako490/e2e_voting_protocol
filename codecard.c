#include "receipt.h"
#include <stdio.h>
#include <string.h>
// ciphertext used to bind receipt to encrypted vote
#include <openssl/hmac.h>

static const char ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static void derive_fake_code(const unsigned char *seed,
                             uint32_t candidate_id,
                             const unsigned char hash[SHA256_DIGEST_LENGTH],
                             char out[CODE_LENGTH]) {
    unsigned char msg[sizeof(candidate_id) + SHA256_DIGEST_LENGTH];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    memcpy(msg, &candidate_id, sizeof(candidate_id));
    memcpy(msg + sizeof(candidate_id), hash, SHA256_DIGEST_LENGTH);

    HMAC(EVP_sha256(), seed, SEED_LENGTH, msg, sizeof(msg), mac, &mac_len);

    for (int i = 0; i < CODE_LENGTH - 1; i++) {
        out[i] = ALPHABET[mac[i] % (sizeof(ALPHABET) - 1)];
    }
    out[CODE_LENGTH - 1] = '\0';
}

void generate_receipt(const CodeCard *card,
                      int selected_candidate_id,
                      const unsigned char *ciphertext,
                      size_t ciphertext_len,
                      VoteReceipt *receipt) {
    memset(receipt, 0, sizeof(*receipt));
    SHA256(ciphertext, ciphertext_len, receipt->ciphertext_hash);

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