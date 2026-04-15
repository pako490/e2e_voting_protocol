#ifndef RECEIPT_H
#define RECEIPT_H

#include "codecard.h"
#include <stddef.h>
#include <stdint.h>
// ciphertext used to bind receipt to encrypted vote
#include <openssl/sha.h>

typedef struct {
    uint32_t candidate_id;
    char verification_code[CODE_LENGTH];
} ReceiptEntry;

typedef struct {
    ReceiptEntry entries[NUM_CANDIDATES];
    unsigned char ciphertext_hash[SHA256_DIGEST_LENGTH];
} VoteReceipt;

void generate_receipt(const CodeCard* card, uint32_t selected_candidate_id, const unsigned char *ciphertext, size_t ciphertext_len, VoteReceipt *receipt);
void print_receipt(const VoteReceipt* receipt);

#endif