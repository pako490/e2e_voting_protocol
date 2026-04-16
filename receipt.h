#ifndef RECEIPT_H
#define RECEIPT_H

#include "codecard.h"
#include <stddef.h>
#include <stdint.h>

#define HASH_LEN 32

typedef struct {
    uint32_t candidate_id;
    char verification_code[CODE_LENGTH];
} ReceiptEntry;

typedef struct {
    ReceiptEntry entries[NUM_CANDIDATES];
    unsigned char ciphertext_hash[HASH_LEN];
} VoteReceipt;

void generate_receipt(const CodeCard* card, uint32_t selected_candidate_id, const unsigned char *ciphertext, size_t ciphertext_len, VoteReceipt *receipt);
void print_receipt(const VoteReceipt* receipt);

#endif