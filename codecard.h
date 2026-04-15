#ifndef CODECARD_H
#define CODECARD_H

#include <stdint.h>

#define NUM_CANDIDATES 4
#define CODE_LENGTH 5
#define SEED_LENGTH 32

typedef struct {
    uint32_t candidate_id;
    char vote_code[CODE_LENGTH];
} VoteCodeEntry;

typedef struct {
    VoteCodeEntry entries[NUM_CANDIDATES];
    char confirm_code[CODE_LENGTH];
    unsigned char receipt_seed[SEED_LENGTH];
} CodeCard;

void init_code_card(CodeCard* card);
int find_candidate_by_code(const CodeCard* card, const char* code);
void print_code_card(const CodeCard* card);

#endif