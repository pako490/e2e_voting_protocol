#ifndef CODECARD_H
#define CODECARD_H

#include <stdint.h>
#include <stddef.h>

#define NUM_CANDIDATES 4
#define CODE_LENGTH 4
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
int codecard_value_for_choice(uint32_t choice_id, uint64_t *out_value);
int codecard_text_for_value(uint64_t value, char *out, size_t out_len);


#endif