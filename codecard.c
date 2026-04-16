#include "codecard.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "receipt.h"

static const char ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static void random_code(char out[CODE_LENGTH]) {
    unsigned char b;
    for (int i = 0; i < CODE_LENGTH - 1; i++) {
        b = rand() % 256;
        out[i] = ALPHABET[b % (sizeof(ALPHABET) - 1)];
    }
    out[CODE_LENGTH - 1] = '\0';
}

void init_code_card(CodeCard *card) {
    memset(card, 0, sizeof(*card));

    for (int i = 0; i < NUM_CANDIDATES; i++) {
        card->entries[i].candidate_id = i + 1;
        random_code(card->entries[i].vote_code);
    }

    random_code(card->confirm_code);

    for (int i = 0; i < SEED_LENGTH; i++) {
        card->receipt_seed[i] = rand() % 256;
    }
}

int find_candidate_by_code(const CodeCard *card, const char *code) {
    for (int i = 0; i < NUM_CANDIDATES; i++) {
        if (strcmp(card->entries[i].vote_code, code) == 0) {
            return (int)card->entries[i].candidate_id;
        }
    }
    return -1;
}

void print_code_card(const CodeCard *card) {
    printf("Code Card\n");
    for (int i = 0; i < NUM_CANDIDATES; i++) {
        printf("%u -> %s\n",
               card->entries[i].candidate_id,
               card->entries[i].vote_code);
    }
    printf("Confirmation Code -> %s\n", card->confirm_code);
}


int codecard_value_for_choice(uint32_t choice_id, uint64_t *out_value) {
    if (out_value == NULL) {
        return -1;
    }

    switch (choice_id) {
        case 1: *out_value = 1101; return 0;
        case 2: *out_value = 2202; return 0;
        case 3: *out_value = 3303; return 0;
        case 4: *out_value = 4404; return 0;
        default: return -1;
    }
}

int codecard_text_for_value(uint64_t value, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return -1;
    }

    switch (value) {
        case 1101:
            snprintf(out, out_len, "Choice 1 confirmed");
            return 0;
        case 2202:
            snprintf(out, out_len, "Choice 2 confirmed");
            return 0;
        case 3303:
            snprintf(out, out_len, "Choice 3 confirmed");
            return 0;
        case 4404:
            snprintf(out, out_len, "Choice 4 confirmed");
            return 0;
        default:
            snprintf(out, out_len, "Unknown receipt value");
            return -1;
    }
}