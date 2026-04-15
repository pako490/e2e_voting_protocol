#include "codecard.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

static const char ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static void random_code(char out[CODE_LENGTH]) {
    unsigned char b;
    for (int i = 0; i < CODE_LENGTH - 1; i++) {
        RAND_bytes(&b, 1);
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
    RAND_bytes(card->receipt_seed, SEED_LENGTH);
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