#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>

#define MAX_KEYS 1000
#define KEY_LEN 32

#define MAX_BALLOT_OPTIONS 50
#define OPTION_TEXT_LEN 100

typedef struct {
    char key[KEY_LEN];
} VotingKey;

typedef struct {
    uint32_t id;
    char text[OPTION_TEXT_LEN];
} BallotOption;

/* Global arrays and counters */
extern VotingKey valid_keys[MAX_KEYS];
extern int valid_key_count;

extern VotingKey used_keys[MAX_KEYS];
extern int used_key_count;

extern BallotOption ballot_options[MAX_BALLOT_OPTIONS];
extern int ballot_option_count;

/* Loaders */
int load_valid_keys_binary(const char *filename);
int load_ballot_binary(const char *filename);

/* Runtime used key handling */
void init_used_keys(void);
int append_used_key(const char *key);

/* Validation helpers */
int is_valid_key(const char *submitted_key);
int is_used_key(const char *submitted_key);
int is_valid_ballot_choice(uint32_t choice_id);

/* Formatting helper */
int build_ballot_text(char *buffer, int buffer_size);

/* Debug helpers */
void print_valid_keys(void);
void print_used_keys(void);
void print_ballot(void);

#endif