#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

VotingKey valid_keys[MAX_KEYS];
int valid_key_count = 0;

VotingKey used_keys[MAX_KEYS];
int used_key_count = 0;

BallotOption ballot_options[MAX_BALLOT_OPTIONS];
int ballot_option_count = 0;

static uint32_t current_receipt_id = 1000;

static void safe_copy_key(char dest[KEY_LEN], const char *src) {
    strncpy(dest, src, KEY_LEN - 1);
    dest[KEY_LEN - 1] = '\0';
}

static int load_key_file_binary(const char *filename, VotingKey keys[], int max_keys) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror(filename);
        return -1;
    }

    uint32_t count = 0;
    if (fread(&count, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        fprintf(stderr, "Failed to read key count from %s\n", filename);
        return -1;
    }

    if ((int)count > max_keys) {
        fclose(fp);
        fprintf(stderr, "Key count in %s exceeds MAX_KEYS\n", filename);
        return -1;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (fread(keys[i].key, sizeof(char), KEY_LEN, fp) != KEY_LEN) {
            fclose(fp);
            fprintf(stderr, "Failed to read key record %u from %s\n", i, filename);
            return -1;
        }
        keys[i].key[KEY_LEN - 1] = '\0';
    }

    fclose(fp);
    return (int)count;
}

int load_valid_keys_binary(const char *filename) {
    int count = load_key_file_binary(filename, valid_keys, MAX_KEYS);
    if (count >= 0) {
        valid_key_count = count;
    }
    return count;
}

int load_ballot_binary(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror(filename);
        return -1;
    }

    uint32_t count = 0;
    if (fread(&count, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        fprintf(stderr, "Failed to read ballot count from %s\n", filename);
        return -1;
    }

    if ((int)count > MAX_BALLOT_OPTIONS) {
        fclose(fp);
        fprintf(stderr, "Ballot count in %s exceeds MAX_BALLOT_OPTIONS\n", filename);
        return -1;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (fread(&ballot_options[i].id, sizeof(uint32_t), 1, fp) != 1) {
            fclose(fp);
            fprintf(stderr, "Failed to read ballot id %u from %s\n", i, filename);
            return -1;
        }

        if (fread(ballot_options[i].text, sizeof(char), OPTION_TEXT_LEN, fp) != OPTION_TEXT_LEN) {
            fclose(fp);
            fprintf(stderr, "Failed to read ballot text %u from %s\n", i, filename);
            return -1;
        }

        ballot_options[i].text[OPTION_TEXT_LEN - 1] = '\0';
    }

    fclose(fp);
    ballot_option_count = (int)count;
    return ballot_option_count;
}

void init_used_keys(void) {
    used_key_count = 0;
    memset(used_keys, 0, sizeof(used_keys));
}

int append_used_key(const char *key) {
    if (used_key_count >= MAX_KEYS) {
        fprintf(stderr, "used_keys array full\n");
        return -1;
    }

    safe_copy_key(used_keys[used_key_count].key, key);
    used_key_count++;
    return 0;
}

int is_valid_key(const char *submitted_key) {
    for (int i = 0; i < valid_key_count; i++) {
        if (strcmp(valid_keys[i].key, submitted_key) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_used_key(const char *submitted_key) {
    for (int i = 0; i < used_key_count; i++) {
        if (strcmp(used_keys[i].key, submitted_key) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_valid_ballot_choice(uint32_t choice_id) {
    for (int i = 0; i < ballot_option_count; i++) {
        if (ballot_options[i].id == choice_id) {
            return 1;
        }
    }
    return 0;
}

int build_ballot_text(char *buffer, int buffer_size) {
    if (!buffer || buffer_size <= 0) {
        return -1;
    }

    int written = 0;
    int n = snprintf(buffer + written, buffer_size - written, "Ballot:\n");
    if (n < 0 || n >= buffer_size - written) {
        return -1;
    }
    written += n;

    for (int i = 0; i < ballot_option_count; i++) {
        n = snprintf(
            buffer + written,
            buffer_size - written,
            "%u. %s\n",
            ballot_options[i].id,
            ballot_options[i].text
        );

        if (n < 0 || n >= buffer_size - written) {
            return -1;
        }

        written += n;
    }

    return written;
}

void print_valid_keys(void) {
    printf("Valid keys (%d):\n", valid_key_count);
    for (int i = 0; i < valid_key_count; i++) {
        printf("  %s\n", valid_keys[i].key);
    }
}

void print_used_keys(void) {
    printf("Used keys (%d):\n", used_key_count);
    for (int i = 0; i < used_key_count; i++) {
        printf("  %s\n", used_keys[i].key);
    }
}

void print_ballot(void) {
    printf("Ballot options (%d):\n", ballot_option_count);
    for (int i = 0; i < ballot_option_count; i++) {
        printf("  %u -> %s\n", ballot_options[i].id, ballot_options[i].text);
    }
}

uint32_t next_receipt_id(void) {
    return current_receipt_id++;
}

int append_receipt(const StoredReceipt *r) {
    FILE *fp = fopen("receipts.bin", "ab");
    if (!fp) return -1;

    size_t written = fwrite(r, sizeof(StoredReceipt), 1, fp);
    fclose(fp);

    return (written == 1) ? 0 : -1;
}