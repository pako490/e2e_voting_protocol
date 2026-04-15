#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//THIS FILE IS FOR GENERATING THE LIST OF VALID KEYS VOTERS CAN USE

#define KEY_LENGTH 8
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define MAX_KEYS 10000

void generate_key(char *buffer, size_t length) {
    size_t charset_size = strlen(CHARSET);

    for (size_t i = 0; i < length; i++) {
        buffer[i] = CHARSET[rand() % charset_size];
    }

    buffer[length] = '\0';
}

int key_exists(char keys[][KEY_LENGTH + 1], int count, const char *candidate) {
    for (int i = 0; i < count; i++) {
        if (strcmp(keys[i], candidate) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_keys> <output_file>\n", argv[0]);
        return 1;
    }

    int num_keys = atoi(argv[1]);
    const char *output_file = argv[2];

    if (num_keys <= 0 || num_keys > MAX_KEYS) {
        fprintf(stderr, "Number of keys must be between 1 and %d\n", MAX_KEYS);
        return 1;
    }

    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    srand((unsigned int)time(NULL));

    char keys[MAX_KEYS][KEY_LENGTH + 1];
    int count = 0;

    while (count < num_keys) {
        char candidate[KEY_LENGTH + 1];
        generate_key(candidate, KEY_LENGTH);

        if (!key_exists(keys, count, candidate)) {
            strcpy(keys[count], candidate);
            fprintf(fp, "%s\n", candidate);
            count++;
        }
    }

    fclose(fp);

    printf("Generated %d unique keys in %s\n", num_keys, output_file);
    return 0;
}