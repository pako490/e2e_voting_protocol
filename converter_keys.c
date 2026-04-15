#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define KEY_LEN 32
#define MAX_KEYS 1000

int main() {
    FILE *in = fopen("valid_keys.txt", "r");
    FILE *out = fopen("valid_keys.bin", "wb");

    if (!in || !out) {
        perror("file");
        return 1;
    }

    char keys[MAX_KEYS][KEY_LEN];
    int count = 0;
    char line[KEY_LEN];

    while (fgets(line, sizeof(line), in) && count < MAX_KEYS) {
        line[strcspn(line, "\r\n")] = '\0';

        if (strlen(line) == 0) continue;

        strncpy(keys[count], line, KEY_LEN - 1);
        keys[count][KEY_LEN - 1] = '\0';
        count++;
    }

    uint32_t file_count = count;
    fwrite(&file_count, sizeof(uint32_t), 1, out);

    for (int i = 0; i < count; i++) {
        fwrite(keys[i], sizeof(char), KEY_LEN, out);
    }

    fclose(in);
    fclose(out);

    printf("Converted %d keys\n", count);
    return 0;
}