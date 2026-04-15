#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define OPTION_TEXT_LEN 100
#define MAX_OPTIONS 50

typedef struct {
    uint32_t id;
    char text[OPTION_TEXT_LEN];
} BallotOption;

int main() {
    FILE *in = fopen("ballot.txt", "r");
    FILE *out = fopen("ballot.bin", "wb");

    if (!in || !out) {
        perror("file");
        return 1;
    }

    BallotOption options[MAX_OPTIONS];
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), in) && count < MAX_OPTIONS) {
        line[strcspn(line, "\r\n")] = '\0';

        char *comma = strchr(line, ',');
        if (!comma) continue;

        *comma = '\0';

        options[count].id = atoi(line);
        strncpy(options[count].text, comma + 1, OPTION_TEXT_LEN - 1);
        options[count].text[OPTION_TEXT_LEN - 1] = '\0';

        count++;
    }

    uint32_t file_count = count;
    fwrite(&file_count, sizeof(uint32_t), 1, out);

    for (int i = 0; i < count; i++) {
        fwrite(&options[i], sizeof(BallotOption), 1, out);
    }

    fclose(in);
    fclose(out);

    printf("Converted %d ballot options\n", count);
    return 0;
}