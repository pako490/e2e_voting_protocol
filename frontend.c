#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "comm.h"

static int read_line(char *buf, size_t len) {
    if (fgets(buf, len, stdin) == NULL) {
        return -1;
    }
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;

    ClientMessage outgoing;
    ServerMessage incoming;
    uint32_t received_size = 0;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Connected to backend\n");

    /*
        STEP 1: LOGIN
        Send MSG_LOGIN with the voter key in text
    */
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_LOGIN;
    outgoing.status = STATUS_NONE;
    outgoing.choice_id = 0;

    printf("Enter voter key: ");
    if (read_line(outgoing.text, sizeof(outgoing.text)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to read voter key\n");
        close(sock_fd);
        return 1;
    }

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send login message\n");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Login sent\n");

    /*
        STEP 2: RECEIVE BALLOT DATA OR ERROR
    */
    memset(&incoming, 0, sizeof(incoming));
    received_size = 0;

    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to receive login response\n");
        close(sock_fd);
        return 1;
    }

    if (received_size != sizeof(incoming)) {
        fprintf(stderr, "[FRONTEND] Unexpected response size: %u bytes\n", received_size);
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_ERROR || incoming.status == STATUS_NO) {
        printf("[FRONTEND] Login failed: %s\n", incoming.text);
        close(sock_fd);
        return 1;
    }

    if (incoming.type != MSG_BALLOT_DATA) {
        fprintf(stderr, "[FRONTEND] Expected MSG_BALLOT_DATA, got type=%u\n", incoming.type);
        close(sock_fd);
        return 1;
    }

    printf("\n[FRONTEND] Ballot received:\n%s\n", incoming.text);

    /*
        STEP 3: SEND VOTE
        Send MSG_VOTE with choice_id filled in
    */
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_VOTE;
    outgoing.status = STATUS_NONE;
    outgoing.choice_id = 0;
    outgoing.text[0] = '\0';

    printf("Enter your ballot choice ID: ");
    if (scanf("%u", &outgoing.choice_id) != 1) {
        fprintf(stderr, "[FRONTEND] Invalid ballot choice input\n");
        close(sock_fd);
        return 1;
    }

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send vote\n");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Vote sent\n");

    /*
        STEP 4: RECEIVE RECEIPT OR ERROR
    */
    memset(&incoming, 0, sizeof(incoming));
    received_size = 0;

    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to receive vote response\n");
        close(sock_fd);
        return 1;
    }

    if (received_size != sizeof(incoming)) {
        fprintf(stderr, "[FRONTEND] Unexpected receipt size: %u bytes\n", received_size);
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_ERROR || incoming.status == STATUS_NO) {
        printf("[FRONTEND] Vote failed: %s\n", incoming.text);
        close(sock_fd);
        return 1;
    }

    if (incoming.type != MSG_RECEIPT) {
        fprintf(stderr, "[FRONTEND] Expected MSG_RECEIPT, got type=%u\n", incoming.type);
        close(sock_fd);
        return 1;
    }

    printf("\n[FRONTEND] Receipt received\n");
    printf("Receipt ID: %u\n", incoming.receipt_id);
    printf("Message: %s\n", incoming.text);

    close(sock_fd);
    return 0;
}