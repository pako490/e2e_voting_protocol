#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "comm.h"
#include "rsa.h"  //saving the best for last
#include "codecard.h"

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

    uint32_t voter_id = 0;
    uint64_t auth_private_d = 0;
    uint64_t decrypted_challenge = 0;
    uint32_t choice_id = 0;
    uint64_t encrypted_vote = 0;
    uint64_t decrypted_receipt_value = 0;
    char receipt_text[128];

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("[FRONTEND] socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[FRONTEND] connect");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Connected to backend\n");

    printf("Enter voter ID (0 for Vote Tally): ");
    if (scanf("%u", &voter_id) != 1) {
        fprintf(stderr, "Invalid voter ID\n");
        close(sock_fd);
        return 1;
    }

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_HELLO;
    outgoing.status = STATUS_NONE;
    outgoing.voter_id = voter_id;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send hello\n");
        close(sock_fd);
        return 1;
    }

    memset(&incoming, 0, sizeof(incoming));
    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to receive challenge\n");
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_ERROR) {
        printf("[FRONTEND] Error: %s\n", incoming.payload);
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_STATUS) {
        //call tally
        printf("\n[FRONTEND] Vote Tally: \n%s\n", incoming.payload);
        close(sock_fd);
        return 0;
    } 

    if (incoming.type == MSG_RECEIPT && incoming.status == STATUS_NO) {
        printf("[FRONTEND] You have already voted.\n");
        printf("%s\n", incoming.payload);
        return 0;
    }

    if (incoming.type != MSG_CHALLENGE) {
        printf("[FRONTEND] Expected challenge, got type=%d\n", incoming.type);
        return 1;
    }

    printf("Enter your private key for voter %u: ", voter_id);
    if (scanf("%llu", (unsigned long long *)&auth_private_d) != 1) {
        fprintf(stderr, "Invalid private key\n");
        close(sock_fd);
        return 1;
    }

    decrypted_challenge =
        rsa_decrypt_uint64(incoming.value, auth_private_d, incoming.modulus_n);
    
    
    //checking authentication
    printf("%llu", decrypted_challenge);

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_CHALLENGE_RESPONSE;
    outgoing.status = STATUS_NONE;
    outgoing.voter_id = voter_id;
    outgoing.key_id = incoming.key_id;
    outgoing.value = decrypted_challenge;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send challenge response\n");
        close(sock_fd);
        return 1;
    }

    memset(&incoming, 0, sizeof(incoming));
    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to receive ballot\n");
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_ERROR) {
        printf("[FRONTEND] Error: %s\n", incoming.payload);
        close(sock_fd);
        return 1;
    }

    if (incoming.type != MSG_BALLOT_DATA) {
        fprintf(stderr, "[FRONTEND] Expected ballot data, got type=%u\n", incoming.type);
        close(sock_fd);
        return 1;
    }

    printf("\n[FRONTEND] Ballot:\n%s\n", incoming.payload);

    printf("Enter your choice ID: ");
    if (scanf("%u", &choice_id) != 1) {
        fprintf(stderr, "Invalid choice ID\n");
        close(sock_fd);
        return 1;
    }

    encrypted_vote =
        rsa_encrypt_uint64((uint64_t)choice_id, incoming.exponent_e, incoming.modulus_n);

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_VOTE;
    outgoing.status = STATUS_NONE;
    outgoing.voter_id = voter_id;
    outgoing.key_id = incoming.key_id;
    outgoing.choice_id = choice_id;
    outgoing.value = encrypted_vote;
    outgoing.modulus_n = incoming.modulus_n;
    outgoing.exponent_e = incoming.exponent_e;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send vote\n");
        close(sock_fd);
        return 1;
    }

    memset(&incoming, 0, sizeof(incoming));
    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to receive receipt\n");
        close(sock_fd);
        return 1;
    }

    if (incoming.type == MSG_ERROR) {
        printf("[FRONTEND] Error: %s\n", incoming.payload);
        close(sock_fd);
        return 1;
    }

    if (incoming.type != MSG_RECEIPT) {
        fprintf(stderr, "[FRONTEND] Expected receipt, got type=%u\n", incoming.type);
        close(sock_fd);
        return 1;
    }

    printf("\n[FRONTEND] Receipt:\n%s\n", incoming.payload);

    close(sock_fd);
    return 0;
}