#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/bn.h>

#include "protocol.h"
#include "comm.h"
#include "rsa_openssl.h"  //saving the best for last
#include "codecard.h"

// Helpers 
static int read_line(char *buf, size_t len) {
    if (fgets(buf, len, stdin) == NULL) {
        return -1;
    }

    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

static void u64_to_bytes(uint64_t val, uint8_t *out, size_t *len) {
    *len = 8;
    for (int i = 0; i < 8; i++) {
        out[7 - i] = (val >> (i * 8)) & 0xFF;
    }
}

static uint64_t bytes_to_u64(const uint8_t *in, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | in[i];
    }
    return val;
}

int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;

    ClientMessage outgoing;
    ServerMessage incoming;
    uint32_t received_size = 0;

    uint32_t voter_id = 0;
    uint32_t choice_id = 0;

    // RSA stuff
    uint8_t encrypted_vote[RSA_MAX_BYTES];
    size_t encrypted_vote_len;

    uint8_t decrypted_challenge[RSA_MAX_BYTES];
    size_t decrypted_challenge_len;

    uint8_t decrypted_receipt[RSA_MAX_BYTES];
    size_t decrypted_receipt_len;

    uint64_t challenge_value = 0;
    uint64_t receipt_value = 0;

    // uint64_t auth_private_d = 0;
    // uint64_t decrypted_challenge = 0;
    
    // uint64_t encrypted_vote = 0;
    // uint64_t decrypted_receipt_value = 0;
    char receipt_text[128];

    // Private key (in bytes)
    uint8_t private_key_d[RSA_MAX_BYTES];
    size_t private_key_len;

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

    printf("Enter voter ID: ");
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

    // memset(&incoming, 0, sizeof(incoming));
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

    if (incoming.type != MSG_CHALLENGE) {
        fprintf(stderr, "[FRONTEND] Expected challenge, got type=%u\n", incoming.type);
        close(sock_fd);
        return 1;
    }

    printf("Enter your private key for voter %u: ", voter_id);
    if (scanf("%llu", (unsigned long long *)&auth_private_d) != 1) {
        fprintf(stderr, "Invalid private key\n");
        close(sock_fd);
        return 1;
    }

    // decrypted_challenge =
    //     rsa_decrypt_uint64(incoming.value, auth_private_d, incoming.modulus_n);
    
    rsa_decrypt_bytes(
    incoming.value, incoming.value_len,
    priv.n_bytes, priv.n_len,
    priv.d_bytes, priv.d_len,
    decrypted_challenge, &decrypted_challenge_len
    );

    // Convert bytes → uint64
    challenge_value = bytes_to_u64(decrypted_challenge, decrypted_challenge_len);

    // Check auth
    printf("[FRONTEND] Decrypted challenge: %llu\n",
        (unsigned long long)challenge_value);

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_CHALLENGE_RESPONSE;
    outgoing.status = STATUS_NONE;
    outgoing.voter_id = voter_id;
    outgoing.key_id = incoming.key_id;
    // outgoing.value = decrypted_challenge;

    uint8_t response_bytes[8];
    size_t response_len;

    u64_to_bytes(challenge_value, response_bytes, &response_len);
    outgoing.value_len = response_len;

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

    // encrypted_vote =
    //     rsa_encrypt_uint64((uint64_t)choice_id, incoming.exponent_e, incoming.modulus_n);

    uint8_t vote_bytes[8];
    size_t vote_len;

    u64_to_bytes((uint64_t)choice_id, vote_bytes, &vote_len);

    rsa_encrypt_bytes(
        vote_bytes, vote_len,
        incoming.modulus_n, incoming.n_len,
        incoming.exponent_e, incoming.e_len,
        encrypted_vote, &encrypted_vote_len
    );

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_VOTE;
    outgoing.status = STATUS_NONE;
    outgoing.voter_id = voter_id;
    outgoing.key_id = incoming.key_id;

    outgoing.choice_id = 0;

    memcpy(outgoing.value, encrypted_vote, encrypted_vote_len);
    outgoing.value_len = encrypted_vote_len;    

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

    // decrypted_receipt_value =
    //     rsa_decrypt_uint64(incoming.value, auth_private_d, incoming.modulus_n);

    rsa_decrypt_bytes(
    incoming.value, incoming.value_len,
    priv.n_bytes, priv.n_len,
    priv.d_bytes, priv.d_len,
    decrypted_receipt, &decrypted_receipt_len
    );

    receipt_value = bytes_to_u64(decrypted_receipt, decrypted_receipt_len);

    codecard_text_for_value(receipt_value, receipt_text, sizeof(receipt_text));

    printf("\n[FRONTEND] Receipt ID: %u\n", incoming.receipt_id);
    printf("[FRONTEND] Receipt code value: %llu\n",
           (unsigned long long)receipt_value);
    printf("[FRONTEND] Code card result: %s\n", receipt_text);

    close(sock_fd);
    return 0;
}