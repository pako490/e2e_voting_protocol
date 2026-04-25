#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "comm.h"
#include "rsa_openssl.h"
#include "codecard.h"

// Helpers
static void u64_to_bytes(uint64_t val, uint8_t *out, size_t *len) {
    *len = 8;
    for (int i = 0; i < 8; i++)
        out[7 - i] = (val >> (i * 8)) & 0xFF;
}

static uint64_t bytes_to_u64(const uint8_t *in, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++)
        val = (val << 8) | in[i];
    return val;
}

/*
 * Read a hex string from stdin and convert it to a big-endian byte array
 * via OpenSSL BIGNUM so the width is correct.
 * Returns the number of bytes written, or -1 on error.
 */
static int read_hex_key(const char *prompt,
                        uint8_t *out_bytes, size_t *out_len,
                        size_t max_len) {
    char hex_buf[1024];
    printf("%s", prompt);
    if (scanf("%1023s", hex_buf) != 1) {
        fprintf(stderr, "Failed to read key\n");
        return -1;
    }

    BIGNUM *bn = NULL;
    if (BN_hex2bn(&bn, hex_buf) == 0 || bn == NULL) {
        fprintf(stderr, "Invalid hex key\n");
        return -1;
    }

    int len = BN_num_bytes(bn);
    if ((size_t)len > max_len) {
        fprintf(stderr, "Key too large for buffer\n");
        BN_free(bn);
        return -1;
    }

    // BN_bn2bin gives big-endian bytes
    BN_bn2bin(bn, out_bytes);
    *out_len = (size_t)len;
    BN_free(bn);
    return 0;
}

// Main()
int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;

    ClientMessage outgoing;
    ServerMessage incoming;
    uint32_t received_size = 0;

    uint32_t voter_id  = 0;
    uint32_t choice_id = 0;

    // Auth private key supplied by the voter
    uint8_t auth_d_bytes[RSA_MAX_BYTES];
    size_t  auth_d_len = 0;

    uint8_t auth_n_bytes[RSA_MAX_BYTES];
    size_t  auth_n_len = 0;

    uint8_t decrypted_challenge[RSA_MAX_BYTES];
    size_t  decrypted_challenge_len = 0;

    uint8_t encrypted_vote[RSA_MAX_BYTES];
    size_t  encrypted_vote_len = 0;

    uint8_t decrypted_receipt[RSA_MAX_BYTES];
    size_t  decrypted_receipt_len = 0;

    uint64_t challenge_value = 0;
    uint64_t receipt_value   = 0;

    char receipt_text[128];

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("[FRONTEND] socket"); return 1; }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sock_fd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("[FRONTEND] connect");
        close(sock_fd);
        return 1;
    }
    printf("[FRONTEND] Connected to backend\n");

    printf("Enter voter ID (0 = Vote Tally, 9999 = Bulletin/Lookup): ");
    if (scanf("%u", &voter_id) != 1) {
        fprintf(stderr, "Invalid voter ID\n");
        close(sock_fd);
        return 1;
    }

    if (voter_id == 9999) {
        uint64_t encrypted_vote = 0;

        printf("Enter encrypted vote to lookup (0 = show full bulletin): ");
        scanf("%llu", (unsigned long long*)&encrypted_vote);

        memset(&outgoing, 0, sizeof(outgoing));
        outgoing.type = MSG_HELLO;
        outgoing.status = STATUS_NONE;
        outgoing.voter_id = 9999;
        outgoing.value = encrypted_vote;

        send_message(sock_fd, &outgoing, sizeof(outgoing));
        recv_message(sock_fd, &incoming, sizeof(incoming), &received_size);

        printf("\n[FRONTEND] Bulletin Board:\n%s\n", incoming.payload);

        close(sock_fd);
        return 0;
    }

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type     = MSG_HELLO;
    outgoing.status   = STATUS_NONE;
    outgoing.voter_id = voter_id;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send hello\n");
        close(sock_fd);
        return 1;
    }

    // Send challenge
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

    auth_n_len = incoming.n_len;
    memcpy(auth_n_bytes, incoming.modulus_n, auth_n_len);

    // Read private key d as hex, convert to big-endian bytes via BN
    if (read_hex_key("Enter your private key d (hex) for voter: ",
                     auth_d_bytes, &auth_d_len, sizeof(auth_d_bytes)) < 0) {
        close(sock_fd);
        return 1;
    }

    // Decrypt the challenge: m = c^d mod n
    rsa_decrypt_bytes(
        incoming.value,   incoming.value_len,
        auth_n_bytes,     auth_n_len,          /* n from server  */
        auth_d_bytes,     auth_d_len,           /* d from voter   */
        decrypted_challenge, &decrypted_challenge_len
    );

    challenge_value = bytes_to_u64(decrypted_challenge, decrypted_challenge_len);
    printf("[FRONTEND] Decrypted challenge: %llu\n",
           (unsigned long long)challenge_value);

    // Send challenge resp.
    uint8_t response_bytes[8];
    size_t  response_len = 0;
    u64_to_bytes(challenge_value, response_bytes, &response_len);

    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type       = MSG_CHALLENGE_RESPONSE;
    outgoing.status     = STATUS_NONE;
    outgoing.voter_id   = voter_id;
    outgoing.key_id     = incoming.key_id;
    
    // Copy the response bytes into the message
    memcpy(outgoing.value, response_bytes, response_len);
    outgoing.value_len  = response_len;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send challenge response\n");
        close(sock_fd);
        return 1;
    }

    // Ballot data
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

    // Encrypt the vote: c = m^e mod n  (ballot public key from server)
    uint8_t vote_bytes[8];
    size_t  vote_len = 0;
    u64_to_bytes((uint64_t)choice_id, vote_bytes, &vote_len);

    rsa_encrypt_bytes(
        vote_bytes,        vote_len,
        incoming.modulus_n, incoming.n_len,   /* ballot n from server */
        incoming.exponent_e, incoming.e_len,  /* ballot e from server */
        encrypted_vote,   &encrypted_vote_len
    );

    // Vote
        printf("[DEBUG] Encrypted vote: %llu\n", (unsigned long long)encrypted_vote);
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type      = MSG_VOTE;
    outgoing.status    = STATUS_NONE;
    outgoing.voter_id  = voter_id;
    outgoing.key_id    = incoming.key_id;
    outgoing.choice_id = 0;
    memcpy(outgoing.value, encrypted_vote, encrypted_vote_len);
    outgoing.value_len = encrypted_vote_len;

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send vote\n");
        close(sock_fd);
        return 1;
    }

    // Receive receipt
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

    // Decrypt the receipt with the voter's auth key
    rsa_decrypt_bytes(
        incoming.value,   incoming.value_len,
        auth_n_bytes,     auth_n_len,
        auth_d_bytes,     auth_d_len,
        decrypted_receipt, &decrypted_receipt_len
    );

    receipt_value = bytes_to_u64(decrypted_receipt, decrypted_receipt_len);
    codecard_text_for_value(receipt_value, receipt_text, sizeof(receipt_text));

    printf("\n[FRONTEND] Receipt ID:         %u\n",  incoming.receipt_id);
    printf("[FRONTEND] Receipt code value: %llu\n", (unsigned long long)receipt_value);
    printf("[FRONTEND] Code card result:   %s\n",   receipt_text);

    // printf("[FRONTEND] Receipt ID: %u\n", incoming.receipt_id);
    printf("[FRONTEND] %s\n", incoming.payload);
        
    close(sock_fd);
    return 0;
}