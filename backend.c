#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "comm.h"
#include "storage.h"
#include "keyloader.h"
#include "rsa_openssl.h" //saving the best for last
#include "codecard.h"

#define RSA_MAX_BYTES 256
// RSA Helpers
// uint64 → big-endian bytes
static void u64_to_bytes(uint64_t val, uint8_t *out, size_t *len) {
    *len = 8;
    for (int i = 0; i < 8; i++) {
        out[7 - i] = (val >> (i * 8)) & 0xFF;
    }
}

// big-endian bytes → uint64
static uint64_t bytes_to_u64(const uint8_t *in, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | in[i];
    }
    return val;
}

typedef enum {
    STATE_HELLO,
    STATE_AUTH,
    STATE_BALLOT,
    STATE_DONE
} SessionState;

typedef struct {
    SessionState state;
    uint32_t voter_id;
    uint32_t auth_key_id;
    uint64_t auth_challenge;
    uint32_t selected_choice;
    uint32_t receipt_id;
} ClientSession;

static PublicKeyList voter_public_keys;
static PrivateKeyList ballot_private_keys;

static uint32_t next_receipt_id(void) {
    static uint32_t id = 1000;
    return id++;
}

static void set_error(ServerMessage *outgoing, const char *message) {
    memset(outgoing, 0, sizeof(*outgoing));
    outgoing->type = MSG_ERROR;
    outgoing->status = STATUS_NO;
    snprintf(outgoing->payload, sizeof(outgoing->payload), "%s", message);
}

static const RSAPrivateKey *get_ballot_private_key(void) {
    if (ballot_private_keys.count == 0) {
        return NULL;
    }

    return &ballot_private_keys.keys[0];
}

static void voter_id_to_key_string(uint32_t voter_id, char *out, size_t out_len) {
    snprintf(out, out_len, "%u", voter_id);
}

static void process_message(ClientSession *session,
                            const ClientMessage *incoming,
                            ServerMessage *outgoing) {
    const RSAPublicKey *auth_pub;
    const RSAPrivateKey *ballot_priv;
    uint64_t decrypted_vote;
    uint64_t receipt_code_value;
    uint64_t encrypted_receipt_value;

    memset(outgoing, 0, sizeof(*outgoing));

    switch (session->state) {
        case STATE_HELLO:
            if (incoming->type != MSG_HELLO) {
                set_error(outgoing, "Expected hello message.");
                return;
            }

            session->voter_id = incoming->voter_id;
            session->auth_key_id = incoming->voter_id;

            auth_pub = find_public_key(&voter_public_keys, session->auth_key_id);
            if (auth_pub == NULL) {
                set_error(outgoing, "Unknown voter ID.");
                return;
            }

            char used_key_buf_auth[32];
            voter_id_to_key_string(session->voter_id, used_key_buf_auth, sizeof(used_key_buf_auth));

            if (is_used_key(used_key_buf_auth)) {
                set_error(outgoing, "Voter has already voted.");
                session->state = STATE_DONE;
                return;
            }
        

            session->auth_challenge =
                (uint64_t)(rand() % 10000 + 1000);

            outgoing->type = MSG_CHALLENGE;
            outgoing->status = STATUS_YES;
            outgoing->key_id = auth_pub->key_id;

            // BIGNUM *m = BN_new();
            // BIGNUM *c = BN_new();
            // BN_set_word(m, session->auth_challenge);

            // c = rsa_encrypt_bn(m, auth_pub, rsa_ctx);

            // outgoing->value = BN_get_word(c);
            // outgoing->modulus_n = auth_pub->n;

            uint8_t plaintext[8];
            size_t plaintext_len;

            uint8_t ciphertext[RSA_MAX_BYTES];
            size_t ciphertext_len;

            // Convert challenge to bytes
            u64_to_bytes(session->auth_challenge, plaintext, &plaintext_len);

            // Encryption
            rsa_encrypt_bytes(
                plaintext, plaintext_len,
                auth_pub->n_bytes, auth_pub->n_len,
                auth_pub->e_bytes, auth_pub->e_len,
                ciphertext, &ciphertext_len
            );

            // Store in message
            memcpy(outgoing->valu, ciphertext, ciphertext_len);
            outgoing->value_len = ciphertext_len;

            // Copy Public key
            memcpy(outgoing->modulus_n, auth_pub->n_bytes, auth_pub->n_len);
            outgoing->n_len = auth_pub->n_len;

            memcpy(outgoing->exponent_e, auth_pub->e_bytes, auth_pub->e_len);
            outgoing->e_len = auth_pub->e_len;

            snprintf(outgoing->payload, sizeof(outgoing->payload),
                     "Decrypt the challenge with your private key.");

            session->state = STATE_AUTH;
            return;

        case STATE_AUTH:

            if (incoming->type != MSG_CHALLENGE_RESPONSE) {
                set_error(outgoing, "Expected challenge response.");
                return;
            }

            uint64_t response = bytes_to_u64(incoming->value, incoming->value_len);
        
            if (response->value != session->auth_challenge) {
                set_error(outgoing, "Authentication failed.");
                session->state = STATE_DONE;
                return;
            }

            ballot_priv = get_ballot_private_key();
            if (ballot_priv == NULL) {
                set_error(outgoing, "No ballot key loaded.");
                session->state = STATE_DONE;
                return;
            }

            if (build_ballot_text(outgoing->payload, sizeof(outgoing->payload)) < 0) {
                set_error(outgoing, "Failed to build ballot.");
                session->state = STATE_DONE;
                return;
            }

            outgoing->type = MSG_BALLOT_DATA;
            outgoing->status = STATUS_YES;
            outgoing->key_id = ballot_priv->key_id;
            // outgoing->modulus_n = ballot_priv->n;

            /*
                In this demo, we reuse key_id 1 in the private list and derive the
                public exponent from your generated data convention.
                For the cleanest setup, also load a ballot public key list and use e from there.
            */
            // outgoing->exponent_e = 65537;

            memcpy(outgoing->modulus_n, ballot_priv->n_bytes, ballot_priv->n_len);
            outgoing->n_len = ballot_priv->n_len;

            memcpy(outgoing->exponent_e, ballot_priv->e_bytes, ballot_priv->e_len);
            outgoing->e_len = ballot_priv->e_len;

            session->state = STATE_BALLOT;
            return;

        case STATE_BALLOT:
            if (incoming->type != MSG_VOTE) {
                set_error(outgoing, "Expected vote message.");
                return;
            }

            ballot_priv = get_ballot_private_key();
            if (ballot_priv == NULL) {
                set_error(outgoing, "No ballot private key available.");
                session->state = STATE_DONE;
                return;
            }

            // decrypted_vote =
            //     rsa_decrypt_uint64(incoming->value, ballot_priv->d, ballot_priv->n);

            uint8_t decrypted[RSA_MAX_BYTES];
            size_t decrypted_len;

            rsa_decrypted_bytes(
                incoming->value, incoming->value_len,
                ballet_priv->n_bytes, ballot_priv->n_len,
                ballot_priv->d_bytes, ballot_priv->d_len,
                decrypted, &decrypted_len
            );

            uint64_t decrypted_vote = bytes_to_u64(decrypted, decrypted_len);

            if (!is_valid_ballot_choice((uint32_t)decrypted_vote)) {
                set_error(outgoing, "Invalid decrypted vote.");
                session->state = STATE_DONE;
                return;
            }

            session->selected_choice = (uint32_t)decrypted_vote;
            session->receipt_id = next_receipt_id();

            char used_key_buf_ballot[32];
            voter_id_to_key_string(session->voter_id, used_key_buf_ballot, sizeof(used_key_buf_ballot));

            if (append_used_key(used_key_buf_ballot) < 0) {
                set_error(outgoing, "Failed to record used voter.");
                session->state = STATE_DONE;
                return;
            }

            if (codecard_value_for_choice(session->selected_choice, &receipt_code_value) < 0) {
                set_error(outgoing, "Failed to create code card value.");
                session->state = STATE_DONE;
                return;
            }

            auth_pub = find_public_key(&voter_public_keys, session->auth_key_id);
            if (auth_pub == NULL) {
                set_error(outgoing, "Auth public key missing for receipt.");
                session->state = STATE_DONE;
                return;
            }

            // encrypted_receipt_value =
            //     rsa_encrypt_uint64(receipt_code_value, auth_pub->e, auth_pub->n);

            uint8_t receipt_bytes[8];
            size_t receipt_len;

            uint8_t encrypted[RSA_MAX_BYTES];
            size_t encrypted_len;

            // Convert receipt → bytes
            u64_to_bytes(receipt_code_value, receipt_bytes, &receipt_len);

            // Encrypt
            rsa_encrypt_bytes(
                receipt_bytes, receipt_len,
                auth_pub->n_bytes, auth_pub->n_len,
                auth_pub->e_bytes, auth_pub->e_len,
                encrypted, &encrypted_len
            );

            // Store
            memcpy(outgoing->value, encrypted, encrypted_len);
            outgoing->value_len = encrypted_len;

            memcpy(outgoing->modulus_n, auth_pub->n_bytes, auth_pub->n_len);
            outgoing->n_len = auth_pub->n_len;

            memcpy(outgoing->exponent_e, auth_pub->e_bytes, auth_pub->e_len);
            outgoing->e_len = auth_pub->e_len;

            outgoing->type = MSG_RECEIPT;
            outgoing->status = STATUS_YES;
            outgoing->key_id = auth_pub->key_id;
            outgoing->receipt_id = session->receipt_id;
            outgoing->choice_id = session->selected_choice;
            outgoing->value = encrypted_receipt_value;
            outgoing->modulus_n = auth_pub->n;
            snprintf(outgoing->payload, sizeof(outgoing->payload),
                     "Decrypt the receipt value and check your code card.");

            session->state = STATE_DONE;
            return;

        case STATE_DONE:
        default:
            set_error(outgoing, "Session finished.");
            return;
    }
}

static void handle_client(int client_fd) {
    ClientSession session;
    ClientMessage incoming;
    ServerMessage outgoing;
    uint32_t received_size = 0;

    memset(&session, 0, sizeof(session));
    session.state = STATE_HELLO;

    while (session.state != STATE_DONE) {
        memset(&incoming, 0, sizeof(incoming));
        memset(&outgoing, 0, sizeof(outgoing));
        received_size = 0;

        if (recv_message(client_fd, &incoming, sizeof(incoming), &received_size) < 0) {
            perror("recv_message");
            break;
        }

        if (received_size != sizeof(incoming)) {
            fprintf(stderr, "[BACKEND] Unexpected message size: %u\n", received_size);
            break;
        }

        process_message(&session, &incoming, &outgoing);

        if (send_message(client_fd, &outgoing, sizeof(outgoing)) < 0) {
            perror("send_message");
            break;
        }

        if (outgoing.type == MSG_ERROR) {
            break;
        }
    }

    close(client_fd);
}

int main(void) {
    int server_fd;
    int client_fd;
    int opt = 1;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    srand((unsigned int)time(NULL));

    //--------------LOADS DATA -------------------//

    if (load_valid_keys_binary("public_auth_keys.bin") < 0) {
        fprintf(stderr, "[BACKEND] Failed to load valid voter keys\n");
        return 1;
    }

    if (load_ballot_binary("ballot.bin") < 0) {
        fprintf(stderr, "[BACKEND] Failed to load ballot\n");
        return 1;
    }

    if (load_public_key_list_bin("public_ballot_keys.bin", &voter_public_keys) < 0) {
        fprintf(stderr, "[BACKEND] Failed to load public key list\n");
        return 1;
    }

    if (load_private_key_list_bin("ballot_priv_keys.bin", &ballot_private_keys) < 0) {
        fprintf(stderr, "[BACKEND] Failed to load ballot private key list\n");
        return 1;
    }


    init_used_keys();


    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[BACKEND] Listening on %s:%d\n", SERVER_ADDR, SERVER_PORT);

    while (1) {
        client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        handle_client(client_fd);
    }

    close(server_fd);

    return 0;
}