#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <inttypes.h>

#include "protocol.h"
#include "comm.h"
#include "storage.h"
#include "keyloader.h"
#include "rsa.h" //saving the best for last
#include "codecard.h"
#include "receipt.h"

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
    CodeCard code_card;
    VoteReceipt receipt;
} ClientSession;

typedef struct {
    uint64_t encrypted_vote;
    uint32_t candidate_id;
} BulletinEntry;

static PublicKeyList voter_public_keys;
static PrivateKeyList ballot_private_keys;
static int vote_tally[4] = {0, 0, 0, 0};
#define MAX_BULLETIN 1000
static BulletinEntry bulletin_board[MAX_BULLETIN];
static int bulletin_count = 0;

static void set_error(ServerMessage *outgoing, const char *message) {
    memset(outgoing, 0, sizeof(*outgoing));
    outgoing->type = MSG_ERROR;
    outgoing->status = STATUS_NO;
    snprintf(outgoing->payload, sizeof(outgoing->payload), "%s", message);
}

static int append_code_card_text(char *buffer, size_t buffer_size, const CodeCard *card) {
    size_t used = strlen(buffer);

    int n = snprintf(buffer + used, buffer_size - used,
                     "\nCode Card\n"
                     "1 -> %s\n"
                     "2 -> %s\n"
                     "3 -> %s\n"
                     "4 -> %s\n"
                     "Confirmation Code -> %s\n",
                     card->entries[0].vote_code,
                     card->entries[1].vote_code,
                     card->entries[2].vote_code,
                     card->entries[3].vote_code,
                     card->confirm_code);

    if (n < 0 || (size_t)n >= buffer_size - used) return -1;
    return 0;
}

static const RSAPrivateKey *get_ballot_private_key(void) {
    if (ballot_private_keys.count == 0) {
        return NULL;
    }

    return &ballot_private_keys.keys[0];
}

static void build_tally(char *buf, size_t len)
{
    snprintf(buf, len,
        "Candidate A: %d\nCandidate B: %d\nCandidate C: %d\nCandidate D: %d", vote_tally[0], vote_tally[1], vote_tally[2], vote_tally[3]);
}

static int bulletin_lookup(uint64_t encrypted_vote, char *buf, size_t len) {
    for (int i = 0; i < bulletin_count; i++) {
        if (bulletin_board[i].encrypted_vote == encrypted_vote) {
            snprintf(buf, len, "Encrypted Vote: %" PRIu64 "\nCandidate: %u", encrypted_vote, bulletin_board[i].candidate_id);
            return 0;
        }
    }

    snprintf(buf, len, "Vote not found on bulletin board.");
    return -1;
}

static void full_bulletin(char *buf, size_t len) {
    int offset = 0;

    if (bulletin_count == 0) {
        snprintf(buf + offset, len - offset, "No votes recorded.\n");
        return;
    }

    for (int i = 0; i < bulletin_count; i++) {
        int vote = snprintf(buf + offset, len - offset, "%" PRIu64 " -> Candidate %u\n", bulletin_board[i].encrypted_vote, bulletin_board[i].candidate_id);

        if (vote < 0 || vote >= (int)(len - offset)) {
            break;
        }
        offset += vote;
    }
}

static void voter_id_to_key_string(uint32_t voter_id, char *out, size_t out_len) {
    snprintf(out, out_len, "%u", voter_id);
}

static int format_receipt_text(char *buffer, size_t buffer_size,
                               uint32_t receipt_id,
                               const VoteReceipt *receipt) {
    int written = 0;

    int n = snprintf(buffer + written, buffer_size - written,
                     "Vote Receipt\nReceipt ID: %u\n",
                     receipt_id);
    if (n < 0 || (size_t)n >= buffer_size - written) return -1;
    written += n;

    for (int i = 0; i < NUM_CANDIDATES; i++) {
        n = snprintf(buffer + written, buffer_size - written,
                     "%u -> %s\n",
                     receipt->entries[i].candidate_id,
                     receipt->entries[i].verification_code);
        if (n < 0 || (size_t)n >= buffer_size - written) return -1;
        written += n;
    }

    return 0;
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
        case STATE_HELLO: {
            char used_key_buf_auth[32];
            StoredReceipt stored;

            printf("[BACKEND] Received voter_id: %u\n", incoming->voter_id);

            if (incoming->type != MSG_HELLO) {
                set_error(outgoing, "Expected hello message.");
                return;
            }

            session->voter_id = incoming->voter_id;
            session->auth_key_id = incoming->voter_id;

            // tally
            if (session->voter_id == 0) {
                char buf[256];
                build_tally(buf, sizeof(buf));

                outgoing->type = MSG_STATUS;
                outgoing->status = STATUS_YES;
                snprintf(outgoing->payload, sizeof(outgoing->payload), "%s", buf);

                session->state = STATE_DONE;
                return;
            }

            // bulletin board & lookup
            if (session->voter_id == 9999) {
                char buf[512];
                outgoing->type = MSG_STATUS;

                if (incoming->value == 0) {  // full bulletin
                    full_bulletin(buf, sizeof(buf));
                    outgoing->status = STATUS_YES;
                } else {  // lookup
                    if (bulletin_lookup(incoming->value, buf, sizeof(buf)) == 0) {
                        outgoing->status = STATUS_YES;
                    } else {
                        outgoing->status = STATUS_NO;
                    }
                }
                snprintf(outgoing->payload, sizeof(outgoing->payload), "%s", buf);

                session->state = STATE_DONE;
                return;
            }

            auth_pub = find_public_key(&voter_public_keys, session->auth_key_id);
            if (auth_pub == NULL) {
                set_error(outgoing, "Unknown voter ID.");
                return;
            }

            voter_id_to_key_string(session->voter_id,
                                   used_key_buf_auth,
                                   sizeof(used_key_buf_auth));

            if (is_used_key(used_key_buf_auth)) {
                if (find_receipt_by_voter_id(session->voter_id, &stored) == 0) {
                    if (format_receipt_text(outgoing->payload,
                                            sizeof(outgoing->payload),
                                            stored.receipt_id,
                                            &stored.receipt) < 0) {
                        set_error(outgoing, "Voter has already voted, but receipt formatting failed.");
                        session->state = STATE_DONE;
                        return;
                    }

                    outgoing->type = MSG_RECEIPT;
                    outgoing->status = STATUS_NO;
                } else {
                    set_error(outgoing, "Voter has already voted, but no receipt was found.");
                }

                session->state = STATE_DONE;
                return;
            }

            session->auth_challenge = (uint64_t)(rand() % 10000 + 1000);

            outgoing->type = MSG_CHALLENGE;
            outgoing->status = STATUS_YES;
            outgoing->key_id = auth_pub->key_id;
            outgoing->value =
                rsa_encrypt_uint64(session->auth_challenge, auth_pub->e, auth_pub->n);
            outgoing->modulus_n = auth_pub->n;
            snprintf(outgoing->payload, sizeof(outgoing->payload),
                     "Decrypt the challenge with your private key.");

            session->state = STATE_AUTH;
            return;
        }

        case STATE_AUTH:

            if (incoming->type != MSG_CHALLENGE_RESPONSE) {
                set_error(outgoing, "Expected challenge response.");
                return;
            }

            if (incoming->value != session->auth_challenge) {
                set_error(outgoing, "Authentication failed.");
                session->state = STATE_DONE;
                return;
            }

            init_code_card(&session->code_card);

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

            if (append_code_card_text(outgoing->payload, sizeof(outgoing->payload),
                                    &session->code_card) < 0) {
                set_error(outgoing, "Failed to append code card.");
                session->state = STATE_DONE;
                return;
            }

            outgoing->type = MSG_BALLOT_DATA;
            outgoing->status = STATUS_YES;
            outgoing->key_id = ballot_priv->key_id;
            outgoing->modulus_n = ballot_priv->n;

            /*
                In this demo, we reuse key_id 1 in the private list and derive the
                public exponent from your generated data convention.
                For the cleanest setup, also load a ballot public key list and use e from there.
            */
            outgoing->exponent_e = 65537;

            session->state = STATE_BALLOT;
            return;

        case STATE_BALLOT: {
            unsigned char ciphertext_buf[64];
            int cipher_len;
            char used_key_buf_ballot[32];
            StoredReceipt stored;

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

            decrypted_vote =
                rsa_decrypt_uint64(incoming->value, ballot_priv->d, ballot_priv->n);

            if (!is_valid_ballot_choice((uint32_t)decrypted_vote)) {
                set_error(outgoing, "Invalid decrypted vote.");
                session->state = STATE_DONE;
                return;
            }

            session->selected_choice = (uint32_t)decrypted_vote;

            // store vote tallies 
            if (session->selected_choice >= 1 && session->selected_choice <= 4) {
                vote_tally[session->selected_choice - 1]++;
            }

            session->receipt_id = next_receipt_id();

            voter_id_to_key_string(session->voter_id,
                                   used_key_buf_ballot,
                                   sizeof(used_key_buf_ballot));

            if (append_used_key(used_key_buf_ballot) < 0) {
                set_error(outgoing, "Failed to record used voter.");
                session->state = STATE_DONE;
                return;
            }

            // bulletin board once vote accepted
            if (bulletin_count < MAX_BULLETIN) {
                bulletin_board[bulletin_count].encrypted_vote = incoming;
                bulletin_board[bulletin_count].candidate_id = session->selected_choice;
                bulletin_count++;
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

            encrypted_receipt_value =
                rsa_encrypt_uint64(receipt_code_value, auth_pub->e, auth_pub->n);

            cipher_len = snprintf((char *)ciphertext_buf,
                                  sizeof(ciphertext_buf),
                                  "vote:%u",
                                  session->selected_choice);

            if (cipher_len < 0 || (size_t)cipher_len >= sizeof(ciphertext_buf)) {
                set_error(outgoing, "Failed to build ciphertext buffer.");
                session->state = STATE_DONE;
                return;
            }

            generate_receipt(&session->code_card,
                             session->selected_choice,
                             ciphertext_buf,
                             (size_t)cipher_len,
                             &session->receipt);

            stored.receipt_id = session->receipt_id;
            stored.voter_id   = session->voter_id;
            stored.choice_id  = session->selected_choice;
            stored.receipt    = session->receipt;

            if (append_receipt(&stored) < 0) {
                set_error(outgoing, "Failed to store receipt.");
                session->state = STATE_DONE;
                return;
            }

            if (format_receipt_text(outgoing->payload,
                                    sizeof(outgoing->payload),
                                    session->receipt_id,
                                    &session->receipt) < 0) {
                set_error(outgoing, "Failed to format receipt.");
                session->state = STATE_DONE;
                return;
            }

            outgoing->type = MSG_RECEIPT;
            outgoing->status = STATUS_YES;
            outgoing->key_id = auth_pub->key_id;
            outgoing->receipt_id = session->receipt_id;
            outgoing->choice_id = session->selected_choice;
            outgoing->value = encrypted_receipt_value;
            outgoing->modulus_n = auth_pub->n;

            session->state = STATE_DONE;
            return;
        }

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