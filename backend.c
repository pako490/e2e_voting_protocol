#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "comm.h"
#include "protocol.h"
#include "storage.h"

typedef enum {
    STATE_LOGIN,
    STATE_BALLOT,
    STATE_RECEIPT,
    STATE_DONE
} SessionState;

typedef struct {
    SessionState state;
    int authenticated;
    char voter_key[KEY_LEN];
    uint32_t selected_choice;
    int receipt_id;

    int hit_login;
    int hit_ballot;
    int hit_receipt;
    int hit_done;
} ClientSession;

static int next_receipt_id(void) {
    static int id = 1000;
    return id++;
}

static const char *state_name(SessionState state) {
    switch (state) {
        case STATE_LOGIN:   return "LOGIN";
        case STATE_BALLOT:  return "BALLOT";
        case STATE_RECEIPT: return "RECEIPT";
        case STATE_DONE:    return "DONE";
        default:            return "UNKNOWN";
    }
}

static const char *msg_type_name(uint32_t type) {
    switch (type) {
        case MSG_NONE:        return "MSG_NONE";
        case MSG_LOGIN:       return "MSG_LOGIN";
        case MSG_VOTE:        return "MSG_VOTE";
        case MSG_BALLOT_DATA: return "MSG_BALLOT_DATA";
        case MSG_RECEIPT:     return "MSG_RECEIPT";
        case MSG_ERROR:       return "MSG_ERROR";
        case MSG_STATUS:      return "MSG_STATUS";
        default:              return "UNKNOWN";
    }
}

static const char *status_name(uint32_t status) {
    switch (status) {
        case STATUS_NONE: return "STATUS_NONE";
        case STATUS_NO:   return "STATUS_NO";
        case STATUS_YES:  return "STATUS_YES";
        default:          return "UNKNOWN";
    }
}

static void print_session_hits(const ClientSession *session) {
    printf("[BACKEND] State hit counts: LOGIN=%d BALLOT=%d RECEIPT=%d DONE=%d\n",
           session->hit_login,
           session->hit_ballot,
           session->hit_receipt,
           session->hit_done);
}

static void set_error_response(ServerMessage *outgoing, const char *message) {
    memset(outgoing, 0, sizeof(*outgoing));
    outgoing->type = MSG_ERROR;
    outgoing->status = STATUS_NO;
    snprintf(outgoing->text, sizeof(outgoing->text), "%s", message);
}

static void process_message(ClientSession *session,
                            const ClientMessage *incoming,
                            ServerMessage *outgoing) {
    memset(outgoing, 0, sizeof(*outgoing));
    outgoing->status = STATUS_NONE;

    printf("[BACKEND] Enter process_message: state=%s, incoming_type=%s (%u), status=%s (%u)\n",
           state_name(session->state),
           msg_type_name(incoming->type),
           incoming->type,
           status_name(incoming->status),
           incoming->status);

    switch (session->state) {
        case STATE_LOGIN:
            session->hit_login++;

            if (incoming->type != MSG_LOGIN) {
                set_error_response(outgoing, "Expected login first.");
                printf("[BACKEND] LOGIN rejected: wrong message type\n");
                break;
            }

            if (!is_valid_key(incoming->text)) {
                set_error_response(outgoing, "Invalid key.");
                printf("[BACKEND] LOGIN rejected: invalid key=%s\n", incoming->text);
                break;
            }

            if (is_used_key(incoming->text)) {
                set_error_response(outgoing, "Key already used.");
                printf("[BACKEND] LOGIN rejected: used key=%s\n", incoming->text);
                break;
            }

            strncpy(session->voter_key, incoming->text, KEY_LEN - 1);
            session->voter_key[KEY_LEN - 1] = '\0';
            session->authenticated = 1;

            printf("[BACKEND] LOGIN success: key=%s\n", session->voter_key);
            printf("[BACKEND] Transition: %s -> %s\n",
                   state_name(session->state), state_name(STATE_BALLOT));

            session->state = STATE_BALLOT;

            outgoing->type = MSG_BALLOT_DATA;
            outgoing->status = STATUS_YES;

            if (build_ballot_text(outgoing->text, sizeof(outgoing->text)) < 0) {
                set_error_response(outgoing, "Failed to build ballot.");
                printf("[BACKEND] Failed to build ballot text\n");
            }
            break;

        case STATE_BALLOT:
            session->hit_ballot++;

            if (incoming->type != MSG_VOTE) {
                set_error_response(outgoing, "Expected ballot submission.");
                printf("[BACKEND] BALLOT rejected: wrong message type\n");
                break;
            }

            if (!session->authenticated) {
                set_error_response(outgoing, "Not authenticated.");
                printf("[BACKEND] BALLOT rejected: session not authenticated\n");
                break;
            }

            printf("[BACKEND] Received ballot choice=%u\n", incoming->choice_id);

            if (!is_valid_ballot_choice(incoming->choice_id)) {
                set_error_response(outgoing, "Invalid ballot choice.");
                printf("[BACKEND] BALLOT rejected: invalid choice=%u\n", incoming->choice_id);
                break;
            }

            session->selected_choice = incoming->choice_id;

            if (append_used_key(session->voter_key) < 0) {
                set_error_response(outgoing, "Failed to record used key.");
                printf("[BACKEND] BALLOT failed: could not append used key=%s\n",
                       session->voter_key);
                break;
            }

            session->receipt_id = next_receipt_id();

            printf("[BACKEND] BALLOT success: key=%s choice=%u receipt=%d\n",
                   session->voter_key,
                   session->selected_choice,
                   session->receipt_id);
            printf("[BACKEND] Transition: %s -> %s\n",
                   state_name(session->state), state_name(STATE_RECEIPT));

            session->state = STATE_RECEIPT;

            outgoing->type = MSG_RECEIPT;
            outgoing->status = STATUS_YES;
            outgoing->receipt_id = session->receipt_id;
            snprintf(outgoing->text, sizeof(outgoing->text),
                     "Vote accepted. Receipt issued.");
            break;

        case STATE_RECEIPT:
            session->hit_receipt++;

            printf("[BACKEND] RECEIPT state reached, preparing to finish session\n");
            printf("[BACKEND] Transition: %s -> %s\n",
                   state_name(session->state), state_name(STATE_DONE));

            session->state = STATE_DONE;
            session->hit_done++;

            outgoing->type = MSG_STATUS;
            outgoing->status = STATUS_YES;
            snprintf(outgoing->text, sizeof(outgoing->text), "Session complete.");
            break;

        case STATE_DONE:
            session->hit_done++;
            set_error_response(outgoing, "Connection closed.");
            printf("[BACKEND] DONE state reached\n");
            break;
    }
}

static void handle_client(int client_fd) {
    ClientSession session;
    ClientMessage incoming;
    ServerMessage outgoing;
    uint32_t received_size = 0;

    memset(&session, 0, sizeof(session));
    session.state = STATE_LOGIN;

    printf("[BACKEND] New client session started\n");
    printf("[BACKEND] Session initialized: state=%s\n", state_name(session.state));

    while (session.state != STATE_DONE) {
        memset(&incoming, 0, sizeof(incoming));
        memset(&outgoing, 0, sizeof(outgoing));
        received_size = 0;

        if (recv_message(client_fd, &incoming, sizeof(incoming), &received_size) < 0) {
            perror("recv_message");
            break;
        }

        if (received_size != sizeof(incoming)) {
            fprintf(stderr, "[BACKEND] Unexpected message size: %u bytes\n", received_size);
            break;
        }

        printf("[BACKEND] Received %u bytes\n", received_size);
        printf("[BACKEND] Incoming payload: type=%s (%u), status=%s (%u), choice_id=%u, text=\"%s\"\n",
               msg_type_name(incoming.type),
               incoming.type,
               status_name(incoming.status),
               incoming.status,
               incoming.choice_id,
               incoming.text);

        process_message(&session, &incoming, &outgoing);

        if (send_message(client_fd, &outgoing, sizeof(outgoing)) < 0) {
            perror("send_message");
            break;
        }

        printf("[BACKEND] Outgoing payload: type=%s (%u), status=%s (%u), receipt_id=%u, text=\"%s\"\n",
               msg_type_name(outgoing.type),
               outgoing.type,
               status_name(outgoing.status),
               outgoing.status,
               outgoing.receipt_id,
               outgoing.text);

        if (session.state == STATE_RECEIPT) {
            session.hit_receipt++;
            printf("[BACKEND] Receipt delivered, ending session after receipt\n");
            printf("[BACKEND] Transition: %s -> %s\n",
                   state_name(session.state), state_name(STATE_DONE));
            session.state = STATE_DONE;
            session.hit_done++;
        }
    }

    print_session_hits(&session);
    printf("[BACKEND] Session closing in state=%s\n", state_name(session.state));

    close(client_fd);
    printf("[BACKEND] Client session ended\n");
}

int main(void) {
    int server_fd;
    int client_fd;
    int opt = 1;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    if (load_valid_keys_binary("valid_keys.bin") < 0) {
        fprintf(stderr, "[BACKEND] Failed to load valid keys\n");
        return 1;
    }

    if (load_ballot_binary("ballot.bin") < 0) {
        fprintf(stderr, "[BACKEND] Failed to load ballot\n");
        return 1;
    }

    init_used_keys();

    printf("[BACKEND] Loaded %d valid keys\n", valid_key_count);
    print_valid_keys();

    printf("[BACKEND] Loaded %d ballot options\n", ballot_option_count);
    print_ballot();

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

        printf("[BACKEND] Client connected\n");
        handle_client(client_fd);
    }

    close(server_fd);
    return 0;
}