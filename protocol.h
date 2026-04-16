#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"

#define MESSAGE_PAYLOAD_LEN 256
#define KEY_FILE_MAX 128

typedef enum {
    MSG_NONE = 0,
    MSG_HELLO = 1,
    MSG_CHALLENGE = 2,
    MSG_CHALLENGE_RESPONSE = 3,
    MSG_BALLOT_DATA = 4,
    MSG_VOTE = 5,
    MSG_RECEIPT = 6,
    MSG_ERROR = 7,
    MSG_STATUS = 8
} MessageType;

typedef enum {
    STATUS_NONE = 0,
    STATUS_NO = 1,
    STATUS_YES = 2
} MessageStatus;

typedef struct {
    uint32_t type;
    uint32_t status;
    uint32_t voter_id;
    uint32_t key_id;
    uint32_t choice_id;

    uint64_t value;
    uint64_t modulus_n;
    uint64_t exponent_e;

    char payload[MESSAGE_PAYLOAD_LEN];
} ClientMessage;

typedef struct {
    uint32_t type;
    uint32_t status;
    uint32_t key_id;
    uint32_t receipt_id;
    uint32_t choice_id;

    uint64_t value;
    uint64_t modulus_n;
    uint64_t exponent_e;

    char payload[MESSAGE_PAYLOAD_LEN];
} ServerMessage;

#endif