#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"

#define MESSAGE_TEXT_LEN 256

typedef enum {
    MSG_NONE = 0,
    MSG_LOGIN = 1,
    MSG_VOTE = 2,
    MSG_BALLOT_DATA = 3,
    MSG_RECEIPT = 4,
    MSG_ERROR = 5,
    MSG_STATUS = 6
} MessageType;

typedef enum {
    STATUS_NONE = 0,
    STATUS_NO = 1,
    STATUS_YES = 2
} MessageStatus;

typedef struct {
    uint32_t type;        // MessageType
    uint32_t status;      // optional, usually STATUS_NONE for client requests
    uint32_t choice_id;   // used for ballot submission
    char text[MESSAGE_TEXT_LEN]; // key, message text, fallback input
} ClientMessage;

typedef struct {
    uint32_t type;        // MessageType
    uint32_t status;      // STATUS_YES / STATUS_NO / STATUS_NONE
    uint32_t receipt_id;  // used for MSG_RECEIPT
    char text[MESSAGE_TEXT_LEN]; // ballot text, error text, receipt text
} ServerMessage;

#endif