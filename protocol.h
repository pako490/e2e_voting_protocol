#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"

#define MESSAGE_TEXT_LEN 256
#define KEY_LEN 64

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
    uint32_t type;         
    uint32_t status;       
    uint32_t choice_id;    
    char text[MESSAGE_TEXT_LEN]; 
} ClientMessage;

typedef struct {
    uint32_t type;        
    uint32_t status;      
    uint32_t receipt_id;  
    char text[MESSAGE_TEXT_LEN]; 
} ServerMessage;

#endif