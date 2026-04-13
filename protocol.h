#ifndef PROTOCOL_H
#define PROTOCOL_H

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 8080 // will probably change this to somethign else later 

#define MSG_TEXT 1
#define MSG_RECEIPT 2
#define MSG_ERROR 3

typedef struct {
    int type;
    char text[256];
} ClientMessage;

typedef struct {
    int type;
    int receipt_id;
    char text[256];
} ServerMessage;

#endif