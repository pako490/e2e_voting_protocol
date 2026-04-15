#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"
#include "comm.h"


int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;

    //imported types from protocol.h
    ClientMessage outgoing;
    ServerMessage incoming;
    uint32_t received_size = 0; //update this later

    //creates a socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }


    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    //connects to backend 
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Connected to backend\n");

    //implement login/log out here 




    //allocates memory for outgoing message
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.type = MSG_TEXT;


    //sending message 
    printf("Enter a message to send: ");
    if (fgets(outgoing.text, sizeof(outgoing.text), stdin) == NULL) {
        fprintf(stderr, "Failed to read input\n");
        close(sock_fd);
        return 1;
    }

    // ENCRYPTION HERE


    outgoing.text[strcspn(outgoing.text, "\n")] = '\0';

    if (send_message(sock_fd, &outgoing, sizeof(outgoing)) < 0) {
        fprintf(stderr, "[FRONTEND] Failed to send message\n");
        close(sock_fd);
        return 1;
    }

    printf("[FRONTEND] Message sent\n");


    //this should be the ballot 

    //receiving receipt 
    memset(&incoming, 0, sizeof(incoming));
    if (recv_message(sock_fd, &incoming, sizeof(incoming), &received_size) <= 0) {
        perror("recv");
        close(sock_fd);
        return 1;
    }


    //incoming size checker
    if (received_size != sizeof(incoming)) {
        fprintf(stderr, "[FRONTEND] Unexpected receipt size: %u bytes\n", received_size);
        close(sock_fd);
        return 1;
    }

    //DECREYPTION HERE


    //print the ballot 
    printf("[FRONTEND] Receipt received\n");
    printf("Receipt ID: %d\n", incoming.receipt_id);
    printf("Message: %s\n", incoming.text);

    close(sock_fd);
    return 0;
}