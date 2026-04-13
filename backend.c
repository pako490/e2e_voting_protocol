#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "protocol.h"

static int next_receipt_id(void) {
    static int id = 1000;
    return id++;
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    ClientMessage incoming;
    ServerMessage outgoing;

    //creates socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }  

    int opt = 1;    
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
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        printf("[BACKEND] Client connected\n");

        memset(&incoming, 0, sizeof(incoming));
        ssize_t bytes_received = recv(client_fd, &incoming, sizeof(incoming), 0);
        if (bytes_received <= 0) {
            perror("recv");
            close(client_fd);
            continue;
        }

        printf("[BACKEND] Received type=%d text=\"%s\"\n", incoming.type, incoming.text);

        memset(&outgoing, 0, sizeof(outgoing));
        outgoing.type = MSG_RECEIPT;
        outgoing.receipt_id = next_receipt_id();
        snprintf(outgoing.text, sizeof(outgoing.text),
                 "Backend received your message successfully.");

        if (send(client_fd, &outgoing, sizeof(outgoing), 0) < 0) {
            perror("send");
        } else {
            printf("[BACKEND] Sent receipt_id=%d\n", outgoing.receipt_id);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}