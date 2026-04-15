#include <stdio.h>  
#include <stdint.h>     
#include <stddef.h>     
#include <sys/socket.h> 
#include <arpa/inet.h> 

ssize_t send_all(int sock, const void *buffer, size_t length) {
    size_t total_sent = 0;
    const char *buf = buffer;

    while (total_sent < length) {
        ssize_t sent = send(sock, buf + total_sent, length - total_sent, 0);
        if (sent < 0) {
            perror("send");
            return -1;
        }
        if (sent == 0) {
            break;
        }
        total_sent += sent;
    }

    return total_sent;
}

ssize_t recv_all(int sock, void *buffer, size_t length) {
    size_t total_received = 0;
    char *buf = buffer;

    while (total_received < length) {
        ssize_t received = recv(sock, buf + total_received, length - total_received, 0);
        if (received < 0) {
            perror("recv");
            return -1;
        }
        if (received == 0) {
            // client disconnected
            return 0;
        }
        total_received += received;
    }

    return total_received;
}

int send_message(int sock, const void *data, uint32_t size) {
    uint32_t net_size = htonl(size);

    // send size first
    if (send_all(sock, &net_size, sizeof(net_size)) != sizeof(net_size)) {
        return -1;
    }

    // send actual data
    if (send_all(sock, data, size) != size) {
        return -1;
    }

    return 0;
}


int recv_message(int sock, void *buffer, uint32_t max_size, uint32_t *out_size) {
    uint32_t net_size;

    // receive size
    ssize_t r = recv_all(sock, &net_size, sizeof(net_size));
    if (r <= 0) return -1;

    uint32_t size = ntohl(net_size);

    if (size > max_size) {
        printf("Message too large\n");
        return -1;
    }

    // receive payload
    r = recv_all(sock, buffer, size);
    if (r <= 0) return -1;

    *out_size = size;
    return 0;
}