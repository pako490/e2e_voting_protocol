#ifndef COMM_H
#define COMM_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

ssize_t send_all(int sock, const void *buffer, size_t length);
ssize_t recv_all(int sock, void *buffer, size_t length);
int send_message(int sock, const void *data, uint32_t size);
int recv_message(int sock, void *buffer, uint32_t max_size, uint32_t *out_size);

#endif