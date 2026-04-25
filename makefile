OPENSSL_DIR := $(shell brew --prefix openssl@3)

CFLAGS = -Wall -Wextra -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib -lssl -lcrypto

all: backend frontend keygen

backend:
	gcc backend.c comm.c storage.c codecard.c receipt.c key.c rsa_openssl.c $(CFLAGS) $(LDFLAGS) -o backend

frontend:
	gcc frontend.c comm.c codecard.c key.c rsa_openssl.c $(CFLAGS) $(LDFLAGS) -o frontend

keygen:
	gcc keygen.c key.c rsa_openssl.c $(CFLAGS) $(LDFLAGS) -o keygen

clean:
	rm -f backend frontend keygen