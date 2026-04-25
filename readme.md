# End-to-End Verifiable E-Voting System

## Overview

This project implements a simplified end to end verifiable electronic voting system using a client server architecture and RSA encryption.

The system consists of:

* **Backend**: Handles authentication, ballot distribution, vote decryption, and receipt generation
* **Frontend**: Handles user interaction and cryptographic operations

---

## Requirements

* GCC or Clang
* OpenSSL

---

## Project Structure

* `backend.c` – Server logic and session handling
* `frontend.c` – Client voting interface
* `rsa_openssl.c/.h` – RSA encryption and decryption
* `comm.c/.h` – TCP communication
* `protocol.h` – Message definitions
* `storage.c/.h` – Key tracking and storage
* `keyloader.c/.h` – Loads keys from files
* `codecard.c/.h` – Receipt mapping

---

## Required Files

Ensure these files exist before running:

* `public_auth_keys.bin`
* `public_ballot_keys.bin`
* `ballot_priv_keys.bin`
* `ballot.bin`

---

## How to Run

* [macOS Instructions](#macos)
* [Windows Instructions](#windows)

---

## macOS

### 1. Install OpenSSL

```bash
brew install openssl@3
```

### 2. Build

```bash
make clean
make all
```

If needed, ensure your Makefile includes:

```make
OPENSSL_DIR := $(shell brew --prefix openssl@3)
CFLAGS = -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib -lssl -lcrypto
```

### 3. Run backend

```bash
./backend
```

### 4. Run frontend (new terminal)

```bash
./frontend
```

---

## Windows

### Recommended: WSL (Ubuntu)

#### 1. Install dependencies

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

#### 2. Build

```bash
make clean
make all
```

#### 3. Run backend

```bash
./backend
```

#### 4. Run frontend (new terminal)

```bash
./frontend
```

---

## How It Works

1. Frontend connects to backend via TCP
2. Backend sends encrypted authentication challenge
3. Frontend decrypts and responds
4. Backend verifies and sends ballot
5. Frontend encrypts vote and sends it
6. Backend decrypts vote and generates receipt
7. Frontend decrypts receipt and displays result

---

## Notes

* Backend must be running before frontend
* Each voter can vote only once
* Private keys are entered manually on the frontend
* All communication uses RSA encryption

---
