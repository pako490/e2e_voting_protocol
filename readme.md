# End-to-End Verifiable E-Voting System

## Overview

This project implements a simplified end to end verifiable electronic voting system using a client server architecture and RSA encryption.

The system consists of:

* **Backend**: Handles authentication, ballot distribution, vote decryption, tallying, bulletin board display, and receipt generation
* **Frontend**: Handles voter input, challenge response, vote encryption, and receipt display
* **Keygen**: Generates the key files required to run the system

---

## How to Run

* [macOS Instructions](#macos)
* [Windows Instructions](#windows)
* [How Keygen Works](#how-keygen-works)
* [Where Voter Passwords Are](#where-voter-passwords-are)

---

## Requirements

* GCC or Clang
* OpenSSL
* Make

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

### 3. Generate keys

```bash
./keygen
```

### 4. Run backend

```bash
./backend
```

### 5. Run frontend in a new terminal

```bash
./frontend
```

---

## Windows

### Recommended: WSL Ubuntu

### 1. Install dependencies

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

### 2. Build

```bash
make clean
make all
```

### 3. Generate keys

```bash
./keygen
```

### 4. Run backend

```bash
./backend
```

### 5. Run frontend in a new terminal

```bash
./frontend
```

---

## Project Structure

* `backend.c`
  Server side program. It authenticates voters, sends ballots, receives encrypted votes, decrypts votes, updates the tally, stores bulletin board entries, and returns receipts.

* `frontend.c`
  Client side program. It connects to the backend, asks for a voter ID, asks for the voter private key, decrypts the challenge, encrypts the vote, and displays the receipt.

* `keygen.c`
  Generates the RSA key files needed by the system.

* `key.c` / `key.h`
  Handles saving, loading, and searching public and private key lists.

* `rsa_openssl.c` / `rsa_openssl.h`
  Handles RSA key generation, encryption, and decryption using OpenSSL BIGNUM operations.

* `protocol.h`
  Defines the message structures used between frontend and backend.

* `comm.c` / `comm.h`
  Sends and receives full message structs over TCP sockets.

* `storage.c` / `storage.h`
  Tracks used voter IDs and stored receipts.

* `codecard.c` / `codecard.h`
  Creates code card values and confirmation codes.

* `receipt.c` / `receipt.h`
  Builds and stores vote receipts.

---

## Generated Key Files

Running:

```bash
./keygen
```

creates a `keys/` folder with generated key files:

```text
keys/
├── public_auth_keys.bin
├── private_auth_keys.bin
├── public_auth_keys.txt
├── private_auth_keys.txt
├── public_ballot_keys.bin
├── ballot_priv_keys.bin
├── public_ballot_keys.txt
└── ballot_priv_keys.txt
```

---

## How Keygen Works

`keygen` creates two separate sets of RSA key pairs.

### 1. Authentication keys

These are used to prove that a voter is allowed to vote.

```text
public_auth_keys.bin
private_auth_keys.txt
```

The backend loads `public_auth_keys.bin`.

The voter uses `private_auth_keys.txt`.

### 2. Ballot keys

These are used to encrypt and decrypt votes.

```text
public_ballot_keys.bin
ballot_priv_keys.bin
```

The frontend receives the public ballot key from the backend and uses it to encrypt the vote.

The backend uses the matching private ballot key to decrypt the vote.

---

## Where Voter Passwords Are

The voter password is the private key value `d` stored in:

```text
keys/private_auth_keys.txt
```

The file looks like:

```text
count=100
key_id,d
1,ABC123...
2,DEF456...
3,789ABC...
```

To vote as voter `3`, use:

```text
voter ID: 3
private key d: value from row 3
```

The frontend asks:

```text
Enter voter ID:
Enter your private key d (hex) for voter:
```

Copy only the `d` value from `private_auth_keys.txt`.

---

## Voting Modes

When running `./frontend`, enter:

```text
0
```

to show the vote tally.

Enter:

```text
9999
```

to access the bulletin board.

Enter a normal voter ID, such as:

```text
1
```

to vote.

---

## How Voting Works

1. Frontend connects to backend.
2. Voter enters voter ID.
3. Backend sends an encrypted challenge.
4. Voter enters private authentication key `d`.
5. Frontend decrypts challenge and sends response.
6. Backend verifies the response.
7. Backend sends ballot and ballot public key.
8. Frontend encrypts selected vote.
9. Backend stores encrypted vote on bulletin board.
10. Backend decrypts vote for tallying.
11. Backend sends receipt back to frontend.

---

## Notes

* Run `./keygen` before running the backend.
* Run backend before frontend.
* Generated key files are stored in `keys/`.
* Each voter can vote only once.
* `private_auth_keys.txt` contains the voter passwords.
* `9999` shows the bulletin board.
* `0` shows the tally.
