# HE_Vault

A command-line password vault written in C++ that stores credentials using **Homomorphic Encryption** (Microsoft SEAL / BFV scheme) and protects the master key with **AES-256-GCM** (OpenSSL). Credentials are never written to disk in plaintext — they live on disk exclusively as BFV ciphertexts.

---

## Features

- **Homomorphic Encryption storage** — credentials are encrypted with Microsoft SEAL's BFV scheme and batch-encoded into polynomial slots before being written to disk.
- **AES-256-GCM master key protection** — the SEAL secret key is encrypted with a key derived from your master password via PBKDF2-SHA256 (100 000 iterations) before being saved.
- **Atomic file operations** — every write goes through a temp-file + `rename()` pattern, so a crash mid-write can never corrupt your vault.
- **Secure memory erasure** — all sensitive strings (passwords, credentials, serialised keys) are wiped with `OPENSSL_cleanse` before they go out of scope.
- **Input validation** — account names and credentials are checked for empty values, null bytes, the reserved `|` delimiter, and a 1 024-byte length cap.
- **Credential screen-clearing** — after displaying credentials, the terminal lines are erased with ANSI escape codes once you press Enter.
- **Password change** — re-encrypts the secret key blob under a new master password without touching the vault data.

---

## Cryptographic Design

```
Master Password
      │
      ▼  PBKDF2-SHA256 (100 000 iters, random 16-byte salt)
  AES-256-GCM key
      │
      ▼  AES-256-GCM encrypt  (random 12-byte IV, 16-byte GCM tag)
  Encrypted SEAL SecretKey  ──► secret_key.enc
      │
      │  (only decrypted in RAM, never written back plain)
      ▼
  SEAL BFV Decryptor
      │
      ▼  decrypt + BatchDecode each ciphertext
  Plaintext credentials  ──► wiped from heap immediately after use

Credentials on disk:
  account_name|credential  ──► BatchEncode ──► BFV Encrypt ──► data_store.bin
```

The public key (`public_key.bin`) is stored unprotected because it is only needed for encryption and reveals nothing about stored credentials.

---

## Files Created at Runtime

| File | Contents |
|---|---|
| `params.bin` | SEAL `EncryptionParameters` (BFV, poly_modulus_degree = 4096) |
| `public_key.bin` | SEAL `PublicKey` (plaintext — used only for encryption) |
| `secret_key.enc` | AES-256-GCM blob: `salt \|\| IV \|\| GCM-tag \|\| encrypted SecretKey` |
| `data_store.bin` | Concatenated SEAL `Ciphertext` objects (one per account) |

---

## Dependencies

| Library | Version | Purpose |
|---|---|---|
| [Microsoft SEAL](https://github.com/microsoft/SEAL) | ≥ 4.1 | BFV homomorphic encryption |
| [OpenSSL](https://www.openssl.org/) | any modern | AES-256-GCM, PBKDF2, RAND_bytes, secure erase |
| C++ Standard Library | C++17 | `std::filesystem`, atomics, containers |

---

## Build

```bash
# 1. Install Microsoft SEAL (builds + installs to /usr/local by default)
git clone https://github.com/microsoft/SEAL.git
cd SEAL && cmake -S . -B build -DSEAL_USE_INTEL_HEXL=OFF
cmake --build build --target install
cd ..

# 2. Install OpenSSL development headers
# Ubuntu/Debian:
sudo apt install libssl-dev
# macOS (Homebrew):
brew install openssl

# 3. Build HE_Vault
git clone https://github.com/nithish2572007-star/HE_Vault.git
cd HE_Vault
cmake -S . -B build
cmake --build build
```

The compiled binary is placed at `build/he_vault`.

---

## Usage

Run the binary from the directory where you want the vault files to be stored (they are created in the current working directory):

```
./build/he_vault
```

### Menu

```
==============================
         HE Vault CLI
==============================
 1. Setup / Factory Reset
 2. Add Account
 3. Retrieve Credentials
 4. Update Account
 5. Delete Account
 6. Change Master Password
 7. Exit
==============================
```

### First Run

Select **1 (Setup)** to generate a fresh set of SEAL keys and create an empty vault. You will be asked to set a master password and to confirm it. **Warning:** running Setup again wipes all stored accounts.

### Add an Account

Select **2**, enter your master password, then provide an account name and the credentials to store. If the account name already exists, you will be prompted to overwrite it.

### Retrieve Credentials

Select **3**, enter your master password. All account names are listed; type the one you want and the credentials are displayed. Press Enter to erase them from the terminal.

### Update / Delete

Options **4** and **5** load all accounts into RAM (decrypted), modify the map, and rewrite the entire vault atomically.

### Change Master Password

Option **6** decrypts the SEAL secret key blob under the old password, re-encrypts it under the new password, and atomically replaces `secret_key.enc`. The vault ciphertext data is untouched.

---

## Security Notes

- The BFV polynomial modulus degree is set to **4096**, giving a slot count of 2048. Any `account_name|credential` string longer than 2048 characters will be rejected.
- PBKDF2 with 100 000 SHA-256 iterations provides a reasonable work factor for offline brute-force resistance; increase `PBKDF2_ITERS` in the source if you want stronger protection.
- The vault does **not** implement brute-force lockout; a stolen `secret_key.enc` file can be attacked offline. Use a strong master password.
- All temporary files use the `.tmp` suffix and are renamed atomically; stale `.tmp` files left behind by a crash can be safely deleted.
- The project has been hardened against: partial-write data corruption, heap-lingering plaintext credentials, input injection via the `|` delimiter, and silent stream-close failures.

---
