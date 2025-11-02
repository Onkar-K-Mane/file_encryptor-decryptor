# File Encryptor / Decryptor (AES & DES)

A small browser-based tool to encrypt and decrypt files using CryptoJS (AES and DES/3DES). It runs entirely in the browser — no server required.

This repository contains:

- `index.html` — UI for selecting files, operation (encrypt/decrypt), algorithm (AES/DES), key size and password.
- `script.js` — client-side logic using CryptoJS: PBKDF2 key derivation, AES/DES encryption/decryption, binary handling.
- `style.css` — optional UI styling (if present).

## Features

- AES (128 / 192 / 256) encryption and decryption.
- DES (single DES) and 3DES (Triple DES) support for legacy compatibility.
- Password-based key derivation using PBKDF2 (SHA-256) with a random 16-byte salt.
- Random IV generation per encryption: 16-byte IV for AES, 8-byte IV for DES/3DES.
- Binary-safe handling: files are read/written as Uint8Array / Blob so any file type works.

## File format (current implementation)

Encrypted files produced by this tool are a simple concatenation of:

- 16 bytes: salt (used for PBKDF2)
- N bytes: IV (16 bytes for AES, 8 bytes for DES/3DES)
- remaining bytes: ciphertext (raw bytes)



## How to use

1. Open `index.html` in a modern browser (Chrome, Edge, Firefox).
2. Choose a file using the file picker.
3. Select operation: Encrypt or Decrypt.
4. Choose Algorithm: AES or DES. (When switching, the Key Size dropdown updates automatically.)
5. Choose Key Size:
   - AES: 128 / 192 / 256 bits
   - DES: 64 bits (DES) or 192 bits (3DES)
6. Enter a password.
7. Click "Process File".
8. After processing, click the download link to save the resulting file.

For decryption, pick the encrypted file, enter the password, and process.you do not need to choose the same algorithm and key size used when encrypting,it will be done automatically.

## Security notes

- DES (single DES) is insecure. Avoid it for new data. Triple DES (3DES) is better but also considered legacy.
- AES-CBC is used (via CryptoJS) with PKCS#7 padding. AES-CBC is not an authenticated mode — it does not provide integrity/authenticity. Use AES-GCM (authenticated encryption) or add an HMAC to detect tampering.
- PBKDF2 iteration count in the code is conservative for client-side usage; raising iterations increases brute-force resistance but slows processing on low-end devices.
- All cryptographic operations happen client-side; ensure you run `index.html` locally in a trusted browser environment.

## Development notes

- The project uses [CryptoJS](https://cdnjs.com/libraries/crypto-js) included in `index.html` via CDN.
- `script.js` contains helper utilities to convert between CryptoJS WordArray and Uint8Array, PBKDF2 calls, and the encrypt/decrypt flow.
- Tested locally in desktop browsers. Behavior may vary on mobile browsers.

