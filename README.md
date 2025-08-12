# 🔐 Keysafe – Secure CLI Password Manager Using RSA Encryption

**Keysafe** is a command-line password manager built in Python that combines secure password generation with RSA encryption for safe local storage. It’s designed for simplicity, modularity, and security.

Keysafe uses only built-in Python libraries for maximum portability.

You don’t need to install any external packages — just run it with Python 3.x and you're good to go.

## 🚀 Features

- ✅ Generate strong, random passwords
- 🔒 Encrypt passwords using custom RSA implementation
- 🗝️ Manage public/private RSA key pairs
- 📂 Securely store and retrieve passwords
- 🧂 Salt and hash-based verification
- 🧪 Debug mode for hash comparison and verification

## 🧱 Project Structure
## Encryption.py 
Handles RSA logic and ASCII conversion

Handles Hash Validation

RSA public key and private key generation

Generate random prime number

# password_manager.py  
Generate Random password 

Encrypt and store password

Retrive stored password from Store.txt

# public_keys.txt 
Stores public key (e, n), salt, hash(salt + private key)

# store.txt
Encrypted password vault 

# message_hash.txt
hash passwords pre-encryption for verification (debug) stored in this file

