# 🧊 Custom 32-bit Block Cipher
This is a fun experimental block cipher implementation written in C. It operates on 32-bit blocks using a 64-bit hashed key, custom key scheduling, and XOR-based chaining. The design is heavily inspired by concepts from Feistel networks and modern symmetric encryption schemes.

# 🔐 Features
32-bit block size

64-bit key (hashed from arbitrary-length input)

Custom key scheduling via rotation and shuffling

Stream-like chaining using XOR with previous ciphertext

Deterministic encryption & decryption with matching key and IV

# 🧪 How It Works
Key Hashing
The raw key is hashed into a 64-bit value through bitwise arithmetic and pseudo-random mutation using its own bytes.

Block Preparation
Input is split into 32-bit blocks. Final block is zero-padded if not divisible by 4.

Key Scheduling
Each round uses a shuffled version of the key halves (ShuffleKeyArray) and dynamic vector rotation (CreateShuffleVector), producing fresh round keys per block.

Encryption Routine
Each block is XORed with the previous ciphertext (or IV for the first block), then mixed with scheduled keys through rotation and shuffling.

Decryption
The process reverses the key mixing and XOR chaining to recover the original plaintext.

# 📦 Example Usage
bash
Copy
Edit
./cipher "your message here"
Example output:

makefile
Copy
Edit
Before: your message here
Encrypted: �^...�
Decrypted: your message here

# ⚠️ Disclaimer
This project is not intended for production use. It’s a learning exercise in cryptographic design and implementation. For real-world use, please stick to audited, standardized encryption libraries like AES or ChaCha20.

# 📚 Credits
Created by [Grant]

