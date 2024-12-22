# Block Chain File Sharing by Hanan Asif

### Overview

This project implements an advanced blockchain-based file sharing system written in Python. The system ensures secure file transfer, file integrity verification, and user authentication. It leverages blockchain technology to maintain an immutable record of file-sharing transactions and uses encryption for enhanced data protection.

## Features

1. Blockchain for File Integrity
   
   - Tracks file transactions with immutable blocks.
   - Ensures file integrity through cryptographic hashes.
  
3. User Authentication
   
   - Secure user registration and login using SHA-256 hashed passwords.
   - Role-based user access with unique encryption keys.
  
4. File Encryption and Decryption

   - Encrypts files before sharing using the `cryptography` library.
   - Supports secure decryption by authorized recipients.
  
5. File Verification

   - Verifies the integrity of shared files using the blockchain.
   - Alerts users of any tampering.
  
## Prerequisites

* Python 3.8+
* Required Python Libraries: Install with the following command:
  ```
  pip install cryptography
  ```
 ## Usage
 #### Register Users
Register new users to the system:
```
system.auth.register_user("username", "password")
```
#### Generate Encryption Keys
Generate unique encryption keys for users:
```
key = system.encryption.generate_key("username")
```
#### Share a File
Encrypt and share a file between users:
```
shared_file = system.share_file("sender", "receiver", "file_path")
print("File shared:", shared_file)
```
#### Verify a File
Check the integrity of the shared file:
```
is_valid, block = system.verify_file("encrypted_file_path")
if is_valid:
    print("File verified!", block)
else:
    print("File verification failed.")
```
#### Decrypt a File
Decrypt a received file:
```
decrypted_file_path = system.decrypt_shared_file("receiver", "encrypted_file_path")
print("File decrypted at:", decrypted_file_path)
```

## Example

1. Register users Alice and Bob.
2. Generate encryption keys for both users.
3. Share a file `example.txt` from Alice to Bob.
4. Verify the integrity of the shared file.
5. Decrypt the file as Bob.

## Warning

> [!WARNING]
> Data Backup: Always keep a backup of your original files. This system does not provide recovery for lost or corrupted files.
> 
> Key Management: Losing your encryption key will make it impossible to decrypt your files. Store keys securely.
> 
> Unauthorized Access: Ensure only authorized personnel have access to your system and encryption keys.

## Security

• Encryption: All files are encrypted before sharing.

• Blockchain: Immutable record of file transactions.

• Authentication: Secure login mechanism with password hashing.

## Contribution
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes and push to your fork.
4. Submit a pull request.

## License
This project is licensed under the `MIT License`. See the `LICENSE file for details.`
