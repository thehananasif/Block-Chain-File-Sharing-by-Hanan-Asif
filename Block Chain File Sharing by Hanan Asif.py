import hashlib
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet

# Blockchain Class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(previous_hash='0', data='Genesis Block')

    def create_block(self, previous_hash, data):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.utcnow()),
            'data': data,
            'previous_hash': previous_hash,
            'hash': None
        }
        block['hash'] = self.calculate_hash(block)
        self.chain.append(block)
        return block

    def calculate_hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def get_last_block(self):
        return self.chain[-1]

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block['previous_hash'] != previous_block['hash']:
                return False
            if self.calculate_hash(current_block) != current_block['hash']:
                return False
        return True

# User Authentication (Simple Mock Example)
class UserAuthentication:
    def __init__(self):
        self.users = {}

    def register_user(self, username, password):
        if username in self.users:
            raise ValueError("User already exists")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = hashed_password

    def authenticate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return self.users.get(username) == hashed_password

# File Encryption and Decryption
class FileEncryption:
    def __init__(self):
        self.keys = {}

    def generate_key(self, username):
        key = Fernet.generate_key()
        self.keys[username] = key
        return key

    def encrypt_file(self, file_path, key):
        with open(file_path, 'rb') as file:
            data = file.read()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path, key):
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        original_file_path = encrypted_file_path.replace(".enc", "")
        with open(original_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        return original_file_path

# Advanced File Sharing System
class AdvancedFileSharingSystem:
    def __init__(self):
        self.blockchain = Blockchain()
        self.auth = UserAuthentication()
        self.encryption = FileEncryption()

    def share_file(self, sender, receiver, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError("File does not exist")

        if sender not in self.encryption.keys or receiver not in self.encryption.keys:
            raise ValueError("Both users must have encryption keys generated")

        # Encrypt file
        encrypted_file_path = self.encryption.encrypt_file(file_path, self.encryption.keys[sender])
        file_hash = self.calculate_file_hash(encrypted_file_path)
        file_data = {
            'sender': sender,
            'receiver': receiver,
            'file_name': os.path.basename(file_path),
            'file_hash': file_hash,
            'encrypted_file_path': encrypted_file_path
        }
        self.blockchain.create_block(
            previous_hash=self.blockchain.get_last_block()['hash'],
            data=file_data
        )
        return file_data

    def calculate_file_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def verify_file(self, encrypted_file_path):
        file_hash = self.calculate_file_hash(encrypted_file_path)
        for block in self.blockchain.chain:
            if block['data'] != 'Genesis Block' and block['data']['file_hash'] == file_hash:
                return True, block
        return False, None

    def decrypt_shared_file(self, receiver, encrypted_file_path):
        if receiver not in self.encryption.keys:
            raise ValueError("Receiver must have an encryption key")
        return self.encryption.decrypt_file(encrypted_file_path, self.encryption.keys[receiver])

# Example Usage
if __name__ == "__main__":
    system = AdvancedFileSharingSystem()

    # Register Users
    system.auth.register_user("alice", "password123")
    system.auth.register_user("bob", "securepass")

    # Authenticate Users
    assert system.auth.authenticate_user("alice", "password123")
    assert system.auth.authenticate_user("bob", "securepass")

    # Generate Encryption Keys
    alice_key = system.encryption.generate_key("alice")
    bob_key = system.encryption.generate_key("bob")

    # File Sharing
    shared_file = system.share_file("alice", "bob", "example.txt")
    print("File shared:", shared_file)

    # File Verification
    is_valid, block = system.verify_file(shared_file['encrypted_file_path'])
    if is_valid:
        print("File verified!", block)
    else:
        print("File verification failed.")

    # File Decryption
    decrypted_file_path = system.decrypt_shared_file("bob", shared_file['encrypted_file_path'])
    print("File decrypted at:", decrypted_file_path)