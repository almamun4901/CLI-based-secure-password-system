"""
Author: @ MD AL MAMUN, @ AIMEN
Date: 16/04/2025

This is the authentication file for the password manager. It does the following:
1. Saving the config file.
2. Creating the master password.
3. Verifying the master password.
4. Hashing the password.
5. Comparing the password.

"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

class Auth:
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.salt = None
        self.hash = None
        self._load_config()

    # saving the config file
    def _save_config(self):
        config = {
            "salt": base64.b64encode(self.salt).decode('utf-8'),
            "hash": self.hash
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    # loading the config file
    # if the config file is not found, it will return False
    def _load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.salt = base64.b64decode(config["salt"])
                self.hash = config["hash"]
                return True
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return False
    
    # creating the master password
    def create_master_password(self, password):
        self.salt = os.urandom(16)
        self.hash = self._hash_password(password, self.salt)
        self._save_config()
        return True
    
    # verifying the master password
    def verify_master_password(self, password):
        # Hash the provided password with stored salt
        hash_attempt = self._hash_password(password, self.salt)
        
        # Constant-time comparison to prevent timing attacks
        return self._secure_compare(hash_attempt, self.hash)
    
    # hashing the password
    def _hash_password(self, password, salt):
        # PBKDF2HMAC for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.b64encode(key).decode('utf-8')

    # password comparison
    def _secure_compare(self, a, b):
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    