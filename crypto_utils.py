"""
Author: @ MD AL MAMUN, @ AIMEN
Date: 16/04/2025

This is the encryption file for the password manager. It does the following:
1. Deriving the key.
2. Encrypting the data.
3. Decrypting the data.
4. Secure wiping the data.

"""

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoUtils:
    def __init__(self, master_password, salt):
        self.key = self.derive_key(master_password, salt)
        self.fernet = Fernet(self.key)
    
    def derive_key(self, password, salt):
        keyDerivationFunction = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(keyDerivationFunction.derive(password.encode()))
        return key
    
    def encrypt(self, data):
        # checking if the data is a string
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data)
    
    def decrypt(self, token):
        return self.fernet.decrypt(token)
    
    def secure_wipe(self):
        self.key = None
        self.fernet = None