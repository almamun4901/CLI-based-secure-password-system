import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

class Auth:
    # def __init__(self, config_file='config.json'):
    #     self.config_file = config_file
    #     self.salt = None
    #     self.hash = None
    #     self._load_config()

    def __init__(self):
        self.salt = None
        self.hash = None
    
    def create_master_password(self, password):
        self.salt = os.urandom(16)
        self.hash = self._hash_password(password, self.salt)
        
        return True
    
    def verify_master_password(self, password):
        # Hash the provided password with stored salt
        hash_attempt = self._hash_password(password, self.salt)
        
        # Constant-time comparison to prevent timing attacks
        return self._secure_compare(hash_attempt, self.hash)
    
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
    
    def _secure_compare(self, a, b):
        return hashlib.compare_digest(a, b)
    