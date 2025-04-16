import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoUtils:
    def __init__(self, master_password, salt):
        self.key = self._derive_key(master_password, salt)
        self.fernet = Fernet(self.key)
    
    def _derive_key(self, password, salt):
        # Convert master password to encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data):
        # Encrypt data using derived key
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data)
    
    def decrypt(self, token):
        return self.fernet.decrypt(token)
    
    def secure_wipe(self):
        # Attempt to clear sensitive data from memory
        # Note: This is difficult to guarantee in Python due to garbage collection
        self.key = None
        self.fernet = None