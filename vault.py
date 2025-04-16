import json
import time
import os
from crypto_utils import CryptoUtils

class PasswordVault:
    def __init__(self, crypto_utils, storage_file='storage.json'):
        self.crypto_utils = crypto_utils
        self.storage_file = storage_file
        self.entries = {}
        self.last_activity = time.time()
        self._load_vault()
    
    def _load_vault(self):
        # Load and decrypt vault if exists
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = self.crypto_utils.decrypt(encrypted_data)
                self.entries = json.loads(decrypted_data.decode())
            except Exception as e:
                # Handle decryption errors
                print(f"Error loading vault: {e}")
                self.entries = {}
        else:
            # Create new vault
            self.entries = {"version": "1.0", "passwords": []}
    
    def _save_vault(self):
        # Encrypt and save vault
        self.last_activity = time.time()
        
        encrypted_data = self.crypto_utils.encrypt(json.dumps(self.entries).encode())
        
        with open(self.storage_file, 'wb') as f:
            f.write(encrypted_data)
    
    def add_password(self, service, username, password, url="", notes=""):
        # Add new entry
        entry_id = self._generate_id()
        
        entry = {
            "id": entry_id,
            "service": service,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "created": time.time(),
            "modified": time.time()
        }
        
        self.entries["passwords"].append(entry)
        self._save_vault()
        return entry_id
    
    def get_password(self, entry_id=None, service=None):
        # Retrieve entry by id or service name
        if entry_id:
            for entry in self.entries["passwords"]:
                if entry["id"] == entry_id:
                    self.last_activity = time.time()
                    return entry
        
        if service:
            matching = []
            for entry in self.entries["passwords"]:
                if service.lower() in entry["service"].lower():
                    matching.append(entry)
            
            self.last_activity = time.time()
            return matching
        
        return None
    
    def update_password(self, entry_id, **kwargs):
        # Update entry fields
        for entry in self.entries["passwords"]:
            if entry["id"] == entry_id:
                for key, value in kwargs.items():
                    if key in entry:
                        entry[key] = value
                
                entry["modified"] = time.time()
                self._save_vault()
                return True
        
        return False
    
    def delete_password(self, entry_id):
        # Delete entry
        for i, entry in enumerate(self.entries["passwords"]):
            if entry["id"] == entry_id:
                del self.entries["passwords"][i]
                self._save_vault()
                return True
        
        return False
    
    def list_services(self):
        # List all services
        services = []
        for entry in self.entries["passwords"]:
            services.append({
                "id": entry["id"],
                "service": entry["service"],
                "username": entry["username"]
            })
        
        self.last_activity = time.time()
        return services
    
    def _generate_id(self):
        # Generate unique ID for entry
        return os.urandom(8).hex()
    
    def check_inactivity(self, timeout=300):
        # Check if vault should auto-lock due to inactivity
        if time.time() - self.last_activity > timeout:
            return True
        return False