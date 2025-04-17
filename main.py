"""
Author: @ MD AL MAMUN, @ AIMEN
Date: 16/04/2025

This is the main file for the password manager. It does the following:
1. Authentication.
2. Command loop.
3. Adding, retrieving, updating, and deleting passwords.
4. Generating passwords.
5. Logging out.

We have taken the help from different sources to make this project ( not particularly AI)
Needed to learn about the cryptography (Fernet, PBKDF2HMAC, SHA256). The password generator wasn't that hard but the encryption was a bit challenging.

"""
import os
import getpass
import sys
import time
from auth import Auth
from crypto_utils import CryptoUtils
from vault import PasswordVault
from password_generator import PasswordGenerator

class PasswordManager:
    def __init__(self):
        self.auth = Auth()
        self.crypto_utils = None
        self.vault = None
        self.password_generator = PasswordGenerator()
        self.is_authenticated = False
        self.auto_lock_timeout = 300 
        self.last_activity = time.time()
    
    def start(self):
        self._print_welcome()
        
        
        if not os.path.exists('config.json'):
            self._setup_master_password()
        else:
            self._login()
        
        if self.is_authenticated:
            self._command_loop()
    
    # printing the welcome message
    def _print_welcome(self):
        print("\nWelcome to your secure password vault\n")
    
    # setting up the master password
    def _setup_master_password(self):
        print("Initial setup - create your master password")
        
        while True:
            password = getpass.getpass("Enter master password: ")
            
            
            strength = self.password_generator.check_password_strength(password)
            if strength["score"] < 3:
                print("Master password is too weak:")
                for feedback in strength["feedback"]:
                    print(f"- {feedback}")
                continue
            
            verify = getpass.getpass("Confirm master password: ")
            
            if password != verify:
                print("Passwords don't match. Try again.")
                continue
            
            break
        
        self.auth.create_master_password(password)
        print("Master password created successfully!")
        
        # Initialize encryption
        self.crypto_utils = CryptoUtils(password, self.auth.salt)
        self.vault = PasswordVault(self.crypto_utils)
        self.is_authenticated = True
    
    # login function
    def _login(self):
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            password = getpass.getpass("Enter master password: ")
            
            if self.auth.verify_master_password(password):
                self.crypto_utils = CryptoUtils(password, self.auth.salt)
                self.vault = PasswordVault(self.crypto_utils)
                self.is_authenticated = True
                return
            
            attempts += 1
            print(f"Invalid password. {max_attempts - attempts} attempts remaining.")
        
        print("Too many failed attempts. Exiting.")
        sys.exit(1)
    
    # command loop to ease the user
    def _command_loop(self):
        print("\nPassword Manager ready. Type 'help' for available commands.")
        
        while True:
            # Check for auto-lock
            if time.time() - self.last_activity > self.auto_lock_timeout:
                print("\nSession timed out due to inactivity. Please login again.")
                self._logout()
                self._login()
                if not self.is_authenticated:
                    return
            
            self.last_activity = time.time()
            command = input("\n> ").strip().lower()
            
            if command == "exit" or command == "quit":
                self._logout()
                break
            elif command == "help":
                self._show_help()
            elif command == "add":
                self._add_entry()
            elif command == "list":
                self._list_entries()
            elif command == "get":
                self._get_entry()
            elif command == "update":
                self._update_entry()
            elif command == "delete":
                self._delete_entry()
            elif command == "generate":
                self._generate_password()
            else:
                print("Unknown command. Type 'help' for available commands.")
    
    # showing the help message
    def _show_help(self):
        print("\nAvailable commands:")
        print("  help      - Show this help message")
        print("  add       - Add a new password entry")
        print("  list      - List all saved services")
        print("  get       - Retrieve password for a service")
        print("  update    - Update an existing entry")
        print("  delete    - Delete an entry")
        print("  generate  - Generate a strong password")
        print("  exit      - Exit the password manager")
    
    # adding the entry
    def _add_entry(self):
        service = input("Service name: ").strip()
        username = input("Username: ").strip()
        
        use_generator = input("Generate password? (y/n): ").strip().lower() == 'y'
        
        if use_generator:
            password = self._generate_password(show_output=False)
        else:
            password = getpass.getpass("Password: ")
        

        entry_id = self.vault.add_password(service, username, password)
        print(f"Password saved successfully with ID: {entry_id}")
    
    # listing the entries
    def _list_entries(self):
        services = self.vault.list_services()
        
        if not services:
            print("No saved passwords.")
            return
        
        print("\nSaved services:")
        print("-" * 50)
        print(f"{'ID':<10} | {'Service':<20} | {'Username':<20}")
        print("-" * 50)
        
        for entry in services:
            print(f"{entry['id']:<10} | {entry['service']:<20} | {entry['username']:<20}")
    
    # getting the entry
    def _get_entry(self):
        search = input("Search by service name: ").strip()
        
        entries = self.vault.get_password(service=search)
        
        if not entries:
            print("No matching entries found.")
            return
        
        if len(entries) > 1:
            print(f"Found {len(entries)} matching entries:")
            for i, entry in enumerate(entries):
                print(f"{i+1}. {entry['service']} ({entry['username']})")
            
            selection = input("Select entry number (or 0 to cancel): ")
            try:
                selection = int(selection) - 1
                if selection < 0 or selection >= len(entries):
                    return
                entry = entries[selection]
            except:
                print("Invalid selection.")
                return
        else:
            entry = entries[0]
        
        print("\nEntry details:")
        print(f"Service:  {entry['service']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
    
    # updating the entry
    def _update_entry(self):
        self._list_entries()
        entry_id = input("\nEnter ID to update (or 0 to cancel): ").strip()
        
        if entry_id == '0':
            return
        
        entry = self.vault.get_password(entry_id=entry_id)
        
        if not entry:
            print("Entry not found.")
            return
        
        print(f"\nUpdating entry for {entry['service']}")
        print("Leave field blank to keep current value.")
        
        service = input(f"Service name [{entry['service']}]: ").strip()
        username = input(f"Username [{entry['username']}]: ").strip()
        
        change_password = input("Change password? (y/n): ").strip().lower() == 'y'
        password = None
        
        if change_password:
            use_generator = input("Generate password? (y/n): ").strip().lower() == 'y'
            
            if use_generator:
                password = self._generate_password(show_output=False)
            else:
                password = getpass.getpass("New password: ")
        
        
        # Prepare update
        updates = {}
        if service:
            updates['service'] = service
        if username:
            updates['username'] = username
        if password:
            updates['password'] = password
        
        if updates:
            if self.vault.update_password(entry_id, **updates):
                print("Entry updated successfully.")
            else:
                print("Failed to update entry.")
        else:
            print("No changes made.")
    
    # deleting the entry
    def _delete_entry(self):
        self._list_entries()
        entry_id = input("\nEnter ID to delete (or 0 to cancel): ").strip()
        
        if entry_id == '0':
            return
        
        confirm = input("Are you sure you want to delete this entry? (y/n): ").strip().lower()
        
        if confirm == 'y':
            if self.vault.delete_password(entry_id):
                print("Entry deleted successfully.")
            else:
                print("Failed to delete entry.")
    
    # generating the password
    def _generate_password(self, show_output=True):
        if show_output:
            print("\nPassword Generator")
        
        length = 16
        try:
            length_input = input(f"Password length [{length}]: ").strip()
            if length_input:
                length = int(length_input)
        except:
            print("Using default length.")
        
        include_uppercase = input("Include uppercase letters? (y/n) [y]: ").strip().lower() != 'n'
        include_lowercase = input("Include lowercase letters? (y/n) [y]: ").strip().lower() != 'n'
        include_digits = input("Include digits? (y/n) [y]: ").strip().lower() != 'n'
        include_special = input("Include special characters? (y/n) [y]: ").strip().lower() != 'n'
        
        password = self.password_generator.generate_password(
            length, include_uppercase, include_lowercase, include_digits, include_special
        )
        
        if show_output:
            print(f"\nGenerated password: {password}")
            
            strength = self.password_generator.check_password_strength(password)
            print(f"Password strength: {strength['rating']}")
            
            if strength['feedback']:
                print("Feedback:")
                for feedback in strength['feedback']:
                    print(f"- {feedback}")
        
        return password
    
    # logging out the user
    def _logout(self):
        if self.vault:
            self.vault = None
        if self.crypto_utils:
            self.crypto_utils.secure_wipe()
            self.crypto_utils = None
        
        self.is_authenticated = False
        print("Securely logged out.")

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.start()