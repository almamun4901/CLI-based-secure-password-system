"""
Author: @ MD AL MAMUN, @ AIMEN
Date: 16/04/2025

we  have used a different approach to randomize the password. To make it stronger, we set the minimum length to 8 and we ensure that the password contains at least one character from each selected set.
Then we replace the random character in the password with one from the char_set.
We also added a feedback mechanism to the password strength check as like the current days websites do.
"""

import secrets
import string

class PasswordGenerator:
    def __init__(self):
        self.uppercase_letters = string.ascii_uppercase
        self.lowercase_letters = string.ascii_lowercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    def generate_password(self, length=16, include_uppercase=True, 
                         include_lowercase=True, include_digits=True, 
                         include_special=True):
       
        if length < 8:
            length = 8  
        
        if not any([include_uppercase, include_lowercase, include_digits, include_special]):
            
            include_lowercase = True
        
        # Build character set
        char_set = ""
        if include_uppercase:
            char_set += self.uppercase_letters
        if include_lowercase:
            char_set += self.lowercase_letters
        if include_digits:
            char_set += self.digits
        if include_special:
            char_set += self.special_chars
        
        # Generate password
        password = ""
        for _ in range(length):
            password += secrets.choice(char_set)
        
        # Ensure password contains at least one character from each selected set to make it stronger
        if include_uppercase and not any(c in self.uppercase_letters for c in password):
            password = self.replace_random_char(password, self.uppercase_letters)
        
        if include_lowercase and not any(c in self.lowercase_letters for c in password):
            password = self.replace_random_char(password, self.lowercase_letters)
        
        if include_digits and not any(c in self.digits for c in password):
            password = self.replace_random_char(password, self.digits)
        
        if include_special and not any(c in self.special_chars for c in password):
            password = self.replace_random_char(password, self.special_chars)
        
        return password
    
    # replacing the random character in the password
    def replace_random_char(self, password, char_set):
        pos = secrets.randbelow(len(password))
        char = secrets.choice(char_set)
        return password[:pos] + char + password[pos+1:]
    
    # checking the password strength
    def check_password_strength(self, password):
        strength = 0
        feedback = []
        
        
        if len(password) < 8:
            feedback.append("Password is too short")
        elif len(password) >= 12:
            strength += 1
            feedback.append("Good length")
        
        
        if any(c in self.uppercase_letters for c in password):
            strength += 1
        else:
            feedback.append("Missing uppercase letters")
        
        if any(c in self.lowercase_letters for c in password):
            strength += 1
        else:
            feedback.append("Missing lowercase letters")
        
        if any(c in self.digits for c in password):
            strength += 1
        else:
            feedback.append("Missing digits")
        
        if any(c in self.special_chars for c in password):
            strength += 1
        else:
            feedback.append("Missing special characters")
        
        
        rating = "Too Weak"
        if strength >= 4:
            rating = "Strong"
        elif strength >= 2:
            rating = "Moderate"
        
        return {
            "score": strength,
            "rating": rating,
            "feedback": feedback
        }