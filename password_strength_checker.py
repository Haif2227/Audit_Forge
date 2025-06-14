#!/usr/bin/env python3
import re
import random
import string
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Common password list
common_passwords = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "password1", "111111"
]

def check_password_strength(password):
    """Evaluate password strength based on specific criteria."""
    length = len(password) >= 8
    uppercase = bool(re.search(r'[A-Z]', password))
    lowercase = bool(re.search(r'[a-z]', password))
    numbers = bool(re.search(r'\d', password))
    special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    return length, uppercase, lowercase, numbers, special

def score_password(password):
    """Score the password based on strength criteria."""
    length, uppercase, lowercase, numbers, special = check_password_strength(password)
    
    # Check if the password meets all required criteria
    if not all([uppercase, lowercase, numbers, special]):
        return "Low"
    
    score = sum([length, uppercase, lowercase, numbers, special])
    if score < 3:
        return "Weak"
    elif score < 5:
        return "Moderate"
    else:
        return "Strong"

def provide_feedback(password):
    """Provide suggestions to improve the password."""
    feedback = []
    if len(password) < 8:
        feedback.append("Increase password length to at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Add at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        feedback.append("Add at least one lowercase letter.")
    if not re.search(r'\d', password):
        feedback.append("Include at least one number.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append("Use special characters for more security.")
    return feedback

def is_common_password(password):
    """Check if the password is in the list of common passwords."""
    return password in common_passwords

def generate_secure_password():
    """Generate a secure password with random characters."""
    characters = (
        random.choices(string.ascii_uppercase, k=2) +
        random.choices(string.ascii_lowercase, k=4) +
        random.choices(string.digits, k=2) +
        random.choices(string.punctuation, k=2)
    )
    random.shuffle(characters)
    return ''.join(characters)

def main():
    """Main function to check password strength."""
    print("Welcome to the Password Strength Checker!")
    password = input("Enter your password: ")

    if is_common_password(password):
        print("\n[!] This password is too common and not secure!")
    else:
        strength = score_password(password)
        print("\nPassword Strength: ", end="")
        
        if strength == "Low":
            print(Fore.RED + strength)
        elif strength == "Weak":
            print(Fore.YELLOW + strength)
        elif strength == "Moderate":
            print(Fore.YELLOW + strength)
        elif strength == "Strong":
            print(Fore.GREEN + strength)

        if strength != "Strong":
            print("\nSuggestions to improve your password:")
            for suggestion in provide_feedback(password):
                print(f"- {suggestion}")

            # Suggest a secure password if the strength is low or weak
            secure_password = generate_secure_password()
            print(f"\nSuggested Secure Password: {secure_password}")

if __name__ == "__main__":
    main()
