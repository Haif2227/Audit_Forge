#!/usr/bin/env python3
import re

def check_password_policy(password):
    # Define password policy criteria
    min_length = 8
    has_uppercase = re.compile(r'[A-Z]')
    has_lowercase = re.compile(r'[a-z]')
    has_digit = re.compile(r'\d')
    has_special_char = re.compile(r'[!@#$%^&*(),.?":{}|<>]')

    if len(password) < min_length:
        return False
    if not has_uppercase.search(password):
        return False
    if not has_lowercase.search(password):
        return False
    if not has_digit.search(password):
        return False
    if not has_special_char.search(password):
        return False

    return True

def main():
    password = input("Enter the password to check: ")
    if check_password_policy(password):
        print("Password meets the policy requirements.")
    else:
        print("Password does not meet the policy requirements.")

if __name__ == "__main__":
    main()
