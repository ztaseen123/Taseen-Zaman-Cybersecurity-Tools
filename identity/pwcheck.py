#!/usr/bin/env python3
import getpass
import math
import re

# List of common weak passwords (you can expand this)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "123123", "letmein", "welcome", "monkey", "admin"
}


def calculate_entropy(password):
    """Estimates the entropy of a password."""
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'\d', password):
        charset += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        charset += 32  # Approximate number of common special chars
    
    # Entropy = log2(charset^length) = length * log2(charset)
    return round(len(password) * math.log2(charset)) if charset > 0 else 0


def check_password_strength(password):
    """Check password strength and return score with feedback."""
    score = 0
    feedback = []
    
    # Check if password is in common passwords list
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("[-] Password is too common.")
        return score, feedback
    
    # Length checks
    if len(password) < 8:
        feedback.append("[-] Too short (min 8 chars).")
    elif len(password) < 12:
        feedback.append("[!] Decent length, but 12+ recommended.")
        score += 1
    else:
        feedback.append("[+] Good length.")
        score += 2
    
    # Character checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("[-] Add lowercase letters.")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("[-] Add uppercase letters.")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("[-] Add numbers.")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("[-] Add special characters.")
    
    # Calculate entropy and provide feedback
    entropy = calculate_entropy(password)
    if entropy < 28:
        feedback.append("[-] Very weak entropy.")
    elif entropy < 36:
        feedback.append("[!] Entropy could be higher.")
    else:
        feedback.append("[+] Good entropy.")
    
    # Overall strength assessment
    if score >= 6 and entropy >= 36:
        feedback.append("[+] Strong password!")
    elif score >= 4:
        feedback.append("[!] Medium strength password. Improve further!")
    else:
        feedback.append("[!] Weak password. Needs improvement.")
    
    return score, feedback


def main():
    """Main function to run the password checker."""
    print("=== Password Strength Checker ===")
    # getpass so it doesn't end up on screen or in scrollback
    password = getpass.getpass("Password to check: ")
    
    score, feedback = check_password_strength(password)
    
    print("\nFeedback:")
    for line in feedback:
        print(line)
    
    print(f"\nScore: {score}/7")


if __name__ == "__main__":
    main()
