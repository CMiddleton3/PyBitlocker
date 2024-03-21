import subprocess
import argparse
import os
import sys
import ctypes
from cryptography.fernet import Fernet

# Function to generate a key for encryption/decryption
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a password using a given key
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Function to decrypt a password using a given key
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Function to save an encrypted password to a file
def save_password_to_file(password, file_path, key):
    encrypted_password = encrypt_password(password, key)
    with open(file_path, 'wb') as file:
        file.write(encrypted_password)

# Function to load an encrypted password from a file
def load_password_from_file(file_path, key):
    with open(file_path, 'rb') as file:
        encrypted_password = file.read()
    return decrypt_password(encrypted_password, key)

def lock_bitlocker(drive_letter, force_dismount, save_password):
    # Validate the drive letter format (assuming it should be a single uppercase letter)
    if not drive_letter.isalpha()  or len(drive_letter) != 1:
        print("Invalid drive letter format. Please provide a single uppercase letter.")
        return

    # Check if the drive exists
    drive_path = f"{drive_letter}:"
    # if not os.path.isdir(drive_path):
    #     print(f"Drive {drive_letter} does not exist.")
    #     return

    # Build the manage-bde command
    command = ["manage-bde.exe", "-lock", drive_path]
    if force_dismount:
        command.append("-ForceDismount")

    # Execute the command
    try:
        subprocess.run(command, check=True)
        print("BitLocker drive locked successfully.")
        if save_password:
            password = input("Enter the BitLocker password: ")
            key = generate_key()
            save_password_to_file(password, f"{drive_letter}_password.txt", key)
            print(f"Password saved to {drive_letter}_password.txt (encrypted with key).")
    except subprocess.CalledProcessError as e:
        print(f"Failed to lock BitLocker drive. Error: {e}")

def unlock_bitlocker(drive_letter, save_password):
    # Validate the drive letter format (assuming it should be a single uppercase letter)
    if not drive_letter.isalpha()  or len(drive_letter) != 1:
        print("Invalid drive letter format. Please provide a single uppercase letter.")
        return

    # Check if the drive exists
    drive_path = f"{drive_letter}:"
    # if not os.path.isdir(drive_path):
    #     print(f"Drive {drive_letter} does not exist.")
    #     return

    # Build the manage-bde command
    command = ["manage-bde.exe", "-unlock", drive_path]

    # Execute the command
    try:
        subprocess.run(command, check=True)
        print("BitLocker drive unlocked successfully.")
        if save_password:
            password = input("Enter the new BitLocker password: ")
            key = generate_key()
            save_password_to_file(password, f"{drive_letter}_password.txt", key)
            print(f"New password saved to {drive_letter}_password.txt (encrypted with key).")
    except subprocess.CalledProcessError as e:
        print(f"Failed to unlock BitLocker drive. Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lock or unlock BitLocker drive using manage-bde.exe.")
    parser.add_argument("drive_letter", help="Drive letter to lock or unlock (e.g., D)")
    parser.add_argument("-f", "--force_dismount", action="store_true", help="Force dismount the drive (only for lock operation)")
    parser.add_argument("--unlock", action="store_true", help="Unlock the BitLocker drive")
    parser.add_argument("--save_password", action="store_true", help="Save the BitLocker password (encrypted) to a file")
    
    args = parser.parse_args()


    # try:
    #     if ctypes.windll.shell32.IsUserAnAdmin():
    #         print("Running as Admin")
    # except AttributeError as e:      
       
    #     print("Scripts need to be ran using Admin Privilege")
    #     # raise AdminStateUnknownError
    #     exit (1)
    
    if args.unlock:
        unlock_bitlocker(args.drive_letter, args.save_password)
    else:
        lock_bitlocker(args.drive_letter, args.force_dismount, args.save_password)
