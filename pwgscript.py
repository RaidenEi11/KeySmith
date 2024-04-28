import string
import secrets
import multiprocessing
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math
import sys
import os

def generate_password(length, result_queue, shared_array, encryption_key, seclist_list):
    try:
        characters = string.ascii_letters + string.digits + string.punctuation
        while True:
            password_string = ''.join(secrets.choice(characters) for _ in range(length))
            # Check if the generated password is in the list of common passwords
            if password_string not in seclist_list:
                break
        entropy = calculate_entropy(password_string, length)
        encrypted_password = encrypt_password(password_string, encryption_key)
        result_queue.put((encrypted_password, entropy))
        # Clear password from memory
        for i in range(len(shared_array)):
            shared_array[i] = 0
    except Exception as e:
        print("Error in password generation:", e)


def display_password(result_queue, encryption_key):
    try:
        encrypted_password, entropy = result_queue.get()
        decrypted_password = decrypt_password(encrypted_password, encryption_key)
        print("Decrypted password:", decrypted_password)
        print("Entropy:", entropy)
        # Delete the encryption key from memory
        del encryption_key
    except Exception as e:
        print("Error in displaying password:", e)

def load_seclist(seclist_file):
    try:
        with open(seclist_file, 'r') as f:
            seclist_list = [line.strip() for line in f]
        return seclist_list
    except Exception as e:
        print("Error loading seclist common password collection:", e)
        return []

def encrypt_password(password, encryption_key):
    backend = default_backend()
    nonce = secrets.token_bytes(16)  # Generate a random nonce
    cipher = Cipher(algorithms.ChaCha20(encryption_key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return nonce + ciphertext

def decrypt_password(encrypted_password, encryption_key):
    backend = default_backend()
    nonce = encrypted_password[:16]
    ciphertext = encrypted_password[16:]
    cipher = Cipher(algorithms.ChaCha20(encryption_key, nonce), mode=None, backend=backend)
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_password.decode()

def calculate_entropy(password, password_length):
    entropy = password_length * math.log(94,2)
    return entropy

def cleanup_resources(password_process, display_process):
    if password_process.is_alive():
        password_process.terminate()
    if display_process.is_alive():
        display_process.terminate()

def main():
    try:
        seclist_file = "seclist1mil.txt"  # Path to your seclist word list file
        seclist_list = load_seclist(seclist_file)
        encryption_key = secrets.token_bytes(32)  # 256-bit key for ChaCha20

        while True:
            try:
                password_length = int(input("Enter password length: "))
                if password_length <= 0:
                    print("password length must be a natural number.")
                    continue
                break  
            except ValueError:
                print("Invalid input. Please enter a valid integer for password length.")

        result_queue = multiprocessing.Queue()
        shared_array = multiprocessing.Array(ctypes.c_int, password_length)

        password_process = multiprocessing.Process(target=generate_password, args=(password_length, result_queue, shared_array, encryption_key, seclist_list))
        display_process = multiprocessing.Process(target=display_password, args=(result_queue, encryption_key))

        password_process.start()
        display_process.start()

        password_process.join()
        display_process.join()

        input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("Process interrupted by user.")
    finally:
        cleanup_resources(password_process, display_process)

if __name__ == "__main__":
    main()

# Clean up bytecode files after execution
if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    # Running inside a virtual environment
    bytecode_dir = os.path.join(sys.prefix, 'lib', 'python' + sys.version[:3], '__pycache__')
else:
    # Running outside a virtual environment
    bytecode_dir = os.path.join(sys.prefix, 'lib', '__pycache__')

# Delete all bytecode files in the directory
for filename in os.listdir(bytecode_dir):
    if filename.endswith('.pyc'):
        os.remove(os.path.join(bytecode_dir, filename))