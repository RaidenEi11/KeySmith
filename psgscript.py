import secrets
import multiprocessing
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math
import sys
import os

def generate_passphrase(diceware_list, passphrase_length, result_queue, shared_array, encryption_key):
    try:
        passphrase = []
        while len(passphrase) < passphrase_length:
            dice_roll = [str(secrets.SystemRandom().randrange(1, 7)) for _ in range(5)]
            dice_key = ''.join(dice_roll)
            for item in diceware_list:
                if item[0] == dice_key:
                    passphrase.append(item[1])
                    break
        passphrase_str = ' '.join(passphrase[:passphrase_length])
        entropy = calculate_entropy(passphrase_str, passphrase_length)
        encrypted_passphrase = encrypt_passphrase(passphrase_str, encryption_key)
        result_queue.put((encrypted_passphrase, entropy))
        # Clear passphrase from memory
        for i in range(len(shared_array)):
            shared_array[i] = 0
    except Exception as e:
        print("Error in passphrase generation:", e)

def display_passphrase(result_queue, encryption_key):
    try:
        encrypted_passphrase, entropy = result_queue.get()
        decrypted_passphrase = decrypt_passphrase(encrypted_passphrase, encryption_key)
        print("Decrypted passphrase:", decrypted_passphrase)
        print("Entropy:", entropy)
        # Delete the encryption key from memory
        del encryption_key
    except Exception as e:
        print("Error in displaying passphrase:", e)


def load_diceware_list(diceware_file):
    try:
        with open(diceware_file, 'r') as f:
            diceware_list = [line.strip().split('\t') for line in f]
        return diceware_list
    except Exception as e:
        print("Error loading Diceware list:", e)
        return []

def encrypt_passphrase(passphrase, encryption_key):
    backend = default_backend()
    nonce = secrets.token_bytes(16)  # Generate a random nonce
    cipher = Cipher(algorithms.ChaCha20(encryption_key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(passphrase.encode()) + encryptor.finalize()
    return nonce + ciphertext

def decrypt_passphrase(encrypted_passphrase, encryption_key):
    backend = default_backend()
    nonce = encrypted_passphrase[:16]
    ciphertext = encrypted_passphrase[16:]
    cipher = Cipher(algorithms.ChaCha20(encryption_key, nonce), mode=None, backend=backend)
    decryptor = cipher.decryptor()
    decrypted_passphrase = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_passphrase.decode()

def calculate_entropy(passphrase, passphrase_length):
    entropy = passphrase_length * math.log(7776,2)
    return entropy

def cleanup_resources(passphrase_process, display_process):
    if passphrase_process.is_alive():
        passphrase_process.terminate()
    if display_process.is_alive():
        display_process.terminate()

def main():
    try:
        diceware_file = "wordlist.txt"  # Path to your Diceware word list file
        diceware_list = load_diceware_list(diceware_file)

        encryption_key = secrets.token_bytes(32)  # 256-bit key for ChaCha20

        while True:
            try:
                passphrase_length = int(input("Enter passphrase length: "))
                if passphrase_length <= 0:
                    print("Passphrase length must be a natural number.")
                    continue
                break  
            except ValueError:
                print("Invalid input. Please enter a valid integer for passphrase length.")

        result_queue = multiprocessing.Queue()
        shared_array = multiprocessing.Array(ctypes.c_int, passphrase_length)

        passphrase_process = multiprocessing.Process(target=generate_passphrase, args=(diceware_list, passphrase_length, result_queue, shared_array, encryption_key))
        display_process = multiprocessing.Process(target=display_passphrase, args=(result_queue, encryption_key))

        passphrase_process.start()
        display_process.start()

        passphrase_process.join()
        display_process.join()

        input("Press Enter to exit...")
    except KeyboardInterrupt:
        print("Process interrupted by user.")
    finally:
        cleanup_resources(passphrase_process, display_process)

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