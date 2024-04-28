import getpass
import math
import multiprocessing
import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

def encrypt_password(password, key):
    nonce = secrets.token_bytes(16)  # Generate a random nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return nonce + ciphertext

def decrypt_password(encrypted_password, key):
    nonce = encrypted_password[:16]
    ciphertext = encrypted_password[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_password.decode()

def encrypt_passphrase(passphrase):
    # Generate a random key
    key = os.urandom(32)
    # Generate a random nonce
    nonce = secrets.token_bytes(16)
    # ChaCha20 encryption
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(passphrase.encode()) + encryptor.finalize()
    return key, nonce, ciphertext

def decrypt_passphrase(key, nonce, ciphertext):
    # ChaCha20 decryption
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_passphrase = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_passphrase.decode()

def password_lengthextractor(password, result_queue):
    password_length = float(len(password))
    result_queue.put(password_length)

def passphrase_lengthextractor(passphrase, result_queue):
    # Count the number of whitespaces and add 1
    word_count = passphrase.count(' ') + 1
    result_queue.put(word_count)

def password_poolsize(password):
    lowercase = any(c.islower() for c in password)
    uppercase = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    special_chars = any(not c.isalnum() for c in password)
    whitespace = ' ' in password
    pool_size = 0
    if lowercase:
        pool_size += 26
    if uppercase:
        pool_size += 26
    if digits:
        pool_size += 10
    if special_chars:
        # Assuming special characters include punctuation, space, etc.
        pool_size += 32  # Adjust this number based on your specific requirements
    if whitespace:
        pool_size += 1
    return pool_size

def load_seclist1mil(seclist1mil_file):
    try:
        with open(seclist1mil_file, 'r') as f:
            seclist1mil_list = [line.strip() for line in f]
        return seclist1mil_list
    except Exception as e:
        print("Error loading seclist 1 million common passwords collection:", e)
        return []

def load_seclist100k(seclist100k_file):
    try:
        with open(seclist100k_file, 'r') as f:
            seclist100k_list = [line.strip() for line in f]
        return seclist100k_list
    except Exception as e:
        print("Error loading seclist 1 million common passwords collection:", e)
        return []

def load_diceware_list(diceware_file):
    try:
        with open(diceware_file, 'r') as f:
            diceware_list = [line.strip().split('\t') for line in f]
        return diceware_list
    except Exception as e:
        print("Error loading Diceware list:", e)
        return []

def password_entropycheck(password_length, pool_size, result_queue):
    password_entropy = password_length * math.log(pool_size, 2)
    result_queue.put(password_entropy)

def passphrase_entropycheck(word_count, result_queue):
    entropy = word_count * math.log(7776,2)
    result_queue.put(entropy)

def ratemypassword(password_entropy):
    if password_entropy < 64:
        print("\nRecommended to change your password immediately, it's very susceptible to a brute force attack!")
    elif 64 <= password_entropy < 80:
        print("\nMight withstand a bruteforce attack. A higher entropy would keep you safer.")
    elif 80 <= password_entropy < 100:
        print("\nGood password strength.")
    elif password_entropy >= 100:
        print("\nExcellent password strength!")

def ratemypassphrase(word_count):
    if word_count < 5:
        print("\nVery weak passphrase. Consider changing your passphrase.")
    elif word_count == 5:
        print("\nNot very suitable for sensitive data.")
    elif word_count == 6:
        print("\nSufficient strength for most data.")
    elif word_count == 7:
        print("\nGood passphrase strength.")
    elif word_count == 8:
        print("\nExcellent passphrase strength!")
    elif word_count > 8:
        print("\nYour passphrase will provide long-term protection!")

def passwordsuite(encrypted_password, key):
    # Decrypt password
    password = decrypt_password(encrypted_password, key)

    seclist1mil_file = "seclist1mil.txt"
    seclist1mil_list = load_seclist1mil(seclist1mil_file)
    seclist100k_file = "seclist100k.txt"
    seclist100k_list = load_seclist100k(seclist100k_file)
    
    if password not in seclist100k_list:
        # Create a queue for length result and entropy result
        length_queue = multiprocessing.Queue()
        entropy_queue = multiprocessing.Queue()
        
        # Create subprocess for length extraction
        length_process = multiprocessing.Process(target=password_lengthextractor, args=(password, length_queue))
        length_process.start()
        
        # Calculate password pool size
        pool_size = password_poolsize(password)
        
        # Join length process
        length_process.join()
        
        # Retrieve password length from the queue
        password_length = length_queue.get()
        
        # Create subprocess for entropy calculation
        entropy_process = multiprocessing.Process(target=password_entropycheck, args=(password_length, pool_size, entropy_queue))
        entropy_process.start()
        
        # Join entropy process
        entropy_process.join()
        
        # Retrieve entropy result from the queue
        entropy_measure = entropy_queue.get()
        
        print("Password Entropy is:", entropy_measure, "bits")
        ratemypassword(entropy_measure)
        
        if password in seclist1mil_list:
            print("\nYour password is among the most common 1 million passwords. You may consider changing it.")
    else:
        print("\nYour password is in the most common 100,000 passwords. Recommended to change immediately.")



def passphrasesuite(encrypted_passphrase):
    key, nonce, ciphertext = encrypted_passphrase
    # Decrypt passphrase
    passphrase = decrypt_passphrase(key, nonce, ciphertext)

    diceware_file = "wordlist.txt"
    diceware_list = load_diceware_list(diceware_file)
    
    passphrase_words = passphrase.split()
    try:
        for word in passphrase_words:
            if word not in [entry[1] for entry in diceware_list]:
                raise ValueError(f"The word '{word}' is not in the wordlist.")
        
        # Create a queue for length result and entropy result
        length_queue = multiprocessing.Queue()
        entropy_queue = multiprocessing.Queue()
        
        # Create subprocess for length extraction
        length_process = multiprocessing.Process(target=passphrase_lengthextractor, args=(passphrase, length_queue))
        length_process.start()
        
        # Join length process
        length_process.join()
        
        # Retrieve passphrase length from the queue
        passphrase_length = length_queue.get()
        
        # Create subprocess for entropy calculation
        entropy_process = multiprocessing.Process(target=passphrase_entropycheck, args=(passphrase_length, entropy_queue))
        entropy_process.start()
        
        # Join entropy process
        entropy_process.join()
        
        # Retrieve entropy result from the queue
        entropy_measure = entropy_queue.get()
        
        print("Passphrase Entropy is:", entropy_measure, "bits")
        ratemypassphrase(passphrase_length)
    except ValueError as e:
        print("\nError:", e)

def selector(choice):
    if choice == 1:
        password = getpass.getpass("Enter your password: ")
        key = os.urandom(32)  # Generate a random key
        encrypted_password = encrypt_password(password, key)
        passwordsuite(encrypted_password, key)
        # Securely delete password and key from memory
        password = None
        key = None
    elif choice == 2:
        passphrase = getpass.getpass("Enter your passphrase: ")
        encrypted_passphrase = encrypt_passphrase(passphrase)
        passphrasesuite(encrypted_passphrase)
        # Securely delete passphrase and key from memory
        passphrase = None
        encrypted_passphrase = None
    else:
        print("\nError: Selection not between 1 or 2. Exiting process.")


def main():
    print("Menu:\n")
    print("1. Password strength check (for passwords / passphrases not from the EFF diceware wordlist)  \n2. EFF Diceware passphrase strength check\n")
    num = int(input("Press the corresponding number to run the desired strength checker."))
    selector(num)

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