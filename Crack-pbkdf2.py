import hashlib
import base64
import os
from tqdm import tqdm

class PasswordEncryptor:
    def __init__(self, hash_type="sha256", pbkdf2_iterations=600000):

        self.hash_type = hash_type
        self.pbkdf2_iterations = pbkdf2_iterations

    def crypt_bytes(self, salt, value):

        hashed_bytes = hashlib.pbkdf2_hmac(
            self.hash_type,               # Hash type (e.g., sha256)
            value,                        
            salt.encode('utf-8'),         # Salt (as bytes)
            self.pbkdf2_iterations        # Number of iterations
        )
        return hashed_bytes.hex()

# Example usage
hash_type = "sha256"
iterations = 600000
salt = "YnRgjnim"
search_hash = "c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed"
wordlist = '<wordlist>'

encryptor = PasswordEncryptor(hash_type, iterations)


total_lines = sum(1 for _ in open(wordlist, 'r', encoding='latin-1'))


with open(wordlist, 'r', encoding='latin-1') as password_list:
    for password in tqdm(password_list, total=total_lines, desc="Processing"):
        value = password.strip()
        
        # Get the encrypted password
        hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))
        
        # Compare with the search hash
        if hashed_password == search_hash:
            print(f'Found Password: {value}, hash: {hashed_password}')
            break  
