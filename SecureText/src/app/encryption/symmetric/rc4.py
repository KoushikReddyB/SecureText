from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext
