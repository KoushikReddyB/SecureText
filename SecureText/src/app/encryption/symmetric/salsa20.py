from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext, nonce
