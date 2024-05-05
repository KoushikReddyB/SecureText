from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_message(message, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), 8))  # 8-byte block size for CAST-128
    return ciphertext