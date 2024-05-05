from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_message(message, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), DES3.block_size))
    return ciphertext, cipher.iv

