# src/decryption/symmetric/twofish.py
from Crypto.Cipher import Twofish
from Crypto.Util.Padding import unpad

def decrypt_message(ciphertext, key):
    cipher = Twofish.new(key)
    plaintext = unpad(cipher.decrypt(ciphertext), Twofish.block_size).decode()
    return plaintext
