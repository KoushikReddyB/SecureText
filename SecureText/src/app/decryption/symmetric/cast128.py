from Crypto.Cipher import CAST
from Crypto.Util.Padding import unpad

def decrypt_message(ciphertext, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 8).decode()  # 8-byte block size for CAST-128
    return plaintext