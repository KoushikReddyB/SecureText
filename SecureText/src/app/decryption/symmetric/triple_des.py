from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

def decrypt_message(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size).decode()
    return plaintext