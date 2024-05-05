from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    return plaintext
