from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad

def decrypt_message(ciphertext, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size).decode()
    return plaintext
