from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_message(message, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), Blowfish.block_size))
    return ciphertext, cipher.iv
