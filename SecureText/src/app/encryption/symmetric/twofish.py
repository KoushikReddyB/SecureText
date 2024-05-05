from Cryptodome.Cipher import Twofish
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

def encrypt_message(message, key):
    cipher = Twofish.new(key)
    ciphertext = cipher.encrypt(pad(message.encode(), cipher.block_size))
    return ciphertext