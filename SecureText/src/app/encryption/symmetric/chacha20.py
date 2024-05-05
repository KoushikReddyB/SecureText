from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long")

    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext, nonce