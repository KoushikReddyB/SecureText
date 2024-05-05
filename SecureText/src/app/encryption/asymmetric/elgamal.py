from Crypto.PublicKey import ElGamal
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(message, public_key):
    session_key = get_random_bytes(16)
    cipher_elgamal = ElGamal.construct((public_key.n, public_key.g))

    ciphertext = cipher_elgamal.encrypt(session_key, 0)[0]

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext += cipher_aes.encrypt(message.encode())
    return ciphertext, cipher_aes.nonce
