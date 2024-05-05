from Crypto.Cipher import Salsa20

def decrypt_message(ciphertext, key, nonce):
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext
