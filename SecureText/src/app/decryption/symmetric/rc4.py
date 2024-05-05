from Crypto.Cipher import ARC4

def decrypt_message(ciphertext, key):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext
