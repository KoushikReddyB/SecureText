from Crypto.Cipher import PKCS1_OAEP

def decrypt_message(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext).decode()
    return plaintext
