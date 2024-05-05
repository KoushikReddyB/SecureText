from Crypto.Cipher import ChaCha20

def decrypt_message(ciphertext, key, nonce):
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long")

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext
