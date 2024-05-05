from src.app.encryption.symmetric import aes as aes_encrypt
from src.app.decryption.symmetric import aes as aes_decrypt
from Crypto.Random import get_random_bytes

def test_aes():
    message = "Hello, AES!"
    key = get_random_bytes(16)  # 16 bytes for AES-128

    ciphertext, iv = aes_encrypt.encrypt_message(message, key)
    decrypted_message = aes_decrypt.decrypt_message(ciphertext, key, iv)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
    assert decrypted_message == message
    print("Encryption and decryption test passed!")

test_aes()