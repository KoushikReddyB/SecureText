from src.app.encryption.symmetric import twofish as twofish_encrypt
from src.app.decryption.symmetric import twofish as twofish_decrypt
from Crypto.Random import get_random_bytes

def test_twofish():
    message = "Let's see who is fishy here ;)"
    key = get_random_bytes(16)  # 16 bytes for AES-128

    ciphertext, iv = twofish_encrypt.encrypt_message(message, key)
    decrypted_message = twofish_decrypt.decrypt_message(ciphertext, key, iv)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
    assert decrypted_message == message
    print("Encryption and decryption test passed!")

test_twofish()