from src.app.encryption.symmetric import blowfish as blowfish_encrypt
from src.app.decryption.symmetric import blowfish as blowfish_decrypt
from Crypto.Random import get_random_bytes

def test_blowfish():
    message = "Heyyy This is Blowfish Algorithm!"
    key = get_random_bytes(16)  # 16 bytes 

    ciphertext, iv = blowfish_encrypt.encrypt_message(message, key)
    decrypted_message = blowfish_decrypt.decrypt_message(ciphertext, key, iv)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
    assert decrypted_message == message
    print("Encryption and decryption test passed!")

test_blowfish()