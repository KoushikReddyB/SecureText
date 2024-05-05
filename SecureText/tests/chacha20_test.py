from src.app.encryption.symmetric import chacha20 as chacha20_encrypt
from src.app.decryption.symmetric import chacha20 as chacha20_decrypt
from Crypto.Random import get_random_bytes

def test_chacha20():
    message = "This is chacha20 algorithm, sounds funny lol"
    key = get_random_bytes(32)  # 32 bytes only

    ciphertext, nonce = chacha20_encrypt.encrypt_message(message, key)
    decrypted_message = chacha20_decrypt.decrypt_message(ciphertext, key, nonce)

    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
    
    assert decrypted_message == message
    print("Encryption and decryption test passed!")

test_chacha20()