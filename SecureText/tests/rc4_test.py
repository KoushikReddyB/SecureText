from src.app.encryption.symmetric import rc4 as rc4_encrypt
from src.app.decryption.symmetric import rc4 as rc4_decrypt
from Crypto.Random import get_random_bytes

def test_rc4():
    message = "This is RC4 algorithm"
    key = get_random_bytes(16)  # 16 bytes

    ciphertext = rc4_encrypt.encrypt_message(message, key)
    decrypted_message = rc4_decrypt.decrypt_message(ciphertext, key)

    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
    
    assert decrypted_message == message
    print("Encryption and decryption test passed!")

test_rc4()