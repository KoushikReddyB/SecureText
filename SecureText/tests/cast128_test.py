from src.app.encryption.symmetric import cast128 as cast128_encrypt
from src.app.decryption.symmetric import cast128 as cast128_decrypt
from Crypto.Random import get_random_bytes

def test_cast128():
    message = "Hello, this is  CAST-128!"
    key = get_random_bytes(16)  # 16 bytes for CAST-128

    ciphertext = cast128_encrypt.encrypt_message(message, key)
    decrypted_message = cast128_decrypt.decrypt_message(ciphertext, key)

    assert decrypted_message == message
    print("CAST-128 encryption and decryption test passed!")
