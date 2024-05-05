from src.app.encryption.symmetric import salsa20 as salsa20_encrypt
from src.app.decryption.symmetric import salsa20 as salsa20_decrypt
from Crypto.Random import get_random_bytes

def test_salsa20():
    message = "Hello, Salsa20!"
    key = get_random_bytes(32)  # 32 bytes for Salsa20

    ciphertext, nonce = salsa20_encrypt.encrypt_message(message, key)
    decrypted_message = salsa20_decrypt.decrypt_message(ciphertext, key, nonce)

    assert decrypted_message == message
    print("Salsa20 encryption and decryption test passed!")

test_salsa20()