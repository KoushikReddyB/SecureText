from src.app.encryption.symmetric import triple_des as triple_des_encrypt
from src.app.decryption.symmetric import triple_des as triple_des_decrypt
from Crypto.Random import get_random_bytes

def test_aes_encryption():
    message = "Hello, 3DES!"
    key = get_random_bytes(16)  # 16 bytes for AES-128

    ciphertext, iv = triple_des_encrypt.encrypt_message(message, key)
    decrypted_message = triple_des_decrypt.decrypt_message(ciphertext, key, iv)

    assert decrypted_message == message
    print("Encryption and decryption test passed!")
