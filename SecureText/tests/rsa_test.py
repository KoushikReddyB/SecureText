from src.app.encryption.asymmetric import rsa as rsa_encypt
from src.app.decryption.asymmetric import rsa as rsa_decrypt
from Crypto.PublicKey import RSA
from Crypto import Random

def test_rsa():
    message = "Hello, RSA algorithm!"
    key = RSA.generate(1024, Random.new().read)

    ciphertext = rsa_encypt.encrypt_message(message, key.publickey())
    decrypted_message = rsa_decrypt.decrypt_message(ciphertext, key)

    assert decrypted_message == message
    print("RSA encryption and decryption test passed!")

test_rsa()