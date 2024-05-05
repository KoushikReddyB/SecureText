from Crypto.PublicKey import ElGamal
from Crypto import Random
from src.app.encryption.asymmetric import elgamal as elgamal_encrypt
from src.app.decryption.asymmetric import elgamal as elgamal_decrypt

def test_elgamal():
    message = "Hello, ElGamal algorithm !! "
    key = ElGamal.generate(1024, Random.new().read)

    ciphertext, nonce = elgamal_encrypt.encrypt_message(message, key.publickey())
    decrypted_message = elgamal_decrypt.decrypt_message(ciphertext, key, nonce)

    assert decrypted_message == message
    print("ElGamal encryption and decryption test passed!")

test_elgamal()
