from Crypto.Cipher import AES
from Crypto.PublicKey import ElGamal

def decrypt_message(ciphertext, private_key, nonce):
    # Create ElGamal object using private key
    cipher_elgamal = ElGamal.construct((private_key.n, private_key.g, private_key.x))
    
    session_key = cipher_elgamal.decrypt(ciphertext[:private_key.size_in_bytes()])

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt(ciphertext[private_key.size_in_bytes():])
    return plaintext.decode()
