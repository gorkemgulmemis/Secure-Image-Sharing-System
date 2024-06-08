import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

def generate_key_pair(filename=None):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    if filename:
        with open(filename, 'wb') as f:
            f.write(private_key)
    return public_key, private_key

def load_key(filename):
    with open(filename, 'rb') as f:
        key = RSA.import_key(f.read())
    return key

def encrypt_with_public_key(data, public_key):
    key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.encrypt(data)

def decrypt_with_private_key(encrypted_data, private_key):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.decrypt(encrypted_data)

def sign_data(data, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signer = pkcs1_15.new(key)
    return signer.sign(h)

def verify_signature(data, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    verifier = pkcs1_15.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def generate_aes_key():
    return get_random_bytes(16)

def encrypt_image(image_path, aes_key):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(image_path, 'rb') as file:
        plaintext = file.read()
    plaintext += bytes((16 - len(plaintext) % 16) * [16 - len(plaintext) % 16])
    encrypted = cipher.encrypt(plaintext)
    return encrypted, iv

def decrypt_image(encrypted_image, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_image)
    return plaintext.rstrip(b'\x10')

def generate_mac_key():
    return get_random_bytes(16)

def create_mac(message, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(message)
    return h.digest()

def verify_mac(message, mac, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(message)
    try:
        h.verify(mac)
        return True
    except ValueError:
        return False
