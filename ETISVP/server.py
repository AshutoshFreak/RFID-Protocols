import flask
import hashlib
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  
import requests
import os
from time import time
import struct


def encrypt(plaintext_bytes):
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePubKey = load_pem_public_key(open(CURR_DIR + '/server-rsapub.pem', 'rb').read(),default_backend())  
    ciphertext = alicePubKey.encrypt(  
        plaintext_bytes,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
        )  
    )
    return ciphertext


# Using RSA for Assymmetric encryption
def generate_key_pairs(secret_bytes):
    # Generate an RSA Keys  
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
    )
    public_key = private_key.public_key()

    # Get current working directory
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))

    # Save the RSA key in PEM format
    with open(CURR_DIR + "/server-rsakey.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(secret_bytes),
        )
    )

    # Save the Public key in PEM format
    with open(CURR_DIR + "/server-rsapub.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def concatenate_bytes(b1, b2):
    # SHA-1 gives 20 bytes output, hence range is 20
    for i in range(20):
        b1 += b2[i:i+1]
    return b1


def hash(byt):
    hash_object = hashlib.sha1(byt)
    hex_dig = hash_object.digest()
    return hex_dig


def s1(Kt_X_Z_T1_Nr):
    password = "reader-password"
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePrivKey = load_pem_private_key(open(CURR_DIR + '/reader-rsapub.pem', 'rb').read(),password,default_backend())  
    d = alicePrivKey.decrypt(  
        Kt_X_Z_T1_Nr,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
    )
    )
    delta_t = 0
    X = b'0' # Extraction of X from d incomplete
    Z = b'0' # Extraction of Z from d incomplete
    T1 = b'0' # Extraction of T1 from d incomplete
    Nr = b'0' # Extraction of Nr from d incomplete
    Ht = b'0' ## Retrieve from database
    Vj = b'0' ## Retrieve from database
    H_Vj = b'0' ## Retrieve from database
    Nt = b'0' ## Retrieve from database
    data = b'0' ### Data that needs to be transfered

    T2 = struct.pack(">i", int(time()))
    if delta_t > T2-T1:
        N_star_t = X ^ (concatenate_bytes(H_Vj, Ht))
        temp = concatenate_bytes(concatenate_bytes(Ht, Nr), N_star_t)
        Z_star = hash(X^hash(temp)^Nt^T1)
        temp = concatenate_bytes(concatenate_bytes(Ht, Nr), Nt)
        W = hash(X ^ hash(temp) ^ T2 ^ Vj)
        if Z_star == Z:
            temp = concatenate_bytes(data, W)
            return encrypt(temp)
            # Contact reader. Call r3
        else:
            return 1
    else:
        return 1


password = "server-password"
generate_key_pairs(password.encode())