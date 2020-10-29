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

app = flask.Flask(__name__)
app.run(host='localhost', port=8002)
random_length = 5
T1 = b'0' # Timer, needs to be initialised everytime return is made
Y = b'0'
h1 = b'0'
h2 = b'0'

######## Test secret value (need to be changed) ########
V = "10".encode()
########################################################

T = "1".encode() # Test tag identity value (need to be changed)


def get_random_bytes(n):
    return os.urandom(n)


def hash(byt):
    hash_object = hashlib.sha1(byt)
    hex_dig = hash_object.digest()
    return hex_dig


def concatenate_bytes(b1, b2):
    # SHA-1 gives 20 bytes output, hence range is 20
    for i in range(20):
        b1 += b2[i:i+1]
    return b1


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
    with open(CURR_DIR + "/tag-rsakey.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(secret_bytes),
        )
    )

    # Save the Public key in PEM format
    with open(CURR_DIR + "/tag-rsapub.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def encrypt(plaintext_bytes):
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePubKey = load_pem_public_key(open(CURR_DIR + '/tag-rsapub.pem', 'rb').read(),default_backend())  
    ciphertext = alicePubKey.encrypt(  
        plaintext_bytes,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
        )  
    )
    return ciphertext


def t2(Kr_W):
    global V
    global T1
    global T3
    global Nr
    global Nt
    password = "reader-password"
    delta_t = 0
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePrivKey = load_pem_private_key(open(CURR_DIR + '/reader-rsapub.pem', 'rb').read(),password,default_backend())  
    W = alicePrivKey.decrypt(  
        Kr_W,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
    )
    )
    T3 = struct.pack(">i", int(time()))
    # How in the world would I know T2>? It was calculated in the server
    # Taking T1
    if delta_t > T3-T1:
        W_star = hash(Y^h1^T1)
        if W_star == W:
            V = hash(hash(V)^Nr^Nt)
        else:
            return 1
    else:
        return 1



@app.route('/t1/<KNr>', methods=['GET'])
def t1(KNr):
    global T1
    global Y
    global Nr
    global Nt
    # data not received properly both as bytes or string
    password = "reader-password"
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePrivKey = load_pem_private_key(open(CURR_DIR + '/reader-rsapub.pem', 'rb').read(),password,default_backend())  
    Nr = alicePrivKey.decrypt(  
        KNr,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
    )
    )
    Nt = get_random_bytes(random_length)
    h1 = hash(V)
    h2 = hash(T)
    X = (concatenate_bytes(h1, h2)) ^ Nt
    Y = X ^ hash(concatenate_bytes(concatenate_bytes(h2, Nr), Nt))
    curTime = int(time())
    T1 = struct.pack(">i", curTime)
    Z = hash(Y ^ T1 ^ Nt)
    encrypt(Z)
    # send back to reader. Call function r2


password = "tag-password"
generate_key_pairs(password.encode())