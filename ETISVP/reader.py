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


# returns random bytes of length "n"
def get_random_bytes(n):
    return os.urandom(n)


# Using sha1 for hash
# Returns hash bytes given bytes bytes
def hash(byt):
    hash_object = hashlib.sha1(byt)
    hex_dig = hash_object.digest()
    return hex_dig


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
    with open(CURR_DIR + "/reader-rsakey.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(secret_bytes),
        )
    )

    # Save the Public key in PEM format
    with open(CURR_DIR + "/reader-rsapub.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

def encrypt(plaintext_bytes):
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePubKey = load_pem_public_key(open(CURR_DIR + '/reader-rsapub.pem', 'rb').read(),default_backend())  
    ciphertext = alicePubKey.encrypt(  
        plaintext_bytes,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
        )  
    )
    return ciphertext


def connect(to_call, param, device):
    if device == 'tag':
        port = 8002
    else:
        port = 8000
    adr = f'http://localhost:{port}/{to_call}/{param}'
    requests.get(url=adr)


def concatenate_bytes(b1, b2):
    # SHA-1 gives 20 bytes output, hence range is 20
    for i in range(20):
        b1 += b2[i:i+1]
    return b1


def r2(Kt_X_Z_T1):
    password = "tag-password"
    global Nr
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePrivKey = load_pem_private_key(open(CURR_DIR + '/tag-rsapub.pem', 'rb').read(),password,default_backend())  
    d = alicePrivKey.decrypt(  
        Kt_X_Z_T1,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
    )
    )
    return concatenate_bytes(d, Nr)
    # contact server. Call function s1


def r3(Kd_DATA_W):
    password = "server-password"
    CURR_DIR = os.path.dirname(os.path.realpath(__file__))
    alicePrivKey = load_pem_private_key(open(CURR_DIR + '/server-rsapub.pem', 'rb').read(),password,default_backend())  
    d = alicePrivKey.decrypt(  
        Kd_DATA_W,  
        padding.OAEP(  
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                algorithm=hashes.SHA256(),  
                label=None  
    )
    )
    data = b'0' # Extract data from Kd_DATA_W
    W = b'0' # Extract data from Kd_DATA_W
    # This returning needs to be done to Tag. call t2
    return encrypt(W)



password = "reader-password"
generate_key_pairs(password.encode())

random_length = 5

####### Protocol Starts #######

Nr = get_random_bytes(random_length)
KNr = str(encrypt(Nr))
# KNr = encrypt(Nr).decode('cp437')
print(KNr)
connect("t1", KNr, 'tag')

# app = flask.Flask(__name__)
# app.run(host='localhost', port=8080)
