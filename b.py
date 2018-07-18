#!/usr/bin/env python
import base64
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = None
public_key = None
with open("/home/skeen/.ssh/id_rsa", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()

def encrypt(message):
    cipher = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher

def decrypt(ciphertext):
    plain = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain

def sign(message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# TODO: We need to filter public keys by group / permissions
r = requests.get('http://localhost:8000/api/public_key/', auth=('ubsadmin', 'ubsadmin'))
print r
print r.json()

password = 'Methodic12884'
# TODO: Encrypt and sign a list (one per user).
encrypted_password = encrypt(password)
signature = sign(encrypted_password)

encoded_password = base64.b64encode(encrypted_password)
encoded_signature = base64.b64encode(signature)
print "Encoded Password: " + encoded_password
print "Encoded Signature: " + encoded_signature

payload = {
    "url": "google.dk",
    "passwords_write": [
        {
            'user_pk': 1,
            'password': encoded_password,
            'signature': encoded_signature,
        },
    ],
    "title": "My gmail login",
    "username": "emil@magenta.dk",
    "notes": "Please don't misuse this"
}
r = requests.post('http://localhost:8000/api/keyentry/', auth=('ubsadmin', 'ubsadmin'), json=payload)
print "---------------"
print "POSTED PASSWORD"
print "---------------"
print r
print r.json()
print ""

password_url = r.json()['passwords'][0]['url']

r = requests.get(password_url, auth=('ubsadmin', 'ubsadmin'))
print "-----------------"
print "GOT PASSWORD BACK"
print "-----------------"
print r
print r.json()
print ""
json = r.json()
incoming_encoded_password = json['password']
print incoming_encoded_password
# assert encoded_password == incoming_encoded_password
incoming_encrypted_password = base64.b64decode(incoming_encoded_password)
# assert encrypted_password == incoming_encrypted_password

incoming_password = decrypt(incoming_encrypted_password)
print incoming_password
assert incoming_password == password
