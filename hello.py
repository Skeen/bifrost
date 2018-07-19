#public const string GET_LOGINS = "get-logins";
#public const string GET_LOGINS_COUNT = "get-logins-count";
#public const string GET_ALL_LOGINS = "get-all-logins";
#public const string SET_LOGIN = "set-login";
#public const string ASSOCIATE = "associate";
#public const string TEST_ASSOCIATE = "test-associate";
#public const string GENERATE_PASSWORD = "generate-password";

# Depends on:
# * pycryptodome

from flask import Flask
from flask import request
from flask import jsonify
app = Flask(__name__)

import hashlib
sha_1 = hashlib.sha1()
sha_1.update("bifrost")
database_hash = sha_1.hexdigest()
print "Our hash is: " + database_hash

database_identifier = ""


def test_associate(data, reply):
    """This endpoint is simply used to check that we are alive."""
    reply["Success"] = True

def test_request_verifier(data, key):
    """Validates that the provided key + nonce is good.
    
    This is done by decrypting the 'Verifier' field using the key+nonce, and
    checking that the result is the nonce itself.
    """
    print "test_request_verifier called"
    import base64
    success = False
    crypted = base64.b64decode(data['Verifier'])

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    key = base64.b64decode(data['Key'])
    iv = base64.b64decode(data['Nonce'])
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(crypted).decode("utf-8"), 16)
    nonce = data['Nonce'].strip()
    print "Decrypted:\t" + decrypted
    print "Nonce:\t\t" + nonce
    return decrypted == nonce

def set_response_verifier(data, reply):
    """Generate a random new nonce, and encrypt it for verification."""
    print "set_response_verifier called"
    import os
    import base64
    reply['Nonce'] = base64.b64encode(os.urandom(16))

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    key = base64.b64decode(data['Key'])
    iv = base64.b64decode(data['Nonce'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(reply['Nonce'], 16))
    reply['Verifier'] = base64.b64encode(ciphertext)


def associate(data, reply):
    print "associate called"

    # Check that the provided key+nonce is good
    if not test_request_verifier(data, data['Key']):
        return
    print "Passed key check"

    # Keepasshttp does a lot of gui work here, boils down to getting a key id
    global database_identifier
    database_identifier = 'cafebabe'
    print database_identifier

    # TODO: Thi is probably to associate the user_input_id with our internal database
    # entry.Strings.Set(ASSOCIATE_KEY_PREFIX + f.KeyId, new ProtectedString(true, r.Key));
    # entry.Touch(true);
    reply["Success"] = True
    reply["Id"] = database_identifier
    
    # set_response_verifier(data, reply)

def reverse_engineer(data, reply):
    print "reverse_engineer called"
    print data
    raise NotImplemented("WOW")

@app.route("/", methods=['GET', 'POST'])
def root():
    print request.data
    data = request.get_json()
    request_type = data['RequestType']
    reply = {
        "Count": None,
        "Entries": None,
        "Error": "",
        "Hash": database_hash,
        "Id": database_identifier,
        "Nonce": "",
        "RequestType": request_type,
        # We need to reply with a recent version, or browser plugin won't load
        "Version": "1.8.4.2",  
        "Success": False,
        "Verifier": "",

    }
    status_code = 200

    switch_dict = {
        'test-associate': test_associate,
        'associate': associate,
    }
    
    try:
        if request_type in switch_dict:
            switch_dict[data['RequestType']](data, reply)
        else:
            reverse_engineer(data, reply)
    except Exception as exception:
        print "EXCEPTION: " + str(exception)
        reply['Error'] = str(exception)
        status_code = 400
        
    print "replying with: " + str(reply)
    return jsonify(reply), status_code
