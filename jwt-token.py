import jwt

# key = "secret"

def encoding(token):
    encoded = jwt.encode(token, "secret", algorithm="HS256")
    return encoded

def decoding(decodedmessage):
    decoded = jwt.decode(decodedmessage, "secssret", algorithms="HS256")    
    return decoded

data = encoding({"username": "shreya", "password": "s123"})
print("encoded data", data)

decoded_data = decoding(data)
print("decoded data", decoded_data)

