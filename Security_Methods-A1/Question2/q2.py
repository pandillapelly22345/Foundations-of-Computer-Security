import base64
import hmac
import json
import binascii
import string

def decode(input_str):
    a = (4 - len(input_str) % 4)
    input_str += "=" * ( a% 4) 
    return base64.urlsafe_b64decode(input_str).decode()


def split_jwt(token):
    return token.split(".")

def JwtVerification(header_1, payload_1, signature_1, secret):

    header = json.loads(decode(header_1))
    payload = json.loads(decode(payload_1))

    scrt = secret.encode('utf-8')
    message = f"{header_1}.{payload_1}".encode('utf-8')

    L = ["HS256", "HS512"]
    if header["alg"] not in L:
        print("algorithm not available!!!!")

    if header["alg"] == "HS256":
        expectedSignHex = hmac.new(scrt, message, "sha256").hexdigest().upper()
    elif header["alg"] == "HS512":
        expectedSignHex = hmac.new(scrt, message, "sha512").hexdigest().upper()

    expectedSignByte = binascii.unhexlify(expectedSignHex)  

    expected_signature_b64 = base64.urlsafe_b64encode(expectedSignByte).decode().rstrip("=")

    if expected_signature_b64 != signature_1: 
        print("Invalid signature")

    print("Valid signature")
    return payload

token = input("Enter JWT token: ")

header_1, payload_1, signature_1 = split_jwt(token)

decoded_payload = decode(payload_1)
print("\nDecoded JWT Payload:")
print(json.dumps(json.loads(decoded_payload), indent=4))

charset = string.ascii_lowercase + string.digits
common_secrets = []
for a in charset:
    for b in charset:
        for c in charset:
            for d in charset:
                for e in charset:
                    common_secrets.append(a + b + c + d + e)

# common_secrets = ["p1gzy", "12345", "qwdfr", "hgtre", "yubdf"]



found_secret = None
for secret in common_secrets:
    message = f"{header_1}.{payload_1}".encode('utf-8')
    se = secret.encode('utf-8')

    calculated_signature = hmac.new(se, message, "sha256").hexdigest().upper()
    calculated_signature_b64 = base64.urlsafe_b64encode(binascii.unhexlify(calculated_signature)).decode().rstrip("=")

    if calculated_signature_b64 == signature_1:
        found_secret = secret
        print(f"Secret found: {secret}")
        break

if not found_secret:
    print("No valid secret found")

# Verify JWT with the found secret
print(JwtVerification(header_1, payload_1, signature_1, found_secret))

#-----------------------------------------------------------------------------------------------------------------
# Creating a new JWT 
print("Algos Available : HS256, HS512")
algo = input("Enter the algorithm you want to use to create new Jwt: ")
secret1 = secret 
payload = {"sub": "fcs-assignment-1", "iat": 1516239022, "exp": 1672511400, "role": "admin", "email": "arun@iiitd.ac.in", "hint": "lowercase-alphanumeric-length-5"}

header = {"alg": algo, "typ": "JWT"}
inp_header = json.dumps(header).encode()
header_1 = base64.urlsafe_b64encode(inp_header).decode().rstrip("=")

inp_payload = json.dumps(payload).encode()
payload_1 = base64.urlsafe_b64encode(inp_payload).decode().rstrip("=")

scrt = secret1.encode('utf-8')
message = f"{header_1}.{payload_1}".encode('utf-8')

if algo == "HS256":
    signature = hmac.new(scrt, message, "sha256").hexdigest().upper()
elif algo == "HS512":
    signature = hmac.new(scrt, message, "sha512").hexdigest().upper()
else:
    print("Unsupported algorithm")

signature_bytes = bytes.fromhex(signature)
signature_1 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip("=") 
new_jwt = f"{header_1}.{payload_1}.{signature_1}"
print("New JWT:", new_jwt)