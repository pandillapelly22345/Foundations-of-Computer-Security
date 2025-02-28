import math
import gmpy2
from Crypto.Cipher import Salsa20
from Crypto import Random 

def isPrime(n):
    if n<2:
        return False
    for i in range(2, n // 2+ 1):
        if n % i == 0:
            return False
    return True

def primeInput(p):
    while True:
        num = int(input(p))
        if isPrime(num):
            return num
        else:
            print("The number is not prime. Enter Again!!!!!!!!!")

def modInverse(e, z):
    g, x, y = gmpy2.gcdext(e, z)  
    if g != 1:
        raise ValueError("Modular inverse does not exist!!!!!!!!!")
    return x % z 

def symmetricE(msg, key):
    cipher = Salsa20.new(key=key)
    return cipher.nonce + cipher.encrypt(msg)

def symmetricD(ciphertext, key):
    nonce, encrypted_msg = ciphertext[:8], ciphertext[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(encrypted_msg)

# Example usage:
p = int(input("Enter First Prime Number: "))
q = int(input("Enter Second Prime Number: "))
# p = gmpy2.next_prime(10**1022)  # Generating a large prime for testing
# q = gmpy2.next_prime(p + 1000)  # Ensuring two distinct large primes

print("Prime no.1:")
print(p)
print("Prime no.2:")
print(q)

print("----------------------------------------------------------------------------------------------------")

# Alice generates symmetric key
k = Random.get_random_bytes(16)
symmetric_key = k
print("symmetric_key: ", symmetric_key)

print("----------------------------------------------------------------------------------------------------")

# Bob generates RSA keys
print("PART-B")
n = p * q
z = (p - 1) * (q - 1)
e = gmpy2.mpz(65537)  # Standard public exponent
# d = gmpy2.invert(e, z)  # Compute modular inverse
d = modInverse(e, z)
public_key, private_key = (n, e), (n, d)
print("Public Key: ", public_key)
print("Private Key: ", private_key)

print("----------------------------------------------------------------------------------------------------")
# Alice encrypts symmetric key with Bob's public key
print("PART-C")
n, e = public_key
msg_int = int.from_bytes(symmetric_key, byteorder="big")  # Convert bytes to integer
C = pow(msg_int, int(e), int(n)) 
ciphertext = C

print("Text After Alice encrypted symmetric key with Bob's public key:")
print("ciphertext: ", ciphertext)

print("----------------------------------------------------------------------------------------------------")
print("PART-D")
# Bob decrypts to obtain symmetric key
n, d = private_key
M = pow(ciphertext, int(d), int(n))  # Decrypt ciphertext
msg_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder="big")
decrypted_key = msg_bytes
print("Bob decrypts to obtain symmetric key")
print("decrypted_key: ", decrypted_key)

# Bob encrypts a msg using the shared symmetric key
msg = input("Enter the message that you need to send to Bob :) - ")
encrypted_msg = symmetricE(msg.encode(), decrypted_key)

# Alice decrypts Bob's msg
decrypted_msg = symmetricD(encrypted_msg, symmetric_key).decode()

# Output results
print("----------------------------------------------------------------------------------------------------")
print("PART-E && PART-F")
print("Original msg:", msg)
print("Encrypted msg:", encrypted_msg)
print("Decrypted msg:", decrypted_msg)