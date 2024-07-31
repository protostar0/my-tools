import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os


padding = padding.PKCS1v15()
# padding = padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )

def generate_and_save_keys(private_key_path, public_key_path):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Save the private key to a file
    with open(private_key_path, 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    with open(public_key_path, 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_keys(private_key_path, public_key_path):
    # Load the private key from a file
    with open(private_key_path, 'rb') as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )

    # Load the public key from a file
    with open(public_key_path, 'rb') as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )

    return private_key, public_key

private_key_path = 'private_key.pem'
public_key_path = 'public_key.pem'

# Check if keys already exist; if not, generate and save them
if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
    generate_and_save_keys(private_key_path, public_key_path)

# Load keys from files
private_key, public_key = load_keys(private_key_path, public_key_path)

# Extract the modulus and exponent
numbers = public_key.public_numbers()
modulus = numbers.n
exponent = numbers.e

# Convert modulus and exponent to hexadecimal
modulus_hex = hex(modulus)
exponent_hex = hex(exponent)

print("Public Exponent (hex):", exponent_hex)
print("Modulus (hex):", modulus_hex)

# Message to be encrypted
message = b"Hello, this is a secret message!"

# Encrypt the message using the public key with RSA PKCS#1 v1.5 padding
ciphertext = public_key.encrypt(
    message,
    padding
)

print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the message using the private key with RSA PKCS#1 v1.5 padding
plaintext = private_key.decrypt(
    ciphertext,
    padding
)

print("Decrypted message:", plaintext.decode('utf-8'))

# Generate RSA public key from given exponent and modulus
def generate_public_key_from_exp_mod(exp, mod):
    public_numbers = rsa.RSAPublicNumbers(exp, mod)
    public_key = public_numbers.public_key(default_backend())
    return public_key

# Use the extracted exponent and modulus to generate a new public key
new_public_key = generate_public_key_from_exp_mod(exponent, modulus)

# Encrypt the message using the new public key with RSA PKCS#1 v1.5 padding
new_ciphertext = new_public_key.encrypt(
    message,
    padding
)



print("New Ciphertext (base64):", base64.b64encode(new_ciphertext).decode('utf-8'))
print("New Ciphertext (COMPAI): gXw82Ph/fq77QHVn/aumDVO+KYit6zb3RdG7I5jVigwCfFm84XBWizVavq55IEI2amym3yjCc8Va7jkJvUhFf1CjFMmgXdZ20SbaLXIBWEnlkkLGY/ZuJrozITo7oNnTlI2R09unxjyDHuHzwweiWrOxxMat48ItWGxF/BI5Zt1+CQVXn+1mtIpcNhskAYBK9j9zRQsQkctRrnwBEIkNzuSPR4mAGNGbceIK+zwi6POdiC+IXCKhOIuJ29q+UWHSYFkmKXkT/oi/sEs3iQLlOaUAmsoslFrZICNiLqH4JLzfeDMOh5mzzVDqZlYqt1aWgva/qtiU2gMgSCAlC8dMEw==")
# Decrypt the message using the private key to verify
new_plaintext = private_key.decrypt(
    new_ciphertext,
    padding
)

print("Decrypted message with new key:", new_plaintext.decode('utf-8'))



print("====================================")
text = base64.b64decode('KVgHDDEvQliWuKb5Vt4KBgGMe6r4hNuLJbZqDBTcuFLQIaFHRJWxFM8NnCuUqudk0jCCPeAq2FwaC82OpiMT2w+b3hlywdcfma2kT5jgfid/8sC6HEpyBDpBO3TDeyKMnRsDvbdF5fVXAWrrMS/QtWJ0vqA7wsAvtSoEfUihMKOcVhFsdLGNSFzGi/2+Ii09sxECzbRtaLfm5H3bEux+UgpJm32qWHFxDUTg4NHlt4bq5gEKt77YTdR9JxfwKFC09ZaauUJQgR9KFkzWzGQ8J91mhyhn/Q/RRocEmfR+Gp0aWnBMOlpXrmWNPaMifcUstbnfLO4LkB8Xqp4jOHG/dA==')
print(text[::-1])
text = text[::-1]
# text = bytes.fromhex('134cc70b2520482003da94d8aabff6829656b72a5666ea50cdb399870e3378dfbc24f8a12e622320d95a942cca9a00a539e50289374bb0bf88fe137929265960d26151bedadb898b38a1225c882f889df3e8223cfb0ae2719bd1188089478fe4ce0d8910017cae51cb91100b45733ff64a8001241b365c8ab466ed9f5705097edd663912fc456c582dc2e3adc6c4b1b35aa207c3f3e11e833cc6a7dbd3918d94d3d9a03b3a2133ba266ef663c64292e5495801722dda26d176d65da0c914a3507f4548bd0939ee5ac573c228dfa66c6a36422079aebe5a358b5670e1bc597c020c8ad59823bbd145f736ebad8829be530da6abfd677540fbae7e7ff8d83c7c81')
# print(text)

new_plaintext = private_key.decrypt(
    text,
    padding
)
print("decrpted:", new_plaintext.decode('utf-8'))
