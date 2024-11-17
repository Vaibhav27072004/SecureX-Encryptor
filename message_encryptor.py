from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import hmac
import hashlib


# 1. Generate RSA Keys
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("RSA keys generated and saved as 'private_key.pem' and 'public_key.pem'.")


# 2. AES Encryption/Decryption
def aes_encrypt_message(message):
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)
    encrypted_message = cipher.encrypt(message.encode())
    return aes_key, encrypted_message


def aes_decrypt_message(encrypted_message, aes_key):
    cipher = Fernet(aes_key)
    return cipher.decrypt(encrypted_message).decode()


# 3. HMAC Functions
def create_hmac(message, key):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(message, key, received_hmac):
    calculated_hmac = create_hmac(message, key)
    return hmac.compare_digest(calculated_hmac, received_hmac)


# 4. RSA Encryption/Decryption
def rsa_encrypt_key(aes_key, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key


def rsa_decrypt_key(encrypted_aes_key, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


# 5. Encryption/Decryption Workflow
def encrypt_message(message, public_key_path, hmac_key):
    aes_key, encrypted_message = aes_encrypt_message(message)
    message_hmac = create_hmac(encrypted_message, hmac_key)
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key_path)
    return encrypted_message, message_hmac, encrypted_aes_key


def decrypt_message(encrypted_message, encrypted_aes_key, private_key_path, hmac_key, received_hmac):
    aes_key = rsa_decrypt_key(encrypted_aes_key, private_key_path)

    # Verify HMAC
    if not verify_hmac(encrypted_message, hmac_key, received_hmac):
        raise ValueError("Message integrity check failed. Possible tampering detected!")

    # Decrypt the message
    return aes_decrypt_message(encrypted_message, aes_key)


# Main Program
if __name__ == "__main__":
    print("1. Generate RSA Keys")
    print("2. Encrypt a Message")
    print("3. Decrypt a Message")
    choice = input("Enter your choice: ")

    if choice == "1":
        generate_rsa_key()

    elif choice == "2":
        public_key_path = "public_key.pem"
        message = input("Enter the message to encrypt: ")
        hmac_key = input("Enter a secret HMAC passphrase: ").encode()

        encrypted_message, message_hmac, encrypted_aes_key = encrypt_message(message, public_key_path, hmac_key)
        print("\n\nEncrypted Message: ", encrypted_message)
        print("\nHMAC :", message_hmac)
        print("\nEncrypted AES Key:", encrypted_aes_key)

    elif choice == "3":
        private_key_path = "private_key.pem"
        encrypted_message = eval(input("Enter the encrypted message (as bytes): "))
        encrypted_aes_key = eval(input("Enter the encrypted AES key: "))
        hmac_key = input("Enter the secret HMAC passphrase: ").encode()
        received_hmac = input("Enter the received HMAC: ")

        try:
            decrypted_message = decrypt_message(encrypted_message, encrypted_aes_key, private_key_path, hmac_key, received_hmac)
            print("\n\nDecrypted Message:", decrypted_message)
        except ValueError as e:
            print(e)

    else:
        print("Invalid choice.")
