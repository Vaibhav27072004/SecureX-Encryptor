from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import hmac
import hashlib
import base64
import time
from colorama import Fore, Style, init
import os

init(autoreset=True) 



def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.CYAN + Style.BRIGHT + """
   _____                      _   __  __
  / ____|                    | | |  \/  |
 | (___   ___  ___ _   _ _ __| |_| \  / | ___
  \___ \ / _ \/ __| | | | '__| __| |\/| |/ _ \\
  ____) |  __/ (__| |_| | |  | |_| |  | |  __/
 |_____/ \___|\___|\__,_|_|   \__|_|  |_|\___|

    """ + Fore.YELLOW + ">> SecureX Encryption Suite <<\n")


def slow_print(text, delay=0.02):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


def loading(message, dots=3):
    print(Fore.YELLOW + message, end="", flush=True)
    for _ in range(dots):
        print(".", end="", flush=True)
        time.sleep(0.4)
    print()



def generate_rsa_key():
    loading("Generating RSA Keys")
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
    print(Fore.GREEN + "RSA keys generated successfully!")


def aes_encrypt_message(message):
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)
    encrypted_message = cipher.encrypt(message.encode())
    return aes_key, encrypted_message


def aes_decrypt_message(encrypted_message, aes_key):
    cipher = Fernet(aes_key)
    return cipher.decrypt(encrypted_message).decode()


def create_hmac(message, key):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(message, key, received_hmac):
    calculated_hmac = create_hmac(message, key)
    return hmac.compare_digest(calculated_hmac, received_hmac)


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


def encrypt_message(message, public_key_path, hmac_key):
    aes_key, encrypted_message = aes_encrypt_message(message)
    message_hmac = create_hmac(encrypted_message, hmac_key)
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key_path)

    return (
        base64.b64encode(encrypted_message).decode(),
        message_hmac,
        base64.b64encode(encrypted_aes_key).decode()
    )


def decrypt_message(encrypted_message_b64, encrypted_aes_key_b64, private_key_path, hmac_key, received_hmac):
    encrypted_message = base64.b64decode(encrypted_message_b64)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    aes_key = rsa_decrypt_key(encrypted_aes_key, private_key_path)

    if not verify_hmac(encrypted_message, hmac_key, received_hmac):
        raise ValueError("Message integrity check failed. Possible tampering detected!")

    return aes_decrypt_message(encrypted_message, aes_key)



if __name__ == "__main__":
    while True:
        banner()
        print(Fore.CYAN + "1." + Fore.WHITE + " Generate RSA Keys")
        print(Fore.CYAN + "2." + Fore.WHITE + " Encrypt a Message")
        print(Fore.CYAN + "3." + Fore.WHITE + " Decrypt a Message")
        print(Fore.CYAN + "4." + Fore.WHITE + " Exit")
        choice = input(Fore.YELLOW + "\nEnter your choice: " + Fore.WHITE)

        if choice == "1":
            generate_rsa_key()
            input(Fore.YELLOW + "\nPress Enter to continue...")

        elif choice == "2":
            public_key_path = "public_key.pem"
            message = input(Fore.GREEN + "Enter the message to encrypt: " + Fore.WHITE)
            hmac_key = input(Fore.GREEN + "Enter a secret HMAC passphrase: " + Fore.WHITE).encode()

            loading("Encrypting Message")
            encrypted_message_b64, message_hmac, encrypted_aes_key_b64 = encrypt_message(message, public_key_path, hmac_key)

            print(Fore.CYAN + "\nEncrypted Message (Base64):" + Fore.WHITE, encrypted_message_b64)
            print(Fore.CYAN + "\nHMAC:" + Fore.WHITE, message_hmac)
            print(Fore.CYAN + "\nEncrypted AES Key (Base64):" + Fore.WHITE, encrypted_aes_key_b64)
            input(Fore.YELLOW + "\nPress Enter to continue...")

        elif choice == "3":
            private_key_path = "private_key.pem"
            encrypted_message_b64 = input(Fore.GREEN + "Enter the encrypted message (Base64): " + Fore.WHITE)
            encrypted_aes_key_b64 = input(Fore.GREEN + "Enter the encrypted AES key (Base64): " + Fore.WHITE)
            hmac_key = input(Fore.GREEN + "Enter the secret HMAC passphrase: " + Fore.WHITE).encode()
            received_hmac = input(Fore.GREEN + "Enter the received HMAC: " + Fore.WHITE)

            try:
                loading("Decrypting Message")
                decrypted_message = decrypt_message(encrypted_message_b64, encrypted_aes_key_b64, private_key_path, hmac_key, received_hmac)
                print(Fore.CYAN + "\nDecrypted Message:" + Fore.WHITE, decrypted_message)
            except ValueError as e:
                print(Fore.RED + str(e))
            input(Fore.YELLOW + "\nPress Enter to continue...")

        elif choice == "4":
            slow_print(Fore.YELLOW + "Exiting SecureX... Goodbye!", 0.03)
            break

        else:
            print(Fore.RED + "Invalid choice. Try again!")
            time.sleep(1)
