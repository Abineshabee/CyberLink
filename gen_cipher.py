from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# File names for keys
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


def generate_keys():
    """Generate RSA key pair and save to files if not already exists."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Save private key
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("🔑 RSA Keys Generated and Saved!")


def load_keys():
    """Load the RSA private and public keys from files."""
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key


def encrypt_message(public_key, message):
    """Encrypt a message using RSA public key."""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_message(private_key, encrypted_message):
    """Decrypt an encrypted message using RSA private key."""
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


if __name__ == "__main__":
    # Generate RSA key pair if not exists
    #generate_keys()

    # Load keys
    private_key, public_key = load_keys()

    # Message to encrypt
    message = "Hello, this is a secret message!"

    # Encrypt the message
    encrypted_msg = encrypt_message(public_key, message)
    print(f"\n🔒 Encrypted Message (Hex): {encrypted_msg.hex()}")

    # Decrypt the message
    decrypted_msg = decrypt_message(private_key, encrypted_msg)
    print(f"🔓 Decrypted Message: {decrypted_msg}")

