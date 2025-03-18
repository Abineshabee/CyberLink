import base64
from cryptography.fernet import Fernet

def get_fixed_key(hex_key):
    """Ensures the key is 32 bytes before Base64 encoding."""
    key_bytes = bytes.fromhex(hex_key)  # Convert hex string to raw bytes

    # Ensure the key is exactly 32 bytes (pad or trim if necessary)
    key_bytes = key_bytes.ljust(32, b'\0')[:32]  

    base64_key = base64.urlsafe_b64encode(key_bytes)  # Convert bytes to Base64
    return base64_key
    
    
def encrypt_data(data, key):
    """Encrypts data using the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Decrypts data using the provided key."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

# Use your own fixed key
hex_key = "da42d93996beb7e773ab31cae77c1c55"
key = get_fixed_key(hex_key)

data_to_encrypt = "This is a secret message."

encrypted_data = encrypt_data(data_to_encrypt, key)
print("Encrypted data:", encrypted_data)

decrypted_data = decrypt_data(encrypted_data, key)
print("Decrypted data:", decrypted_data)

