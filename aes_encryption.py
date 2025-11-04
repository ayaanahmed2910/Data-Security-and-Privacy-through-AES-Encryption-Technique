"""
AES Encryption System for Data Security and Privacy
Implements secure data encryption using AES-256 algorithm
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets


class AESEncryption:
    """
    AES Encryption class providing secure data encryption and decryption
    using AES-256-CBC with PBKDF2 key derivation
    """

    def __init__(self, password: str = None, salt: bytes = None):
        """
        Initialize AES encryption with password and salt

        Args:
            password (str): Password for key derivation
            salt (bytes): Salt for key derivation (auto-generated if None)
        """
        self.backend = default_backend()

        if password:
            self.password = password.encode('utf-8')
            self.salt = salt or os.urandom(16)
            self.key = self._derive_key()
        else:
            # Generate random key for demonstration
            self.key = os.urandom(32)  # 256-bit key
            self.salt = os.urandom(16)

    def _derive_key(self) -> bytes:
        """
        Derive encryption key from password using PBKDF2

        Returns:
            bytes: Derived 256-bit key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=self.salt,
            iterations=100000,  # High iteration count for security
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt plaintext data

        Args:
            plaintext (str): Data to encrypt

        Returns:
            dict: Dictionary containing encrypted data, IV, and salt
        """
        # Generate random IV
        iv = os.urandom(16)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()

        # Pad plaintext to be multiple of block size (16 bytes)
        plaintext_bytes = plaintext.encode('utf-8')
        padding_length = 16 - (len(plaintext_bytes) % 16)
        padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)

        # Encrypt data
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'salt': base64.b64encode(self.salt).decode('utf-8')
        }

    def decrypt(self, encrypted_data: dict) -> str:
        """
        Decrypt encrypted data

        Args:
            encrypted_data (dict): Dictionary containing ciphertext, IV, and salt

        Returns:
            str: Decrypted plaintext
        """
        try:
            # Decode base64 data
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            salt = base64.b64decode(encrypted_data['salt'])

            # Derive key from salt (if password was used)
            if hasattr(self, 'password'):
                self.salt = salt
                self.key = self._derive_key()

            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()

            # Decrypt data
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            padding_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-padding_length].decode('utf-8')

            return plaintext

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def generate_secure_key() -> str:
        """
        Generate a secure random key for AES encryption

        Returns:
            str: Base64 encoded 256-bit key
        """
        key = secrets.token_bytes(32)  # 256-bit key
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def generate_salt() -> str:
        """
        Generate a random salt

        Returns:
            str: Base64 encoded salt
        """
        salt = os.urandom(16)
        return base64.b64encode(salt).decode('utf-8')


def main():
    """
    Demonstration of AES encryption functionality
    """
    print("=== AES Encryption System for Data Security ===")
    print()

    # Initialize encryption with password
    password = "MySecurePassword123!"
    aes = AESEncryption(password=password)

    # Sample data to encrypt
    sensitive_data = {
        "user_id": "12345",
        "email": "user@example.com",
        "credit_card": "4532-1234-5678-9012",
        "personal_info": {
            "name": "John Doe",
            "address": "123 Main St, City, State 12345",
            "phone": "+1-555-0123"
        }
    }

    import json
    plaintext = json.dumps(sensitive_data, indent=2)

    print("Original Data:")
    print(plaintext)
    print()

    # Encrypt data
    print("Encrypting data...")
    encrypted = aes.encrypt(plaintext)
    print("Encryption successful!")
    print()

    # Display encrypted data
    print("Encrypted Data:")
    print(f"Ciphertext: {encrypted['ciphertext'][:50]}...")
    print(f"IV: {encrypted['iv']}")
    print(f"Salt: {encrypted['salt']}")
    print()

    # Decrypt data
    print("Decrypting data...")
    decrypted = aes.decrypt(encrypted)
    print("Decryption successful!")
    print()

    print("Decrypted Data:")
    print(decrypted)
    print()

    # Verify data integrity
    if plaintext == decrypted:
        print("✓ Data integrity verified - encryption/decryption successful!")
    else:
        print("✗ Data integrity check failed!")

    print()
    print("=== Security Features ===")
    print("• AES-256 encryption algorithm")
    print("• CBC mode for enhanced security")
    print("• PBKDF2 key derivation with 100,000 iterations")
    print("• Random IV generation for each encryption")
    print("• PKCS7 padding for data alignment")
    print("• Base64 encoding for safe data transmission")


if __name__ == "__main__":
    main()
