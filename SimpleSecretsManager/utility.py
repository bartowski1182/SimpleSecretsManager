from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import os
import base64
import json
from SimpleSecretsManager.errors import *


class SecretsUtility:
    @staticmethod
    def _generate_key_from_password(password: str, salt: bytes) -> bytes:
        """Generate a key from the given password and salt."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            return base64.urlsafe_b64encode(kdf.derive(password.encode()))
        except Exception as e:
            raise SecretsError(f"Error generating key: {e}")

    @staticmethod
    def encrypt_secrets(secrets: dict, password: str, file_name: str):
        """Encrypt the given secrets dictionary and save to a binary file."""
        try:
            salt = os.urandom(16)
            key = SecretsUtility._generate_key_from_password(password, salt)
            cipher_suite = Fernet(key)
            encrypted_data = cipher_suite.encrypt(json.dumps(secrets).encode())

            with open(file_name, "wb") as file:
                file.write(salt + encrypted_data)
        except IOError as e:
            raise FileError(f"Error writing to file: {file_name}")

    @staticmethod
    def decrypt_secrets(password: str, file_name: str) -> dict:
        """Decrypt the secrets from the given binary file."""
        try:
            with open(file_name, "rb") as file:
                data = file.read()

            salt, encrypted_data = data[:16], data[16:]
            key = SecretsUtility._generate_key_from_password(password, salt)
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            return json.loads(decrypted_data.decode())
        except (IOError, FileNotFoundError):
            raise FileError(f"Error reading from file: {file_name}")
        except InvalidToken:
            raise EncryptionError(
                "Failed to decrypt. Check password or ensure data hasn't been tampered with."
            )
