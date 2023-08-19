import base64
import json
import os
from enum import Enum
from typing import Type

import argon2
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import BaseModel, Field

from simplesecretsmanager.errors import EncryptionError, FileError, SecretsError


class Pbkdf2Algorithm(BaseModel):
    iterations: int = Field(100000, ge=100000, description="Pbkdf2 iterations")
    algorithm: Type[hashes.HashAlgorithm] = hashes.SHA256


class Argon2Algorithm(BaseModel):
    time_cost: int = argon2.DEFAULT_TIME_COST
    memory_cost: int = argon2.DEFAULT_MEMORY_COST
    parallelism: int = argon2.DEFAULT_PARALLELISM


class BcryptAlgorithm(BaseModel):
    rounds: int = Field(16, ge=10)


class SecretsCipher:
    def __init__(
        self,
        raw_password: str,
        algorithm: Pbkdf2Algorithm | Argon2Algorithm | BcryptAlgorithm,
    ) -> None:
        self._algorithm = algorithm
        self.__raw_password = raw_password.encode()

    def __generate_key_from_password(self, salt: bytes) -> bytes:
        """Generate a key from the given password and salt."""

        if isinstance(self._algorithm, Pbkdf2Algorithm):
            try:
                kdf = PBKDF2HMAC(
                    algorithm=self._algorithm.algorithm(),
                    length=32,
                    salt=salt,
                    iterations=self._algorithm.iterations,
                    backend=default_backend(),
                )
                return base64.urlsafe_b64encode(kdf.derive(self.__raw_password))
            except Exception as e:
                raise SecretsError(f"Error generating key: {e}")
        elif isinstance(self._algorithm, Argon2Algorithm):
            argon = argon2.low_level.hash_secret(
                self.__raw_password,
                salt,
                hash_len=32,
                type=argon2.low_level.Type.ID,
                time_cost=self._algorithm.time_cost,
                memory_cost=self._algorithm.memory_cost,
                parallelism=self._algorithm.parallelism,
            )

            return base64.urlsafe_b64encode(argon.split(b"$")[-1])
        else:
            return base64.urlsafe_b64encode(bcrypt.hashpw(self.__raw_password, salt))

    def encrypt_secrets(self, secrets: dict, file_name: str) -> None:
        """Encrypt the given secrets dictionary and save to a binary file."""

        salt = (
            bcrypt.gensalt(self._algorithm.rounds)
            if isinstance(self._algorithm, BcryptAlgorithm)
            else os.urandom(16)
        )
        key = self.__generate_key_from_password(salt)
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(json.dumps(secrets).encode())

        try:
            with open(file_name, "wb") as file:
                file.write(salt + encrypted_data)
        except IOError:
            raise FileError(f"Error writing to file: {file_name}")

    def decrypt_secrets(self, password: str, file_name: str) -> dict:
        """Decrypt the secrets from the given binary file."""
        try:
            with open(file_name, "rb") as file:
                data = file.read()

            salt, encrypted_data = data[:16], data[16:]
            key = self.__generate_key_from_password(salt)
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            return json.loads(decrypted_data.decode())
        except (IOError, FileNotFoundError, ValueError):
            raise FileError(f"Error reading from file: {file_name}")
        except InvalidToken:
            raise EncryptionError(
                "Failed to decrypt. Check password or ensure data hasn't been tampered with."
            )
