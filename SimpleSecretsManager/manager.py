from typing import Optional
from SimpleSecretsManager.utility import SecretsUtility
from SimpleSecretsManager.errors import *
import os


class SecretsManager:
    def __init__(self, password: str, file_name: str):
        """Initialize the Secrets Manager and decrypt the secrets.
        If file doesn't exist, create it."""
        self.password = password
        self.file_name = file_name
        # Check if the file exists
        if not os.path.exists(self.file_name):
            # If it doesn't, initialize an empty secrets dictionary
            self.secrets = {}
            # And save it
            self.save()
        else:
            self.secrets = SecretsUtility.decrypt_secrets(password, file_name)

    def __enter__(self):
        """Executed when entering the `with` block."""
        return self  # this allows you to use the instance within the `with` block

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Executed when exiting the `with` block."""
        self.save()

    def get_secret(self, key: str, default: str | None = None) -> str:
        """Retrieve a secret by its key. If no default is specified.
        Throws SecretsError when key doesn't exist and no default value is given."""
        try:
            secret = self.secrets.get(key, default)
            if secret is None and default is None:
                raise KeyError
            return secret
        except KeyError:
            raise SecretsError(f"Secret with key '{key}' not found.")

    def update_secret(self, key: str, value: str):
        """Update or set a secret."""
        self.secrets[key] = value

    def update_secrets(self, secrets: dict):
        """Update a bulk list of secrets."""
        for key, value in secrets.items():
            self.secrets[key] = value

    def rename_key(self, old_key: str, new_key: str):
        """Update a key while maintaining the value.
        Throws SecretsError if the old key doesn't exist."""
        try:
            value = self.secrets.pop(old_key)
            self.secrets[new_key] = value
        except KeyError:
            raise SecretsError(f"Secret with key '{old_key}' not found.")

    def remove_secret(self, key: str):
        """Remove the given key.
        Throws SecretsError if key does not exist."""
        try:
            self.secrets.pop(key)
        except KeyError:
            raise SecretsError(f"Secret with key '{key}' not found.")

    def save(self):
        """Encrypt and save the current secrets to the binary file.
        Be sure to call this after transactions."""
        SecretsUtility.encrypt_secrets(self.secrets, self.password, self.file_name)
