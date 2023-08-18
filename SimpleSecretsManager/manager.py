from SimpleSecretsManager.utility import SecretsUtility
from SimpleSecretsManager.errors import *
import os


class SecretsManager:
    def __init__(self, password: str, file_name: str):
        """Initialize the Secrets Manager and decrypt the secrets."""
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

    def get_secret(self, key: str) -> str:
        """Retrieve a secret by its key."""
        try:
            secret = self.secrets.get(key, None)
            if secret is None:
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
        """Update the name of a key."""
        try:
            self.secrets[new_key] = self.secrets.get[old_key]
            self.secrets.pop(old_key)
        except KeyError:
            raise SecretsError(f"Secret with key '{old_key}' not found.")

    def remove_secret(self, key: str):
        """Remove the secret for the given key."""
        try:
            self.secrets.pop(key)
        except KeyError:
            raise SecretsError(f"Secret with key '{key}' not found.")

    def save(self):
        """Encrypt and save the current secrets to the binary file."""
        SecretsUtility.encrypt_secrets(self.secrets, self.password, self.file_name)
