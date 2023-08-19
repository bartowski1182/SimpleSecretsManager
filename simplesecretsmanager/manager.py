import os

from .errors import SecretsError, SecretsWarning

from .utility import (
    Argon2Algorithm,
    BcryptAlgorithm,
    Pbkdf2Algorithm,
    SecretsCipher,
)


class SecretsManager:
    def __init__(
        self,
        password: str,
        file_name: str,
        algorithm: Pbkdf2Algorithm
        | Argon2Algorithm
        | BcryptAlgorithm = BcryptAlgorithm(),
        save_password: bool = True,
    ) -> None:
        """Initialize the Secrets Manager and decrypt the secrets.
        If file doesn't exist, create it."""

        if save_password:
            self.password = password.encode()
        self.file_name = file_name
        self.save_password = save_password

        self.cipher = SecretsCipher(algorithm)

        # Check if the file exists
        if not os.path.exists(self.file_name):
            # If it doesn't, initialize an empty secrets dictionary
            self.secrets = {}
            # And save it
            self.save(password)
        else:
            self.secrets = self.cipher.decrypt_secrets(password.encode(), file_name)

    def __enter__(self) -> "SecretsManager":
        """Executed when entering the `with` block.
        Only usable if saving the password in memory."""
        if not self.save_password:
            raise SecretsError(
                "Attempting to enter with no password saved, this will not work."
            )
        return self  # this allows you to use the instance within the `with` block

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Executed when exiting the `with` block.
        Only usable if saving the password in memory."""
        self.save()

    def get_secret(self, key: str, default: str | None = None) -> str:
        """Retrieve a secret by its key. If no default is specified.
        Throws SecretsError when key doesn't exist and no default value is given."""
        try:
            secret = self.secrets.get(key, default)

            if secret is None:
                raise KeyError()
            return secret
        except KeyError:
            raise SecretsError(f"Secret with key '{key}' not found.")

    def update_secret(self, key: str, value: str) -> None:
        """Update or set a secret."""
        self.secrets[key] = value

    def update_secrets(self, secrets: dict) -> None:
        """Update a bulk list of secrets."""
        for key, value in secrets.items():
            self.secrets[key] = value

    def rename_key(self, old_key: str, new_key: str) -> None:
        """Update a key while maintaining the value.
        Throws SecretsError if the old key doesn't exist."""
        try:
            value = self.secrets.pop(old_key)
            self.secrets[new_key] = value
        except KeyError:
            raise SecretsError(f"Secret with key '{old_key}' not found.")

    def remove_secret(self, key: str) -> None:
        """Remove the given key.
        Throws SecretsError if key does not exist."""
        try:
            self.secrets.pop(key)
        except KeyError:
            raise SecretsError(f"Secret with key '{key}' not found.")

    def save(self, password: str = None) -> None:
        """Encrypt and save the current secrets to the binary file.
        Be sure to call this after transactions.
        If given a password, will encrypt with the NEW password"""

        if password is not None and self.save_password:
            raise SecretsWarning(
                "Passwords do not match, old password will be overwritten"
            )

        if password is not None:
            self.password = password.encode()
        if self.save_password and self.password is None:
            raise SecretsError(
                "Calling save with no saved password and no password given"
            )

        self.cipher.encrypt_secrets(self.secrets, self.file_name, self.password)

        if not self.save_password:
            self.password = None
