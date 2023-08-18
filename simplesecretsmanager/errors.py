class SecretsError(Exception):
    """Base exception class for the SecretsManager."""

    pass


class FileError(SecretsError):
    """Exception raised for file-related errors."""

    pass


class EncryptionError(SecretsError):
    """Exception raised for encryption-related errors."""

    pass
