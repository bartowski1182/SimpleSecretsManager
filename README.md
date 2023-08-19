# A Simple Secrets Manager for python

## How to use:

Storing

```python
from SimpleSecretsManager import manager

secrets_manager = manager.SecretsManager("password", "file.bin")

secrets["MY_SECRET"] = "the_secret"
...

secrets_manager.update_secrets(secrets)
secrets_manager.update_secret("ANOTHER_SECRET", "the_other_secret")
secrets_manager.save()
```

There are 2 additional options when creating your SecretsManager, you can pass a non-default algorithm (defautls to Pbkdf2Algorithm):

```python
from SimpleSecretsManager import manager, utility

algorithm = utility.Argon2Algorithm()

secrets_manager = manager.SecretsManager("password", "file.bin", algorithm=algorithm)
```

You can also choose to not have the password saved in memory:

```python
from SimpleSecretsManager import manager

secrets_manager = manager.SecretsManager("password", "file.bin", save_password=False)

secrets_manager.update_secret("MY_SECRET", "the_secret")
# Must give password when saving if save_password = False, throws SecretsError otherwise
secrets_manager.save("password")
```

## Note: when giving a password to save(), this will be used to encrypt the file, in place of whatever was orinally stored

Retrieving

```python
from SimpleSecretsManager import manager

secrets_manager = manager.SecretsManager("password", "file.bin")

try:
    my_secret = secrets_manager.get_secret("MY_SECRET")
except SecretsError as e:
    print("Issue retrieving 'MY_SECRET': {e}")
```

By default, it will throw an error SecretsError if the secret does not exist. If you instead pass a default value, you'll be able to get that returned no matter what.

You can also use the secret manager with the 'with' clause so that it auto saves after:

```python
with secrets_manager:
    secrets_manager.update_secret("MY_SECRET", "newvalue")
```

and then upon exiting, newvalue will be saved into "MY_SECRET"

## Note: This won't work and will throw an error if used when save_password is false, since we won't be able to save the value when we get there

Provided under MIT License
