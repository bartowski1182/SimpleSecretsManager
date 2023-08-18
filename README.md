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
