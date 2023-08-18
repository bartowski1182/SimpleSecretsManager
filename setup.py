from setuptools import setup

setup(
    name="SimpleSecretsManager",
    version="0.2",
    packages=["SimpleSecretsManager"],
    install_requires=[
        "cryptography",
    ],
    license="MIT",
    description="A simple secrets manager",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/noneabove1182/SimpleSecretsManager",
)
