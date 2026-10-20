"""Create deployment secret files locally. Never commit the output."""
import os
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

root = Path("secrets")
root.mkdir(mode=0o700, exist_ok=True)
key = ec.generate_private_key(ec.SECP256R1())
for name, value in {
    "soca-signing.pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    "soca-transactions.key": Fernet.generate_key(),
}.items():
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
print("Created owner-only deployment secrets in secrets/")
