import secrets
from typing import AnyStr


def generate_secret(as_bytes: bool = True, size: int = 16) -> AnyStr:
    """A shared key "should be chosen at random or using a
    cryptographically strong pseudorandom generator properly seeded
    with a random value".

    A shared key must be stored encrypted and decrypted only on for
    password validation and safe copy to a trusted target.
    """
    if as_bytes:
        return secrets.token_bytes(size)
    return secrets.token_hex(size)
