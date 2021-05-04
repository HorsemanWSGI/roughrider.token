import hmac
import hashlib
import math
import time
from typing import Optional
from roughrider.token.meta import HashTokenFactory, HashAlgorithm
from roughrider.token.secret import generate_secret


class TOTTokenFactory(HashTokenFactory):
    """Time-based One-Time token
    """
    __slots__ = ('algorithm', 'secret', 'validity')

    secret: str  # Secret key
    validity: int  # Validity duration in seconds.
    algorithm: HashAlgorithm

    def __init__(self,
                 algorithm: str = 'sha256',
                 validity: int = 30,
                 length: int = 8,
                 secret: Optional[bytes] = None):
        self.algorithm = HashAlgorithm[algorithm]
        self.validity = validity
        self.length = length
        if secret is None:
            secret = generate_secret()
        self.secret = secret

    def _truncation(self, raw_key: hmac.HMAC, length: int) -> str:
        bitstring = bin(int(raw_key.hexdigest(), base=16))
        last_four_bits = bitstring[-4:]
        offset = int(last_four_bits, base=2)
        chosen_32_bits = bitstring[offset * 8 : offset * 8 + 32]
        full_totp = str(int(chosen_32_bits, base=2))
        return full_totp[-length:]

    def generate(self, payload: str = None):
        now_in_seconds = math.floor(time.time())
        t = math.floor(now_in_seconds / self.validity)
        if payload is not None:
            secret = hmac.new(
                key=self.secret,
                msg=payload.encode('utf-8'),
                digestmod=self.algorithm.value
            ).digest()
        else:
            secret = self.secret

        hashed = hmac.new(
            secret,
            t.to_bytes(length=8, byteorder="big"),
            self.algorithm.value
        )
        return self._truncation(hashed, self.length)

    def challenge(self, token, password=None):
        return self.generate(password) == token
