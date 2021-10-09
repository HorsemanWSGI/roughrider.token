import oath
import hmac
from typing import Optional, Literal
from roughrider.token.meta import HashTokenFactory, HashAlgorithm
from roughrider.token.secret import generate_secret


class TOTTokenFactory(HashTokenFactory):
    """Time-based One-Time token
    """
    __slots__ = ('algorithm', 'secret', 'TTL')

    secret: str  # Secret key
    TTL: int  # TTL duration in seconds.
    algorithm: HashAlgorithm

    def __init__(self,
                 algorithm: str = 'sha256',
                 TTL: int = 30,
                 length: Literal[4, 6, 7, 8] = 8,
                 secret: Optional[str] = None):
        self.algorithm = HashAlgorithm[algorithm]
        self.TTL = TTL
        self.length = length
        if secret is None:
            secret = generate_secret(as_bytes=False)
        self.secret = secret

    def _key_from_payload(self, payload: str) -> bytes:
        return hmac.new(
            key=self.secret,
            msg=payload.encode('utf-8'),
            digestmod=self.algorithm.value
        ).hexdigest()

    def generate(self, payload: str = None):
        secret = (self._key_from_payload(payload) if payload is not None
                  else self.secret)
        return oath.totp(
            secret,
            format=f'dec{self.length}',
            period=self.TTL
        )

    def challenge(self, token, payload: str = None):
        secret = (self._key_from_payload(payload) if payload is not None
                  else self.secret)
        result, drift = oath.accept_totp(
            secret,
            token,
            format=f'dec{self.length}',
            period=self.TTL
        )
        return result
