import hashlib
import hmac
import enum
from abc import ABC, abstractmethod
from datetime import date, timedelta


Algorithm = enum.Enum(
    'Algorithm', {
        name: name for name in hashlib.algorithms_guaranteed
    }
)


class TokenFactory(ABC):
    """A unique token factory
    """

    @abstractmethod
    def create(self, word: str):
        """returns a hex representation of a tokenized word.
        """

    @abstractmethod
    def verify(self, word: str, challenger: str):
        """returns a bool. True is tokenized word == challenged.
        False otherwise.
        """


class HashTokenFactory(TokenFactory):
    """Autodeprecating token, based on hashlib's hash algorithms.
    The token is valid for a few days
    """
    secret: bytes  # Secret key
    validity: int  # Validity duration in days.
    algorithm: Algorithm

    def __init__(self, algorithm: str, secret: bytes, validity: int=3):
        self.algorithm = Algorithm[algorithm]
        self.secret = secret
        self.validaty = validity

    def create(self, word):
        token = hmac.new(key=self.secret, digestmod=hashlib.sha256)
        token.update(word.encode('utf-8'))
        token.update(str(date.today()).encode('utf-8'))
        return token.hexdigest()

    def verify(self, word, challenger):
        today = date.today()
        basetoken = hmac.new(key=self.secret, digestmod=hashlib.sha256)
        basetoken.update(word.encode('utf-8'))
        for n in range(self.validity):
            token = basetoken.copy()
            token.update(str(today - timedelta(n)).encode('utf-8'))
            if token.hexdigest() == challenger:
                return True
        return False
