import abc
import datetime
import enum
import hashlib
import hmac


Algorithm = enum.Enum(
    'Algorithm', {
        name: name for name in hashlib.algorithms_guaranteed
    }
)


class TokenFactory(abc.ABC):
    """A unique token factory
    """

    @abc.abstractmethod
    def generate(self, word: str):
        """returns a hex representation of a tokenized word.
        """

    @abc.abstractmethod
    def verify(self, word: str, challenger: str):
        """returns a bool. True is tokenized word == challenged.
        False otherwise.
        """


class HashTokenFactory(TokenFactory):
    """Autodeprecating token, based on hashlib's hash algorithms.
    The token is valid for a few days
    """
    __slots__ = ('algorithm', 'secret', 'validity')

    secret: bytes  # Secret key
    validity: int  # Validity duration in days.
    algorithm: Algorithm

    def __init__(self, algorithm: str, secret: bytes, validity: int=3):
        self.algorithm = Algorithm[algorithm]
        self.secret = secret
        self.validity = validity

    def generate(self, word):
        token = hmac.new(
            key=self.secret, digestmod=self.algorithm.value)
        token.update(word.encode('utf-8'))
        token.update(str(datetime.date.today()).encode('utf-8'))
        return token.hexdigest()

    def verify(self, word, challenger):
        today = datetime.date.today()
        basetoken = hmac.new(
            key=self.secret, digestmod=self.algorithm.value)
        basetoken.update(word.encode('utf-8'))
        for n in range(self.validity):
            token = basetoken.copy()
            token.update(str(today - datetime.timedelta(n)).encode('utf-8'))
            if token.hexdigest() == challenger:
                return True
        return False
