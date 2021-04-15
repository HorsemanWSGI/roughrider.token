import datetime
import hmac
from roughrider.token.meta import HashTokenFactory, HashAlgorithm


class AutoDeprecatingTokenFactory(HashTokenFactory):
    """Autodeprecating token, based on hashlib's hash algorithms.
    The token is valid for a number of days
    """
    __slots__ = ('algorithm', 'secret', 'validity')

    secret: bytes  # Secret key
    validity: int  # Validity duration in days.
    algorithm: HashAlgorithm

    def __init__(self, algorithm: str, secret: bytes, validity: int = 3):
        self.algorithm = HashAlgorithm[algorithm]
        self.secret = secret
        self.validity = validity

    def generate(self, payload: str, startdate: datetime.date = None):
        if startdate is None:
            startdate = datetime.date.today()
        token = hmac.new(
            key=self.secret,
            msg=payload.encode('utf-8'),
            digestmod=self.algorithm.value
        )
        token.update(str(startdate).encode('utf-8'))
        return token.hexdigest()

    def challenge(self, payload, token):
        today = datetime.date.today()
        for n in range(self.validity):
            tokenized = self.generate(
                payload, startdate=(today - datetime.timedelta(n)))
            if hmac.compare_digest(tokenized, token):
                return True
        return False
