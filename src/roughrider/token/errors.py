class TokenException(Exception):
    pass


class InvalidToken(TokenException):
    """Token could not be parsed.
    """


class ExpiredToken(TokenException):
    """Token is expired.
    """
