class TokenException(Exception):

    def __init__(self, token: str):
        self.token = token


class InvalidToken(TokenException):

    def __str__(self):
        return f"Token {self.token!r} could not be parsed."


class ExpiredToken(TokenException):

    def __str__(self):
        return f"Token {self.token!r} is expired."
