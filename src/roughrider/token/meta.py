import abc
import hashlib
import enum
from typing import Any


HashAlgorithm = enum.Enum(
    'Algorithm', {
        name: name for name in hashlib.algorithms_guaranteed
    }
)


class TokenStorage(abc.ABC):

    @abc.abstractmethod
    def store(self, token: str):
        """Stores a token.
        """

    @abc.abstractmethod
    def retrieve(self, *args) -> str:
        """Returns a token.
        """

    @abc.abstractmethod
    def refresh(self, *args) -> bool:
        """Refreshes a token validity.
        """


class TokenFactory(abc.ABC):
    """A token factory
    """

    @abc.abstractmethod
    def generate(self, payload: Any, **kwargs) -> str:
        """Returns a token containing or representing a payload.
        """


class HashTokenFactory(TokenFactory):
    """A token factory using one-way functions to generate tokens.
    """

    @abc.abstractmethod
    def challenge(self, token: str, payload: Any) -> bool:
        """Tokenized payload == token.
        """


class EncryptedTokenFactory(TokenFactory):
    """A token factory using cryptography to encrypt and decrypt payloads.
    """

    @abc.abstractmethod
    def decrypt(self, token: str) -> Any:
        """Returns the payload or raises a TokenException.
        """
