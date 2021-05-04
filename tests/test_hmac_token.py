import pytest
import datetime
from freezegun import freeze_time
from roughrider.token.meta import HashAlgorithm
from roughrider.token.hmac_factories import TOTTokenFactory
from roughrider.token.secret import generate_secret


now = datetime.datetime(2021, 4, 9, 19, 0, 0)
two_min_later = datetime.datetime(2021, 4, 9, 19, 2, 0)
two_hours_later = datetime.datetime(2021, 4, 9, 21, 0, 0)


def test_tottokenfactory_instanciation():
    factory = TOTTokenFactory()
    assert factory.algorithm == HashAlgorithm['sha256']

    with pytest.raises(KeyError):
        TOTTokenFactory(algorithm='unknown')


def test_tottokenfactory_generate_token():
    factory = TOTTokenFactory(secret=b'secret', TTL=180)  # 3 min validity

    with freeze_time(now):
        token = factory.generate('my word')
        assert token == '41948811'

    with freeze_time(two_min_later):
        token = factory.generate('my word')
        assert token == '41948811'


def test_tottokenfactory_challenge_token():
    factory = TOTTokenFactory(secret=b'secret', TTL=180)  # 3 min validity

    with freeze_time(now):
        token = factory.generate('my word')
        assert token == '41948811'

    with freeze_time(two_min_later):
        # After 2 min, the token is still valid
        assert factory.challenge(token, 'my word') is True
        assert factory.challenge(token, 'other word') is False
        assert factory.challenge(token, 'My word') is False

    with freeze_time(two_hours_later):
        # After 2h, the token is no longer valid
        assert factory.challenge(token, 'my word') is False

    # we can change the validity to 3 hours
    # it won't validate as the deprecation is contained within the hash.
    factory.TTL = 10800
    with freeze_time(two_hours_later):
        assert factory.challenge(token, 'my word') is False


def test_TOTP():
    """One time use password.
    """
    factory = TOTTokenFactory(TTL=121)  # 2 min validity

    with freeze_time(now):
        token = factory.generate()

    with freeze_time(two_min_later):
        # After 2 min, the token is still valid
        assert factory.challenge(token) is True

    with freeze_time(two_hours_later):
        # After 2h, the token is no longer valid
        assert factory.challenge(token) is False

    # we can change the validity to 3 hours
    # it won't validate as the deprecation is contained within the hash.
    factory.TTL = 10800
    with freeze_time(two_hours_later):
        assert factory.challenge(token) is False
