import pytest
import datetime
from freezegun import freeze_time
from reiter.token import Algorithm
from reiter.token.hmac_factories import AutoDeprecatingTokenFactory


today = datetime.date(2021, 4, 9)
tomorrow = datetime.date(2021, 4, 10)
week_later = datetime.date(2021, 4, 16)


def test_autodeprecatingtokenfactory_instanciation():
    factory = AutoDeprecatingTokenFactory('md5', b'secret')
    assert factory.validity == 3
    assert factory.secret == b'secret'
    assert factory.algorithm == Algorithm['md5']

    with pytest.raises(KeyError):
        AutoDeprecatingTokenFactory('unknown', b'secret')


def test_autodeprecatingtokenfactory_generate_token():
    factory = AutoDeprecatingTokenFactory('md5', b'secret')

    with freeze_time(today):
        token = factory.generate('my word')
        assert token == 'd2b93d1507fcb56e301e02e2f7e0d60f'

    with freeze_time(tomorrow):
        token = factory.generate('my word')
        assert token == 'de42be9c9a6946e860f8f12e030c1837'


def test_autodeprecatingtokenfactory_verify_token():
    factory = AutoDeprecatingTokenFactory('md5', b'secret')
    with freeze_time(today):
        token = factory.generate('my word')
        assert token == 'd2b93d1507fcb56e301e02e2f7e0d60f'

    assert factory.verify('my word', 'pouet') is False

    with freeze_time(tomorrow):
        # After a day, the token is still valid
        assert factory.verify('my word', token) is True

    with freeze_time(week_later):
        # After a week, the token is no longer valid
        assert factory.verify('my word', token) is False

    # we can change the validity period to 8 days
    factory.validity = 8
    with freeze_time(week_later):
        # After a week, the token is now valid
        assert factory.verify('my word', token) is True
