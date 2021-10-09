roughrider.token
****************

Utilities to generate and verify tokens (autodeprecating or not).

Currently implemented :

  - Time-based One-time Password (TOTP)


TOTP Example
============

Below is an example of a token based on TOTP, self-deprecating after
a given number of seconds


.. code-block:: python

  from roughrider.token.hmac_factories import TOTTokenFactory

  factory = TOTTokenFactory(secret=b'secret', TTL=180)  # 3 min TTL
  token = factory.generate('my word')
  assert factory.challenge(token, 'my word') is True
  assert factory.challenge(token, 'my other word') is False
