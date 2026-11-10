JSON Web Token (JWT)
====================

The jwt Module implements the `JSON Web Token`_ standard.
A JSON Web Token is represented by a JWT object, related utility classes and
functions are available in this module too.

.. _JSON Web Token: http://tools.ietf.org/html/rfc7519

Classes
-------

.. autoclass:: jwcrypto.jwt.JWT
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jwt.JWTClaimsRegistry

.. autodata:: jwcrypto.jwt.JWT_expect_type

Examples
--------

Create a symmetric key::
    >>> from jwcrypto import jwt, jwk
    >>> key = jwk.JWK(generate='oct', size=256)
    >>> key.export()  # doctest: +ELLIPSIS
    '{"k":"...","kty":"oct"}'

Create a signed token with the generated key::
    >>> Token = jwt.JWT(header={"alg": "HS256"},
    ...                 claims={"info": "I'm a signed token"})
    >>> Token.make_signed_token(key)
    >>> Token.serialize()       #doctest: +ELLIPSIS
    'eyJhbGciOiJIUzI1NiJ9.eyJpbmZvIjoiSSdtIGEgc2lnbmVkIHRva2VuIn0...'

Further encrypt the token with the same key::
    >>> Etoken = jwt.JWT(header={"alg": "A256KW", "enc": "A256CBC-HS512"},
    ...                  claims=Token.serialize())
    >>> Etoken.make_encrypted_token(key)
    >>> Etoken.serialize()
    'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0...'

Now decrypt and verify::
    >>> from jwcrypto import jwt, jwk
    >>> k = {"k": "Wal4ZHCBsml0Al_Y8faoNTKsXCkw8eefKXYFuwTBOpA", "kty": "oct"}
    >>> key = jwk.JWK(**k)
    >>> e = 'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.ST5RmjqDLj696xo7YFTFuKUhcd3naCrm6yMjBM3cqWiFD6U8j2JIsbclsF7ryNg8Ktmt1kQJRKavV6DaTl1T840tP3sIs1qz.wSxVhZH5GyzbJnPBAUMdzQ.6uiVYwrRBzAm7Uge9rEUjExPWGbgerF177A7tMuQurJAqBhgk3_5vee5DRH84kHSapFOxcEuDdMBEQLI7V2E0F57-d01TFStHzwtgtSmeZRQ6JSIL5XlgJouwHfSxn9Z_TGl5xxq4TksORHED1vnRA.5jPyPWanJVqlOohApEbHmxi3JHp1MXbmvQe2_dVd8FI'
    >>> ET = jwt.JWT(key=key, jwt=e, expected_type="JWE")
    >>> ST = jwt.JWT(key=key, jwt=ET.claims)
    >>> ST.claims
    '{"info":"I\'m a signed token"}'

Time-based claims (``exp``, ``nbf``, ``iat``)
---------------------------------------------

The time-based claims use the NumericDate format defined in RFC 7519
section 2: a JSON number, i.e. an ``int`` or a finite ``float`` (the
latter allows fractional seconds). Booleans are rejected even though
``bool`` is a subclass of ``int``, and NaN, positive and negative
infinity, numeric strings and any other non-number type raise
:class:`jwcrypto.jwt.JWTInvalidClaimFormat`.

A single verification point in time is captured once per validation and
shared by all three claims. By default it is the current system time,
but an explicit ``now`` NumericDate can be passed per call (or set on
the :class:`jwcrypto.jwt.JWT` object) to reproduce a decision offline,
for example at the moment a token was accepted as recorded in a log::

    >>> key = jwk.JWK(generate='oct', size=256)
    >>> token = jwt.JWT(header={"alg": "HS256"},
    ...                 claims={"exp": 1000000000})
    >>> token.make_signed_token(key)
    >>> # fixed verification time: the result never depends on the
    >>> # wall clock and is fully reproducible
    >>> jwt.JWT(jwt=token.serialize(), key=key, now=1000000000)
    <jwcrypto.jwt.JWT object at ...>
    >>> with __import__('pytest').raises(jwt.JWTExpired):
    ...     jwt.JWT(jwt=token.serialize(), key=key, now=1000000100)

The ``leeway`` (default 60 seconds) is applied symmetrically:

* ``exp``: accepted while ``now <= exp + leeway``
  (equivalently ``exp >= now - leeway``);
* ``nbf``: accepted while ``nbf <= now + leeway``;
* ``iat``: an issued-at time in the future is rejected while
  ``iat > now + leeway``; the same leeway accommodates clock skew.

Optional maximum token lifetime
-------------------------------

Passing ``max_token_age`` (a non-negative number of seconds) enables a
hard cap on the token's own lifetime. Unlike the leeway-based checks
this is a structural check that never relaxes expiration: when enabled,
both ``iat`` and ``exp`` must be present and well-formed NumericDates,
``exp`` must not precede ``iat``, and ``exp - iat`` must not exceed the
configured value. A missing claim raises
:class:`jwcrypto.jwt.JWTMissingClaim`, an out-of-order pair raises
:class:`jwcrypto.jwt.JWTInvalidClaimValue`, and an excessive lifetime
raises :class:`jwcrypto.jwt.JWTExpired`::

    >>> claims = {"iat": 2000.0, "exp": 2100.0}
    >>> token = jwt.JWT(header={"alg": "HS256"}, claims=claims)
    >>> token.make_signed_token(key)
    >>> jwt.JWT(jwt=token.serialize(), key=key, now=2050,
    ...         max_token_age=100)
    <jwcrypto.jwt.JWT object at ...>
    >>> with __import__('pytest').raises(jwt.JWTExpired):
    ...     jwt.JWT(jwt=token.serialize(), key=key, now=2050,
    ...             max_token_age=50)
    >>> no_iat = jwt.JWT(header={"alg": "HS256"},
    ...                  claims={"exp": 2100.0})
    >>> no_iat.make_signed_token(key)
    >>> with __import__('pytest').raises(jwt.JWTMissingClaim):
    ...     jwt.JWT(jwt=no_iat.serialize(), key=key, now=2050,
    ...             max_token_age=100)

The cryptographic check (signature verification or decryption) always
runs before claims validation, and any failure clears the claims
previously stored on the object, so a rejected token never leaves
accessible claims behind.

Offline replay tool
-------------------

The module :mod:`jwcrypto.jwt_replay` provides a small command line
tool that replays a token at an exact, fixed point in time so the same
token, key and parameters always produce the same verdict::

    python -m jwcrypto.jwt_replay --token "$JWT" --key key.json \\
        --now 1000000000 --max-token-age 3600

It prints ``ACCEPTED`` or ``REJECTED`` together with the exception type
and message, and exits with status 0 or 1 respectively.
