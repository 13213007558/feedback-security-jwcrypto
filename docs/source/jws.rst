JSON Web Signature (JWS)
========================

The jws Module implements the `JSON Web Signature`_ standard.
A JSON Web Signature is represented by a JWS object, related utility
classes and functions are available in this module too.

.. _JSON Web Signature: http://tools.ietf.org/html/rfc7515

Classes
-------

.. autoclass:: jwcrypto.jws.JWS
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.JWSCore
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.JWSStreamVerifier
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jws.default_allowed_algs

Exceptions
----------

.. autoclass:: jwcrypto.jws.InvalidJWSSignature
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSObject
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSOperation
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jws.JWSHeaderRegistry
   :annotation:

Examples
--------

Sign a JWS token::
    >>> from jwcrypto import jwk, jws
    >>> from jwcrypto.common import json_encode
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> payload = "My Integrity protected message"
    >>> jwstoken = jws.JWS(payload.encode('utf-8'))
    >>> jwstoken.add_signature(key, None,
    ...                        json_encode({"alg": "HS256"}),
    ...                        json_encode({"kid": key.thumbprint()}))
    >>> sig = jwstoken.serialize()

Verify a JWS token::
    >>> jwstoken = jws.JWS()
    >>> jwstoken.deserialize(sig)
    >>> jwstoken.verify(key)
    >>> payload = jwstoken.payload

Verify a detached JWS signature over a streamed payload (only RSA and
ECDSA algorithms are supported). The payload iterator is consumed
exactly once and is never closed by the verifier; if it wraps a file
the caller closes it, e.g. by passing
``iter(lambda: stream.read(65536), b'')`` inside a ``with`` block::
    >>> from jwcrypto import jwk, jws
    >>> key = jwk.JWK.generate(kty='RSA', size=2048)
    >>> payload = b'a large attachment'
    >>> jwstoken = jws.JWS(payload)
    >>> jwstoken.add_signature(key, None, '{"alg":"RS256"}')
    >>> jwstoken.detach_payload()
    >>> protected, _, signature = jwstoken.serialize(compact=True).split('.')
    >>> verifier = jws.JWSStreamVerifier()
    >>> verifier.add_signature(key, signature, protected=protected)
    >>> chunks = [payload[i:i + 7] for i in range(0, len(payload), 7)]
    >>> verifier.verify(iter(chunks))
    True
    >>> verifier.is_valid
    True
