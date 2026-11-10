JSON Web Encryption (JWE)
=========================

The jwe Module implements the `JSON Web Encryption`_ standard.
A JSON Web Encryption is represented by a JWE object, related utility
classes and functions are available in this module too.

.. _JSON Web Encryption: https://tools.ietf.org/html/rfc7516

Classes
-------

.. autoclass:: jwcrypto.jwe.JWE
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.JWEPolicy
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jwe.default_allowed_algs

Exceptions
----------

.. autoclass:: jwcrypto.jwe.InvalidJWEOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEData
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyType
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyLength
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidCEKeyLength
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jwe.JWEHeaderRegistry
   :annotation:

Examples
--------

Symmetric keys
~~~~~~~~~~~~~~

Encrypt a JWE token::
    >>> from jwcrypto import jwk, jwe
    >>> from jwcrypto.common import json_encode
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> payload = "My Encrypted message"
    >>> jwetoken = jwe.JWE(payload.encode('utf-8'),
    ...                    json_encode({"alg": "A256KW",
    ...                                 "enc": "A256CBC-HS512"}))
    >>> jwetoken.add_recipient(key)
    >>> enc = jwetoken.serialize()

Decrypt a JWE token::
    >>> jwetoken = jwe.JWE()
    >>> jwetoken.deserialize(enc)
    >>> jwetoken.decrypt(key)
    >>> payload = jwetoken.payload

Asymmetric keys
~~~~~~~~~~~~~~~

Encrypt a JWE token::
    >>> from jwcrypto import jwk, jwe
    >>> from jwcrypto.common import json_encode, json_decode
    >>> public_key = jwk.JWK()
    >>> private_key = jwk.JWK.generate(kty='RSA', size=2048)
    >>> public_key.import_key(**json_decode(private_key.export_public()))
    >>> payload = "My Encrypted message"
    >>> protected_header = {
    ...     "alg": "RSA-OAEP-256",
    ...     "enc": "A256CBC-HS512",
    ...     "typ": "JWE",
    ...     "kid": public_key.thumbprint(),
    ... }
    >>> jwetoken = jwe.JWE(payload.encode('utf-8'),
    ...                    recipient=public_key,
    ...                    protected=protected_header)
    >>> enc = jwetoken.serialize()

Decrypt a JWE token::
    >>> jwetoken = jwe.JWE()
    >>> jwetoken.deserialize(enc, key=private_key)
    >>> payload = jwetoken.payload

Receiver policies
~~~~~~~~~~~~~~~~~

By default decryption merges the protected, shared unprotected and
per-recipient unprotected headers, which makes it impossible to require that
a business header was actually authenticated. A :class:`JWEPolicy` keeps the
three header layers separate and rejects tokens that place required headers
outside the protected header, duplicate a header across layers, or use an
unaccepted ``alg``/``enc`` combination.

Enforce protected headers and an algorithm combination when decrypting::

    >>> from jwcrypto.jwe import JWEPolicy
    >>> policy_key = jwk.JWK.generate(kty='oct', size=128)
    >>> policy_token = jwe.JWE(
    ...     b'policy protected message',
    ...     protected={'alg': 'A128KW', 'enc': 'A128GCM',
    ...                'partner': 'example-partner'})
    >>> policy_token.add_recipient(policy_key)
    >>> policy_enc = policy_token.serialize(compact=True)
    >>> policy = JWEPolicy(
    ...     required_protected=['partner'],
    ...     allowed_combos=[('A128KW', 'A128GCM')])
    >>> policy_jwe = jwe.JWE()
    >>> policy_jwe.deserialize(policy_enc, key=policy_key, policy=policy)
    >>> policy_jwe.payload
    b'policy protected message'

The same policy can be attached to the object and is applied to every
recipient actually attempted when using the JSON serialization; a recipient
cannot satisfy the requirements using another recipient's headers. The
compact serialization already places all headers in the protected layer, but
its algorithms are still checked against the combination policy. When no
policy is provided the historical, permissive behavior is unchanged.
