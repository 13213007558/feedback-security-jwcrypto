Strict Nested JWT (JWE wrapping JWS)
====================================

The nested Module provides an explicit, strict verification interface for
the "sign then encrypt" token model of `RFC 7519 section 11.2`_: one JWE
layer whose plaintext is exactly one JWS layer.

Applications that decrypt and verify in two manual steps risk consuming
the inner claims as soon as the outer decryption succeeds, before the
inner signature has been checked.  The
:class:`jwcrypto.nested.NestedJWTValidator` removes that footgun: the
business claims are only exposed after the outer JWE, the inner JWS and
the inner claims conditions have all passed.

The trusted configuration is never inferred from the token.  The caller
supplies, through a :class:`jwcrypto.nested.NestedJWTValidationPolicy`:

* the outer decryption key (or key set),
* the inner signature verification key (or key set),
* an allow list for the outer key management algorithm (``alg``),
* an allow list for the outer content encryption algorithm (``enc``),
* an allow list for the inner signing algorithm (``alg``),
* the expected inner claims.

A token is rejected, with a layer-specific exception, when it is not a
compact JWE, when the outer protected header does not carry
``cty = "JWT"``, when an algorithm is not allowed, when the decrypted
plaintext is not exactly one compact JWS (for example plain JSON, a JWS
wrapping a JWE, or an extra nesting layer), when the signature is
invalid, or when the inner claims do not match.  Error messages never
contain the decrypted payload, a content encryption key or key material.

.. _RFC 7519 section 11.2: https://www.rfc-editor.org/rfc/rfc7519#section-11.2

Classes
-------

.. autoclass:: jwcrypto.nested.NestedJWTValidationPolicy
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested.NestedJWTValidator
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested.VerifiedNestedJWT
   :members:
   :show-inheritance:

Functions
---------

.. autofunction:: jwcrypto.nested.validate_nested_jwt

Exceptions
----------

All errors inherit from :class:`jwcrypto.nested.NestedJWTError` and
expose a ``layer`` attribute equal to ``"outer"``, ``"inner"`` or
``"claims"``.

.. autoclass:: jwcrypto.nested.NestedJWTError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested.OuterLayerError
   :show-inheritance:

.. autoclass:: jwcrypto.nested.OuterKeyError
   :show-inheritance:

.. autoclass:: jwcrypto.nested.InnerLayerError
   :show-inheritance:

.. autoclass:: jwcrypto.nested.InnerKeyError
   :show-inheritance:

.. autoclass:: jwcrypto.nested.ClaimsValidationError
   :show-inheritance:

Example
-------

The sender signs with its own EC key; the receiver decrypts with an
independent symmetric key.  The two keys are never interchangeable, and
the ``kid`` of each layer is only resolved inside that layer's key set.

    >>> from jwcrypto import jwk, jwt
    >>> from jwcrypto.nested import NestedJWTValidationPolicy
    >>> from jwcrypto.nested import NestedJWTValidator
    >>> from jwcrypto.nested import NestedJWTError
    >>> enc_key = jwk.JWK(
    ...     kty='oct',
    ...     k='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    ...     kid='receiver-1')
    >>> sig_key = jwk.JWK(
    ...     kty='EC', crv='P-256',
    ...     x='MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
    ...     y='4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
    ...     d='870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
    ...     kid='sender-1')
    >>> claims = {'iss': 'issuer-a', 'aud': 'audience-a',
    ...           'sub': 'user-1', 'exp': 1893456000}
    >>> signed = jwt.JWT(
    ...     header={'alg': 'ES256', 'kid': 'sender-1'},
    ...     claims=claims,
    ...     default_claims={'exp': claims['exp'],
    ...                     'iat': None, 'nbf': None})
    >>> signed.make_signed_token(sig_key)
    >>> nested_token = jwt.JWT(
    ...     header={'alg': 'dir', 'enc': 'A256GCM',
    ...             'cty': 'JWT', 'kid': 'receiver-1'},
    ...     claims=signed.serialize())
    >>> nested_token.make_encrypted_token(enc_key)
    >>> policy = NestedJWTValidationPolicy(
    ...     outer_key=enc_key, inner_key=sig_key.public(),
    ...     outer_key_algs=['dir'],
    ...     outer_content_algs=['A256GCM'],
    ...     inner_algs=['ES256'],
    ...     check_claims={'iss': 'issuer-a', 'aud': 'audience-a'})
    >>> verified = NestedJWTValidator(policy).validate(
    ...     nested_token.serialize())
    >>> verified.claims['sub']
    'user-1'
    >>> verified.outer_header['cty']
    'JWT'

A nested token whose outer header omits ``cty`` is rejected at the
outer layer, without ever exposing the decrypted inner token:

    >>> no_cty = jwt.JWT(
    ...     header={'alg': 'dir', 'enc': 'A256GCM'},
    ...     claims=signed.serialize())
    >>> no_cty.make_encrypted_token(enc_key)
    >>> try:
    ...     NestedJWTValidator(policy).validate(no_cty.serialize())
    ... except NestedJWTError as error:
    ...     print(error.layer)
    outer
