#!/usr/bin/env python3
"""End-to-end example for strict sign-then-encrypt nested JWT validation.

The sender holds an independent signing key; the receiving service holds
an independent decryption key.  A token is signed first and encrypted
second, then validated through :class:`jwcrypto.nested.NestedJWTValidator`,
which requires exactly one JWE layer around one JWS layer and only
exposes the business claims after both cryptographic layers and the
inner claims checks pass.

Run with the repository root on the import path, e.g.::

    python examples/nested_jwt.py
"""

import json
import time

from jwcrypto import jwk
from jwcrypto import jwt
from jwcrypto.common import base64url_decode
from jwcrypto.common import base64url_encode
from jwcrypto.nested import NestedJWTError
from jwcrypto.nested import NestedJWTValidationPolicy
from jwcrypto.nested import NestedJWTValidator


def build_token(signing_key, encryption_key, claims, cty='JWT',
                sign_alg='ES256', wrap_alg='RSA-OAEP-256',
                enc_alg='A256GCM'):
    """Sign claims first, then encrypt the resulting compact JWS."""
    signed = jwt.JWT(
        header={'alg': sign_alg, 'kid': signing_key.get('kid')},
        claims=claims,
        default_claims={'exp': claims.get('exp'),
                        'iat': None, 'nbf': None})
    signed.make_signed_token(signing_key)

    outer_header = {'alg': wrap_alg, 'enc': enc_alg,
                    'kid': encryption_key.get('kid')}
    if cty is not None:
        outer_header['cty'] = cty
    encrypted = jwt.JWT(header=outer_header,
                        claims=signed.serialize())
    encrypted.make_encrypted_token(encryption_key)
    return encrypted.serialize()


def expect_rejection(label, validator, token):
    try:
        validator.validate(token)
    except NestedJWTError as error:
        print('%-28s -> rejected at %-6s layer: %s'
              % (label, error.layer, error))
        return
    raise SystemExit('%s was unexpectedly accepted' % label)


def main():
    # Independent sender signing key and receiver decryption key.
    sender_key = jwk.JWK.generate(kty='EC', crv='P-256', kid='sender-1')
    receiver_key = jwk.JWK.generate(kty='RSA', size=2048,
                                    kid='receiver-1')

    verification_keys = jwk.JWKSet()
    verification_keys.add(sender_key.public())
    decryption_keys = jwk.JWKSet()
    decryption_keys.add(receiver_key)

    policy = NestedJWTValidationPolicy(
        outer_key=decryption_keys,
        inner_key=verification_keys,
        outer_key_algs=['RSA-OAEP-256'],
        outer_content_algs=['A256GCM'],
        inner_algs=['ES256'],
        check_claims={'iss': 'order-service', 'aud': 'billing-api'},
        leeway=30)
    validator = NestedJWTValidator(policy)

    business_claims = {
        'iss': 'order-service',
        'aud': 'billing-api',
        'sub': 'customer-42',
        'role': 'reader',
        'exp': int(time.time()) + 300,
    }

    print('== negative cases (each must be rejected) ==')

    # 1. Swap the two key sets: the EC verification set cannot decrypt.
    swapped_policy = NestedJWTValidationPolicy(
        outer_key=verification_keys,
        inner_key=decryption_keys,
        outer_key_algs=['RSA-OAEP-256'],
        outer_content_algs=['A256GCM'],
        inner_algs=['ES256'])
    good_token = build_token(sender_key, receiver_key, business_claims)
    expect_rejection('swapped key sets',
                     NestedJWTValidator(swapped_policy), good_token)

    # 2. Modify the inner signature after encryption round trip.
    decrypted_inner = jwt.JWT(
        jwt=good_token, key=receiver_key,
        expected_type='JWE').claims
    parts = decrypted_inner.split('.')
    signature = bytearray(base64url_decode(parts[2]))
    signature[0] ^= 0x01
    parts[2] = base64url_encode(bytes(signature))
    resigned_outer = jwt.JWT(
        header={'alg': 'RSA-OAEP-256', 'enc': 'A256GCM', 'cty': 'JWT'},
        claims='.'.join(parts))
    resigned_outer.make_encrypted_token(receiver_key)
    expect_rejection('modified inner signature', validator,
                     resigned_outer.serialize())

    # 3. Missing outer cty header.
    expect_rejection('missing cty header', validator,
                     build_token(sender_key, receiver_key,
                                 business_claims, cty=None))

    # 4. Expired inner claims.
    expired_claims = dict(business_claims, exp=int(time.time()) - 120)
    expect_rejection('expired inner claims', validator,
                     build_token(sender_key, receiver_key,
                                 expired_claims))

    # 5. Plain JSON masquerading as the signed inner token.
    plain_json = jwt.JWT(
        header={'alg': 'RSA-OAEP-256', 'enc': 'A256GCM', 'cty': 'JWT'},
        claims=json.dumps(business_claims))
    plain_json.make_encrypted_token(receiver_key)
    expect_rejection('plain JSON instead of JWS', validator,
                     plain_json.serialize())

    # 6. Wrong order (JWS wrapped around the JWE).
    signed_jwe = jwt.JWT(header={'alg': 'ES256'}, claims=good_token)
    signed_jwe.make_signed_token(sender_key)
    expect_rejection('JWS wrapping JWE (wrong order)', validator,
                     signed_jwe.serialize())

    print()
    print('== happy path ==')
    verified = validator.validate(
        build_token(sender_key, receiver_key, business_claims))
    print('outer cty :', verified.outer_header['cty'])
    print('inner alg :', verified.inner_header['alg'])

    # The last line hands back only the fully validated business object.
    print('verified business object:', verified.claims)


if __name__ == '__main__':
    main()
