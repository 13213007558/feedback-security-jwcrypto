# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

import time
import unittest
from unittest import mock

from jwcrypto import jwe
from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto import jwt
from jwcrypto import nested
from jwcrypto.common import base64url_decode
from jwcrypto.common import base64url_encode
from jwcrypto.common import json_decode
from jwcrypto.common import json_encode


def _make_ec_key(kid):
    return jwk.JWK.generate(kty='EC', crv='P-256', kid=kid)


def _make_rsa_key(kid):
    return jwk.JWK.generate(kty='RSA', size=2048, kid=kid)


class NestedJWTTestBase(unittest.TestCase):

    def setUp(self):
        self.sender = _make_ec_key('sender-1')
        self.receiver = _make_rsa_key('receiver-1')

        self.inner_key_set = jwk.JWKSet()
        self.inner_key_set.add(self.sender.public())
        self.outer_key_set = jwk.JWKSet()
        self.outer_key_set.add(self.receiver)

        self.policy = nested.NestedJWTValidationPolicy(
            outer_key=self.outer_key_set,
            inner_key=self.inner_key_set,
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'],
            inner_algs=['ES256'],
            check_claims={'iss': 'issuer-a', 'aud': 'audience-a'},
            leeway=30)

    def _sign(self, claims, alg='ES256', kid='sender-1',
              extra_header=None, default_claims=None):
        header = {'alg': alg}
        if kid is not None:
            header['kid'] = kid
        if extra_header:
            header.update(extra_header)
        token = jwt.JWT(header=header, claims=claims,
                        default_claims=default_claims)
        token.make_signed_token(self.sender)
        return token.serialize()

    def _encrypt(self, plaintext, cty='JWT', alg='RSA-OAEP-256',
                 enc='A256GCM', kid='receiver-1', extra_header=None,
                 key=None):
        header = {'alg': alg, 'enc': enc}
        if cty is not None:
            header['cty'] = cty
        if kid is not None:
            header['kid'] = kid
        if extra_header:
            header.update(extra_header)
        token = jwt.JWT(header=header, claims=plaintext)
        token.make_encrypted_token(key or self.receiver)
        return token.serialize()

    def _nested_token(self, claims=None, **sign_kwargs):
        claims = claims or self._valid_claims()
        inner = self._sign(claims, **sign_kwargs)
        return self._encrypt(inner), inner

    @staticmethod
    def _valid_claims(exp_delta=300):
        return {'iss': 'issuer-a', 'aud': 'audience-a', 'sub': 'user-1',
                'exp': int(time.time()) + exp_delta}


class TestNestedJWTHappyPath(NestedJWTTestBase):

    def test_round_trip_with_key_sets(self):
        token, _ = self._nested_token()
        result = nested.NestedJWTValidator(self.policy).validate(token)
        self.assertEqual(result.claims['sub'], 'user-1')
        self.assertEqual(result.outer_header['cty'], 'JWT')
        self.assertEqual(result.outer_header['alg'], 'RSA-OAEP-256')
        self.assertEqual(result.inner_header['alg'], 'ES256')

    def test_round_trip_with_single_jwks(self):
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.receiver,
            inner_key=self.sender.public(),
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'],
            inner_algs=['ES256'],
            check_claims={'iss': 'issuer-a'})
        token, _ = self._nested_token()
        result = nested.validate_nested_jwt(token, policy)
        self.assertEqual(result.claims['iss'], 'issuer-a')

    def test_claims_result_is_deep_copied(self):
        token, _ = self._nested_token()
        validator = nested.NestedJWTValidator(self.policy)
        first = validator.validate(token)
        mutated = first.claims
        mutated['sub'] = 'attacker'
        second = validator.validate(token)
        self.assertEqual(second.claims['sub'], 'user-1')
        self.assertNotIn('sub', first.outer_header)

    def test_outer_same_name_fields_never_join_inner_claims(self):
        # Outer JWE protected header carries same names as inner claims;
        # they must not influence the inner issuer/audience decision.
        inner = self._sign(self._valid_claims())
        token = self._encrypt(
            inner, extra_header={'iss': 'evil-issuer',
                                 'aud': 'evil-audience'})
        result = nested.NestedJWTValidator(self.policy).validate(token)
        self.assertEqual(result.claims['iss'], 'issuer-a')
        self.assertEqual(result.outer_header['iss'], 'evil-issuer')

    def test_result_does_not_retain_key_or_cek_attributes(self):
        token, _ = self._nested_token()
        result = nested.NestedJWTValidator(self.policy).validate(token)
        for name in vars(result):
            self.assertNotIn(name, ('key', 'cek', 'plaintext',
                                    'private_key'))
        self.assertEqual(sorted(vars(result).keys()),
                         ['_claims', '_inner_header', '_outer_header'])


class TestNestedJWTStructure(NestedJWTTestBase):

    def test_bare_jws_is_rejected(self):
        inner = self._sign(self._valid_claims())
        with self.assertRaises(nested.OuterLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(inner)
        self.assertEqual(ctx.exception.layer, 'outer')

    def test_jwe_around_plain_json_is_rejected(self):
        token = self._encrypt(json_encode({'iss': 'issuer-a'}))
        with self.assertRaises(nested.InnerLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(token)
        self.assertEqual(ctx.exception.layer, 'inner')

    def test_wrong_order_jws_wrapping_jwe_is_rejected(self):
        nested_token, _ = self._nested_token()
        # Sign the outer JWE: a JWS whose payload is the JWE compact.
        signed = jwt.JWT(header={'alg': 'ES256'}, claims=nested_token)
        signed.make_signed_token(self.sender)
        with self.assertRaises(nested.OuterLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(
                signed.serialize())
        self.assertEqual(ctx.exception.layer, 'outer')

    def test_double_jwe_nesting_is_rejected(self):
        inner = self._sign(self._valid_claims())
        first = self._encrypt(inner)
        double = self._encrypt(first)
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(self.policy).validate(double)

    def test_json_serialization_is_rejected(self):
        inner = self._sign(self._valid_claims())
        jwe_obj = jwe.JWE(inner,
                          protected={'alg': 'RSA-OAEP-256',
                                     'enc': 'A256GCM', 'cty': 'JWT'})
        jwe_obj.add_recipient(self.receiver)
        json_token = jwe_obj.serialize(compact=False)
        self.assertIsInstance(json_decode(json_token), dict)
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(json_token)

    def test_inner_json_serialization_is_rejected(self):
        claims = json_encode(self._valid_claims())
        jws_obj = jws.JWS(claims)
        jws_obj.add_signature(self.sender, alg='ES256',
                              protected={'alg': 'ES256'})
        json_inner = jws_obj.serialize(compact=False)
        token = self._encrypt(json_inner)
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_missing_cty_is_rejected(self):
        inner = self._sign(self._valid_claims())
        token = self._encrypt(inner, cty=None)
        with self.assertRaises(nested.OuterLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(token)
        self.assertIn('cty', str(ctx.exception))

    def test_wrong_cty_is_rejected(self):
        inner = self._sign(self._valid_claims())
        token = self._encrypt(inner, cty='application/json')
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_malformed_compact_tokens_are_rejected(self):
        # The empty encrypted-key segment at index 1 is legal for "dir",
        # but empty segments at every other position must be rejected.
        for bad in ('', 'a.b', 'a.b.c', 'a.b.c.d',
                    '....', 'a.b.c.d.e.f',
                    '.e.k.iv.ct', 'h.e.k.iv.', 'h.e..iv.ct'):
            with self.subTest(bad=bad):
                with self.assertRaises(nested.OuterLayerError):
                    nested.NestedJWTValidator(self.policy).validate(bad)

    def test_dir_key_management_round_trip(self):
        direct_key = jwk.JWK.generate(kty='oct', size=256, kid='dir-1')
        inner = self._sign(self._valid_claims())
        token = self._encrypt(inner, alg='dir', key=direct_key)
        # The compact "dir" serialization carries an empty encrypted key.
        self.assertEqual(token.split('.')[1], '')
        policy = nested.NestedJWTValidationPolicy(
            outer_key=direct_key, inner_key=self.inner_key_set,
            outer_key_algs=['dir'], outer_content_algs=['A256GCM'],
            inner_algs=['ES256'],
            check_claims={'iss': 'issuer-a', 'aud': 'audience-a'})
        result = nested.NestedJWTValidator(policy).validate(token)
        self.assertEqual(result.claims['sub'], 'user-1')

    def test_non_string_token_is_rejected(self):
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(b'a.b.c.d.e')

    def test_protected_header_that_is_not_an_object_is_rejected(self):
        inner = self._sign(self._valid_claims())
        token = self._encrypt(inner)
        parts = token.split('.')
        parts[0] = base64url_encode(json_encode(['not', 'an', 'object']))
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(
                '.'.join(parts))

    def test_non_string_outer_alg_is_rejected(self):
        inner = self._sign(self._valid_claims())
        token = self._encrypt(inner)
        parts = token.split('.')
        header = json_decode(base64url_decode(parts[0]))
        header['alg'] = 123
        parts[0] = base64url_encode(json_encode(header))
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(
                '.'.join(parts))

    def test_non_string_inner_alg_is_rejected(self):
        inner = self._sign(self._valid_claims())
        parts = inner.split('.')
        header = json_decode(base64url_decode(parts[0]))
        header['alg'] = 123
        parts[0] = base64url_encode(json_encode(header))
        token = self._encrypt('.'.join(parts))
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_inner_protected_header_that_is_not_an_object(self):
        token = self._encrypt(
            base64url_encode(json_encode(['not', 'object'])) +
            '.payload.sig')
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_b64_false_inner_header_is_rejected(self):
        # Manually build a JWS carrying the (critical) b64=false marker.
        payload = json_encode(self._valid_claims())
        jws_obj = jws.JWS(payload.encode('utf-8'))
        jws_obj.add_signature(
            self.sender, alg='ES256',
            protected={'alg': 'ES256', 'b64': False, 'crit': ['b64']})
        token = self._encrypt(jws_obj.serialize(compact=True))
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(self.policy).validate(token)


class TestNestedJWTAlgorithms(NestedJWTTestBase):

    def _policy_with(self, outer_key_algs=None, outer_content_algs=None,
                     inner_algs=None):
        return nested.NestedJWTValidationPolicy(
            outer_key=self.outer_key_set,
            inner_key=self.inner_key_set,
            outer_key_algs=outer_key_algs or ['RSA-OAEP-256'],
            outer_content_algs=outer_content_algs or ['A256GCM'],
            inner_algs=inner_algs or ['ES256'])

    def test_disallowed_outer_key_alg_rejected_before_decrypt(self):
        token, _ = self._nested_token()
        policy = self._policy_with(outer_key_algs=['RSA-OAEP'])
        with self.assertRaises(nested.OuterLayerError) as ctx:
            nested.NestedJWTValidator(policy).validate(token)
        self.assertEqual(ctx.exception.layer, 'outer')

    def test_disallowed_outer_enc_rejected(self):
        token, _ = self._nested_token()
        policy = self._policy_with(outer_content_algs=['A128GCM'])
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(policy).validate(token)

    def test_disallowed_inner_alg_rejected(self):
        token, _ = self._nested_token()
        policy = self._policy_with(inner_algs=['ES384'])
        with self.assertRaises(nested.InnerLayerError) as ctx:
            nested.NestedJWTValidator(policy).validate(token)
        self.assertEqual(ctx.exception.layer, 'inner')

    def test_policy_requires_explicit_alg_lists(self):
        with self.assertRaises(ValueError):
            nested.NestedJWTValidationPolicy(
                outer_key=self.receiver, inner_key=self.sender.public(),
                outer_key_algs=[], outer_content_algs=['A256GCM'],
                inner_algs=['ES256'])
        with self.assertRaises(ValueError):
            nested.NestedJWTValidationPolicy(
                outer_key=self.receiver, inner_key=self.sender.public(),
                outer_key_algs=['RSA-OAEP-256'],
                outer_content_algs=['A256GCM'],
                inner_algs=123)
        with self.assertRaises(ValueError):
            nested.NestedJWTValidationPolicy(
                outer_key=self.receiver, inner_key=self.sender.public(),
                outer_key_algs=['RSA-OAEP-256'],
                outer_content_algs=['A256GCM'],
                inner_algs=[123])
        # A non-empty tuple is accepted and normalized to a list.
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.receiver, inner_key=self.sender.public(),
            outer_key_algs=('RSA-OAEP-256',),
            outer_content_algs=('A256GCM',), inner_algs=('ES256',))
        self.assertEqual(policy.inner_algs, ['ES256'])

    def test_policy_rejects_wrong_key_types(self):
        with self.assertRaises(TypeError):
            nested.NestedJWTValidationPolicy(
                outer_key='not-a-key', inner_key=self.sender.public(),
                outer_key_algs=['RSA-OAEP-256'],
                outer_content_algs=['A256GCM'],
                inner_algs=['ES256'])

    def test_validator_requires_policy_instance(self):
        with self.assertRaises(TypeError):
            nested.NestedJWTValidator({'outer_key': self.receiver})


class TestNestedJWTKeys(NestedJWTTestBase):

    def test_swapped_key_sets_fail_at_outer_layer(self):
        swapped = nested.NestedJWTValidationPolicy(
            outer_key=self.inner_key_set,
            inner_key=self.outer_key_set,
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'],
            inner_algs=['ES256'])
        token, _ = self._nested_token()
        with self.assertRaises(nested.OuterKeyError) as ctx:
            nested.NestedJWTValidator(swapped).validate(token)
        self.assertEqual(ctx.exception.layer, 'outer')

    def test_inner_kid_unknown_to_inner_set(self):
        other = _make_ec_key('sender-other')
        other_set = jwk.JWKSet()
        other_set.add(other.public())
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.outer_key_set, inner_key=other_set,
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'], inner_algs=['ES256'])
        token, _ = self._nested_token()
        with self.assertRaises(nested.InnerKeyError) as ctx:
            nested.NestedJWTValidator(policy).validate(token)
        self.assertEqual(ctx.exception.layer, 'inner')

    def test_outer_kid_unknown_to_outer_set(self):
        other_receiver = _make_rsa_key('receiver-other')
        other_set = jwk.JWKSet()
        other_set.add(other_receiver)
        policy = nested.NestedJWTValidationPolicy(
            outer_key=other_set, inner_key=self.inner_key_set,
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'], inner_algs=['ES256'])
        token, _ = self._nested_token()
        with self.assertRaises(nested.OuterKeyError):
            nested.NestedJWTValidator(policy).validate(token)

    def test_empty_inner_key_set(self):
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.outer_key_set, inner_key=jwk.JWKSet(),
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'], inner_algs=['ES256'])
        token, _ = self._nested_token()
        with self.assertRaises(nested.InnerKeyError):
            nested.NestedJWTValidator(policy).validate(token)

    def test_tampered_inner_signature_fails_at_inner_layer(self):
        token, inner = self._nested_token()
        parts = inner.split('.')
        signature = bytearray(base64url_decode(parts[2]))
        signature[0] ^= 0x01
        parts[2] = base64url_encode(bytes(signature))
        tampered = self._encrypt('.'.join(parts))
        with self.assertRaises(nested.InnerLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(tampered)
        self.assertEqual(ctx.exception.layer, 'inner')

    def test_signature_mismatch_with_single_jwk_is_layer_error(self):
        # A wrong signing key presented as a single JWK (no kid lookup)
        # must surface as an inner layer failure, not an inner key error.
        rogue = _make_ec_key(None)
        claims = self._valid_claims()
        inner = jwt.JWT(header={'alg': 'ES256'}, claims=claims,
                        default_claims={'exp': claims['exp'],
                                        'iat': None, 'nbf': None})
        inner.make_signed_token(rogue)
        token = self._encrypt(inner.serialize())
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.receiver, inner_key=self.sender.public(),
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'], inner_algs=['ES256'],
            check_claims={'iss': 'issuer-a'})
        with self.assertRaises(nested.InnerLayerError):
            nested.NestedJWTValidator(policy).validate(token)

    def test_tampered_outer_ciphertext_fails_at_outer_layer(self):
        token, _ = self._nested_token()
        parts = token.split('.')
        ciphertext = bytearray(base64url_decode(parts[3]))
        ciphertext[0] ^= 0x01
        parts[3] = base64url_encode(bytes(ciphertext))
        with self.assertRaises(nested.OuterLayerError):
            nested.NestedJWTValidator(self.policy).validate(
                '.'.join(parts))


class TestNestedJWTClaims(NestedJWTTestBase):

    def test_expired_claims_rejected_at_claims_layer(self):
        claims = self._valid_claims(exp_delta=-100)
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        with self.assertRaises(nested.ClaimsValidationError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(token)
        self.assertEqual(ctx.exception.layer, 'claims')
        self.assertIn('expired', str(ctx.exception))

    def test_not_yet_valid_rejected(self):
        claims = dict(self._valid_claims(),
                      nbf=int(time.time()) + 500)
        token, _ = self._nested_token(
            claims, default_claims={'nbf': claims['nbf'],
                                    'iat': None, 'exp': None})
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_missing_required_claim_rejected(self):
        claims = self._valid_claims()
        del claims['aud']
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        with self.assertRaises(nested.ClaimsValidationError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(token)
        self.assertIn('missing', str(ctx.exception))

    def test_unexpected_claim_value_rejected(self):
        claims = dict(self._valid_claims(), iss='evil-issuer')
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_audience_match_semantics(self):
        claims = dict(self._valid_claims(),
                      aud=['other-aud', 'audience-a'])
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        result = nested.NestedJWTValidator(self.policy).validate(token)
        self.assertEqual(result.claims['aud'],
                         ['other-aud', 'audience-a'])

    def test_non_object_inner_payload_rejected(self):
        # Sign a JSON array rather than an object of claims.
        jws_obj = jws.JWS(json_encode(['not', 'claims']))
        jws_obj.add_signature(self.sender, alg='ES256',
                              protected={'alg': 'ES256'})
        token = self._encrypt(jws_obj.serialize(compact=True))
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_non_json_inner_payload_rejected(self):
        jws_obj = jws.JWS(b'not-json-text')
        jws_obj.add_signature(self.sender, alg='ES256',
                              protected={'alg': 'ES256'})
        token = self._encrypt(jws_obj.serialize(compact=True))
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_check_claims_false_still_enforces_expiry(self):
        policy = nested.NestedJWTValidationPolicy(
            outer_key=self.outer_key_set,
            inner_key=self.inner_key_set,
            outer_key_algs=['RSA-OAEP-256'],
            outer_content_algs=['A256GCM'],
            inner_algs=['ES256'],
            check_claims=False)
        claims = self._valid_claims(exp_delta=-100)
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(policy).validate(token)

    def test_invalid_claim_format_rejected(self):
        claims = dict(self._valid_claims(), iss=1234)
        token, _ = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})
        with self.assertRaises(nested.ClaimsValidationError):
            nested.NestedJWTValidator(self.policy).validate(token)

    def test_non_utf8_inner_payload_rejected(self):
        # Encrypt raw bytes that are not valid UTF-8.
        jwe_obj = jwe.JWE(b'\xff\xfe\x00\x01',
                          protected={'alg': 'RSA-OAEP-256',
                                     'enc': 'A256GCM', 'cty': 'JWT'})
        jwe_obj.add_recipient(self.receiver)
        with self.assertRaises(nested.InnerLayerError) as ctx:
            nested.NestedJWTValidator(self.policy).validate(
                jwe_obj.serialize(compact=True))
        self.assertEqual(ctx.exception.layer, 'inner')

    def test_verified_result_repr_is_informative(self):
        token, _ = self._nested_token()
        result = nested.NestedJWTValidator(self.policy).validate(token)
        rendered = repr(result)
        self.assertTrue(rendered.startswith('VerifiedNestedJWT('))
        self.assertIn('user-1', rendered)


class TestNestedJWTErrorSafety(NestedJWTTestBase):

    def test_error_hierarchy_and_layers(self):
        self.assertTrue(issubclass(nested.OuterKeyError,
                                   nested.OuterLayerError))
        self.assertTrue(issubclass(nested.InnerKeyError,
                                   nested.InnerLayerError))
        self.assertTrue(issubclass(nested.OuterLayerError,
                                   nested.NestedJWTError))
        self.assertTrue(issubclass(nested.ClaimsValidationError,
                                   nested.NestedJWTError))
        self.assertEqual(nested.OuterKeyError.layer, 'outer')
        self.assertEqual(nested.InnerLayerError.layer, 'inner')
        self.assertEqual(nested.ClaimsValidationError.layer, 'claims')

    def test_errors_never_carry_decrypted_payload(self):
        # Build a token whose inner payload has a distinctive secret.
        secret = 'TOP-SERET-PAYLOAD-MARKER'
        claims = dict(self._valid_claims(), secret=secret)
        token, inner = self._nested_token(
            claims, default_claims={'exp': claims['exp'],
                                    'iat': None, 'nbf': None})

        # Tamper the signature so validation fails at the inner layer.
        parts = inner.split('.')
        signature = bytearray(base64url_decode(parts[2]))
        signature[0] ^= 0x01
        parts[2] = base64url_encode(bytes(signature))
        tampered = self._encrypt('.'.join(parts))
        try:
            nested.NestedJWTValidator(self.policy).validate(tampered)
            self.fail('validation should have failed')
        except nested.NestedJWTError as error:
            rendered = repr(error) + str(error)
            self.assertNotIn(secret, rendered)
            # Exception chaining is suppressed ("raise ... from None")
            # so the original library exception, whose text may quote
            # crypto internals, is not surfaced to callers.
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)

    def test_outer_failure_does_not_expose_plaintext(self):
        token, _ = self._nested_token()
        parts = token.split('.')
        ciphertext = bytearray(base64url_decode(parts[3]))
        ciphertext[0] ^= 0x01
        parts[3] = base64url_encode(bytes(ciphertext))
        try:
            nested.NestedJWTValidator(self.policy).validate(
                '.'.join(parts))
            self.fail('validation should have failed')
        except nested.OuterLayerError as error:
            self.assertNotIn('user-1', str(error))
            self.assertIsNone(error.__cause__)

    def test_cek_is_cleared_after_decryption_attempt(self):
        captured = {}
        original_payload = jwe.JWE.payload.fget

        def spying_payload(self):
            captured['cek_before_finally'] = self.cek
            captured['plaintext_before_finally'] = self.plaintext
            return original_payload(self)

        token, _ = self._nested_token()
        with mock.patch.object(jwe.JWE, 'payload',
                               new=property(spying_payload)):
            result = nested.NestedJWTValidator(
                self.policy).validate(token)
        # The decryption genuinely produced a CEK and plaintext...
        self.assertIsNotNone(captured['cek_before_finally'])
        self.assertIsNotNone(captured['plaintext_before_finally'])
        # ...but only the validated business claims are exposed.
        self.assertEqual(result.claims['sub'], 'user-1')
        self.assertFalse(hasattr(result, 'cek'))

    def test_local_plaintext_is_not_stored_on_validator(self):
        token, _ = self._nested_token()
        validator = nested.NestedJWTValidator(self.policy)
        validator.validate(token)
        self.assertEqual(sorted(vars(validator).keys()), ['policy'])


if __name__ == '__main__':
    unittest.main()
