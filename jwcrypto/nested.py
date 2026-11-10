# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Strict nested JWT verification (one JWE layer wrapping one JWS layer).

This module implements the "sign then encrypt" token model described in
RFC 7519 section 11.2: an inner signed JWT is the plaintext of an outer
encrypted JWT.  Unlike composing :class:`jwcrypto.jwt.JWT` calls manually,
the :class:`NestedJWTValidator` never exposes the decrypted inner token
before the signature and the claims have both been validated, never
guesses the trusted configuration from the token content, and reports
which of the two cryptographic layers (or the claims check) rejected the
token.

The trusted configuration is fully supplied by the caller through a
:class:`NestedJWTValidationPolicy`:

* separate keys for outer decryption and inner signature verification,
* explicit allow lists for the outer key management algorithm, the
  outer content encryption algorithm and the inner signing algorithm,
* expected inner claims.

Only the compact serialization is accepted, the outer JWE protected
header must carry ``cty`` equal to ``"JWT"`` (RFC 7519 section 5.2),
and the inner payload must itself be a compact JWS whose payload is a
JSON object.  A bare JWS, a bare JWE around plain JSON, a JWS wrapping a
JWE (wrong order), additional nesting layers and JSON serializations
are all rejected.
"""

import copy
import time

from jwcrypto.common import JWException
from jwcrypto.common import JWKeyNotFound
from jwcrypto.common import base64url_decode
from jwcrypto.common import json_decode
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwk import JWKSet
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT
from jwcrypto.jwt import JWTExpired
from jwcrypto.jwt import JWTInvalidClaimFormat
from jwcrypto.jwt import JWTInvalidClaimValue
from jwcrypto.jwt import JWTMissingClaim
from jwcrypto.jwt import JWTNotYetValid


# RFC 7519 section 5.2: a nested JWT uses "JWT" as the outer cty value.
_EXPECTED_OUTER_CTY = 'JWT'


class NestedJWTError(JWException):
    """Base class for all nested JWT validation failures.

    Every subclass is bound to the validation stage that failed through
    its :attr:`layer` attribute.  Error messages never contain the
    decrypted payload, a content encryption key or any key material.
    """

    #: Stage at which the failure occurred, one of
    #: ``"outer"``, ``"inner"`` or ``"claims"``.
    layer = None

    def __init__(self, message=None):
        if message is None:
            message = self.default_message
        super().__init__(message)

    @property
    def default_message(self):
        """Generic, non-revealing message for this error type."""
        raise NotImplementedError


class OuterLayerError(NestedJWTError):
    """The outer JWE layer could not be accepted.

    Raised for malformed or unexpected serialization, a missing or
    incorrect ``cty`` header, disallowed outer algorithms, or a failed
    decryption.
    """

    layer = 'outer'
    default_message = 'Outer JWE layer validation failed'


class OuterKeyError(OuterLayerError):
    """No acceptable outer decryption key was found."""

    default_message = 'No matching outer decryption key'


class InnerLayerError(NestedJWTError):
    """The inner JWS layer could not be accepted.

    Raised when the decrypted plaintext is not exactly one compact JWS,
    uses a disallowed signing algorithm, or fails signature verification.
    """

    layer = 'inner'
    default_message = 'Inner JWS layer validation failed'


class InnerKeyError(InnerLayerError):
    """No acceptable inner verification key was found."""

    default_message = 'No matching inner verification key'


class ClaimsValidationError(NestedJWTError):
    """The inner claims are malformed or do not match the policy."""

    layer = 'claims'
    default_message = 'Inner claims validation failed'


class NestedJWTValidationPolicy:
    """Trusted configuration for a sign-then-encrypt nested JWT.

    All security parameters are explicit: nothing is inferred from the
    token headers or payload.  Construct once and reuse it across
    requests.

    :param outer_key: A :class:`jwcrypto.jwk.JWK` or
     :class:`jwcrypto.jwk.JWKSet` used only to decrypt the outer JWE.
    :param inner_key: A :class:`jwcrypto.jwk.JWK` or
     :class:`jwcrypto.jwk.JWKSet` used only to verify the inner JWS
     signature.
    :param outer_key_algs: Allow list of accepted outer JWE key
     management algorithms (the outer ``alg`` header), e.g.
     ``['RSA-OAEP-256']``.
    :param outer_content_algs: Allow list of accepted outer JWE content
     encryption algorithms (the outer ``enc`` header), e.g.
     ``['A256GCM']``.
    :param inner_algs: Allow list of accepted inner JWS signing
     algorithms (the inner ``alg`` header), e.g. ``['ES256']``.
    :param check_claims: Optional claims conditions applied exclusively
     to the inner claims.  Follows the ``check_claims`` semantics of
     :class:`jwcrypto.jwt.JWT`: listing a claim requires its presence,
     a non-``None`` value must match (with the special ``aud``, ``exp``,
     ``nbf`` and ``scope`` handling), and ``False`` skips every claim
     check.  When ``None``, registered claims are still checked for
     format and ``exp``/``nbf`` time validity.
    :param leeway: Clock skew in seconds accepted for the ``exp`` and
     ``nbf`` time checks.
    """

    def __init__(self, outer_key, inner_key, outer_key_algs,
                 outer_content_algs, inner_algs, check_claims=None,
                 leeway=60):
        self._validate_key(outer_key, 'outer_key')
        self._validate_key(inner_key, 'inner_key')
        self._validate_algs(outer_key_algs, 'outer_key_algs')
        self._validate_algs(outer_content_algs, 'outer_content_algs')
        self._validate_algs(inner_algs, 'inner_algs')

        self.outer_key = outer_key
        self.inner_key = inner_key
        self.outer_key_algs = list(outer_key_algs)
        self.outer_content_algs = list(outer_content_algs)
        self.inner_algs = list(inner_algs)
        self.check_claims = check_claims
        self.leeway = int(leeway)

    @staticmethod
    def _validate_key(key, name):
        if not isinstance(key, (JWK, JWKSet)):
            raise TypeError(
                '%s must be a JWK or JWKSet' % name)

    @staticmethod
    def _validate_algs(algs, name):
        if not isinstance(algs, (list, tuple)) or not algs:
            raise ValueError(
                '%s must be a non-empty list of algorithm names' % name)
        if not all(isinstance(alg, str) for alg in algs):
            raise ValueError(
                '%s must contain only algorithm name strings' % name)


class VerifiedNestedJWT:
    """Result of a successful nested JWT validation.

    Instances are only produced by :class:`NestedJWTValidator` after the
    outer JWE, the inner JWS and the inner claims have all been
    validated.  They carry plain dictionaries only; no decrypted token
    object, content encryption key or private key is retained.
    """

    def __init__(self, outer_header, inner_header, claims):
        self._outer_header = copy.deepcopy(outer_header)
        self._inner_header = copy.deepcopy(inner_header)
        self._claims = copy.deepcopy(claims)

    @property
    def outer_header(self):
        """A copy of the validated outer JWE protected header."""
        return copy.deepcopy(self._outer_header)

    @property
    def inner_header(self):
        """A copy of the validated inner JWS protected header."""
        return copy.deepcopy(self._inner_header)

    @property
    def claims(self):
        """The validated inner business claims as a dictionary.

        Outer JWE header fields with the same name are never merged in,
        so issuer, audience and similar checks only ever see the inner
        claims.
        """
        return copy.deepcopy(self._claims)

    def __repr__(self):
        return ('VerifiedNestedJWT(outer_header=%r, inner_header=%r, '
                'claims=%r)' % (self._outer_header, self._inner_header,
                                self._claims))


class NestedJWTValidator:
    """Validates one-JWE-wrapping-one-JWS nested tokens.

    A validator is bound to a :class:`NestedJWTValidationPolicy` and is
    safe to reuse across tokens.  Calling :meth:`validate` either returns
    a :class:`VerifiedNestedJWT` or raises a :class:`NestedJWTError`
    whose :attr:`~NestedJWTError.layer` identifies the failing stage.
    """

    def __init__(self, policy):
        if not isinstance(policy, NestedJWTValidationPolicy):
            raise TypeError(
                'policy must be a NestedJWTValidationPolicy')
        self.policy = policy

    def validate(self, token):
        """Validate a compact, sign-then-encrypt nested JWT.

        :param token: The raw outer JWE compact serialization.
        :returns: A :class:`VerifiedNestedJWT` holding the validated
         inner claims.
        :raises OuterLayerError: if the token is not an acceptable outer
         JWE (serialization, ``cty``, algorithms or decryption).
        :raises OuterKeyError: if no outer decryption key matches.
        :raises InnerLayerError: if the plaintext is not exactly one
         acceptable inner JWS or its signature is invalid.
        :raises InnerKeyError: if no inner verification key matches.
        :raises ClaimsValidationError: if the inner claims are malformed
         or fail the policy's claim conditions.
        """
        outer_header = self._parse_outer_structure(token)
        plaintext = self._decrypt_outer(token)
        try:
            inner_token = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            raise InnerLayerError(
                'Inner JWS layer is not UTF-8 encoded') from None

        inner_header = self._parse_inner_structure(inner_token)
        inner_payload = self._verify_inner(inner_token)
        claims = self._validate_claims(inner_payload)
        return VerifiedNestedJWT(outer_header, inner_header, claims)

    # -- outer JWE -----------------------------------------------------

    def _parse_outer_structure(self, token):
        if not isinstance(token, str):
            raise OuterLayerError(
                'Token must be a compact serialization string')
        # A JSON object would be the general JSON serialization, which
        # RFC 7519 forbids for JWTs and this interface never accepts.
        try:
            if isinstance(json_decode(token), dict):
                raise OuterLayerError(
                    'JSON serialization is not allowed, only the '
                    'compact serialization')
        except OuterLayerError:
            raise
        except ValueError:
            pass

        parts = token.split('.')
        if len(parts) != 5:
            raise OuterLayerError(
                'Expected a compact JWE with exactly five parts')
        # In the compact JWE serialization the encrypted key part is
        # legitimately empty for the "dir" key management algorithm
        # (RFC 7516 section 7.2.2); the other four parts must be present.
        if any(part == '' for index, part in enumerate(parts)
               if index != 1):
            raise OuterLayerError(
                'Compact JWE has an empty required part')

        try:
            protected = json_decode(
                base64url_decode(parts[0]).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise OuterLayerError(
                'Outer JWE protected header is not valid JSON') \
                from None
        if not isinstance(protected, dict):
            raise OuterLayerError(
                'Outer JWE protected header must be a JSON object')

        alg = protected.get('alg')
        enc = protected.get('enc')
        if not isinstance(alg, str) or not isinstance(enc, str):
            raise OuterLayerError(
                'Outer JWE header must contain string alg and enc')
        if alg not in self.policy.outer_key_algs:
            raise OuterLayerError(
                'Outer key management algorithm is not allowed')
        if enc not in self.policy.outer_content_algs:
            raise OuterLayerError(
                'Outer content encryption algorithm is not allowed')
        if protected.get('cty') != _EXPECTED_OUTER_CTY:
            raise OuterLayerError(
                'Outer JWE cty header must be exactly "JWT"')
        return protected

    def _decrypt_outer(self, token):
        jwe = JWE()
        jwe.allowed_algs = (self.policy.outer_key_algs +
                            self.policy.outer_content_algs)
        key = self._select_key(self.policy.outer_key, OuterKeyError)
        try:
            jwe.deserialize(token, key)
            plaintext = jwe.payload
        except JWKeyNotFound:
            raise OuterKeyError() from None
        except JWException:
            raise OuterLayerError() from None
        finally:
            # Drop references that could retain the CEK or plaintext on
            # the object kept alive by a traceback.
            jwe.cek = None
            jwe.plaintext = None
        return plaintext

    # -- inner JWS -----------------------------------------------------

    def _parse_inner_structure(self, inner_token):
        try:
            if isinstance(json_decode(inner_token), dict):
                raise InnerLayerError(
                    'Decrypted content is plain JSON, not a signed JWS')
        except InnerLayerError:
            raise
        except ValueError:
            pass

        parts = inner_token.split('.')
        if len(parts) != 3 or any(part == '' for part in parts):
            raise InnerLayerError(
                'Expected a compact JWS with exactly three parts; '
                'rejecting plain JSON or additional nesting')

        try:
            protected = json_decode(
                base64url_decode(parts[0]).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise InnerLayerError(
                'Inner JWS protected header is not valid JSON') \
                from None
        if not isinstance(protected, dict):
            raise InnerLayerError(
                'Inner JWS protected header must be a JSON object')
        if protected.get('b64') is False:
            raise InnerLayerError(
                'Unencoded (b64=false) JWS payloads are not allowed')
        alg = protected.get('alg')
        if not isinstance(alg, str):
            raise InnerLayerError(
                'Inner JWS header must contain a string alg')
        if alg not in self.policy.inner_algs:
            raise InnerLayerError(
                'Inner signing algorithm is not allowed')
        return protected

    def _verify_inner(self, inner_token):
        jws = JWS()
        jws.allowed_algs = self.policy.inner_algs
        key = self._select_key(self.policy.inner_key, InnerKeyError)
        try:
            jws.deserialize(inner_token, key)
            payload = jws.payload
        except JWKeyNotFound:
            raise InnerKeyError() from None
        except JWException:
            raise InnerLayerError() from None
        return payload

    # -- claims --------------------------------------------------------

    def _validate_claims(self, payload):
        if isinstance(payload, bytes):
            try:
                payload = payload.decode('utf-8')
            except UnicodeDecodeError:
                raise ClaimsValidationError(
                    'Inner payload is not UTF-8 encoded') from None
        try:
            claims = json_decode(payload)
        except ValueError:
            raise ClaimsValidationError(
                'Inner payload is not valid JSON') from None
        if not isinstance(claims, dict):
            raise ClaimsValidationError(
                'Inner payload must be a JSON object of claims')

        checker = JWT(check_claims=self.policy.check_claims)
        checker.leeway = self.policy.leeway
        try:
            # Registered-claim format checks always apply, including
            # when check_claims is False (which would otherwise skip
            # them inside _check_provided_claims).
            checker._check_default_claims(  # pylint: disable=protected-access
                claims)
            # The JWT class only enforces exp/nbf when no check_claims
            # dict is supplied; nested validation always enforces the
            # time validity present in the claims.
            if 'exp' in claims:
                checker._check_exp(  # pylint: disable=protected-access
                    claims['exp'], time.time(), self.policy.leeway)
            if 'nbf' in claims:
                checker._check_nbf(  # pylint: disable=protected-access
                    claims['nbf'], time.time(), self.policy.leeway)
            checked = checker._check_provided_claims(
                claims)  # pylint: disable=protected-access
        except JWTExpired:
            raise ClaimsValidationError('Inner token is expired') \
                from None
        except JWTNotYetValid:
            raise ClaimsValidationError(
                'Inner token is not yet valid') from None
        except JWTMissingClaim:
            raise ClaimsValidationError(
                'A required inner claim is missing') from None
        except JWTInvalidClaimValue:
            raise ClaimsValidationError(
                'An inner claim does not match the expected value') \
                from None
        except JWTInvalidClaimFormat:
            raise ClaimsValidationError(
                'An inner claim has an invalid format') from None
        except JWException:
            raise ClaimsValidationError() from None
        return json_decode(checked)

    # -- helpers -------------------------------------------------------

    @staticmethod
    def _select_key(key, key_error):
        """Resolve a key strictly within one layer's key set.

        The token ``kid`` is only ever looked up in the key set of the
        current layer; the outer and inner sets are never shared.
        """
        if isinstance(key, JWK):
            return key
        if len(key['keys']) == 0:
            raise key_error()
        return key


def validate_nested_jwt(token, policy):
    """Module-level convenience wrapper around :class:`NestedJWTValidator`.

    :param token: The raw outer JWE compact serialization.
    :param policy: The :class:`NestedJWTValidationPolicy` describing the
     trusted keys, algorithms and claims conditions.
    :returns: A :class:`VerifiedNestedJWT`.
    """
    return NestedJWTValidator(policy).validate(token)
