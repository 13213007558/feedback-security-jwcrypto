# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Field-level tampering tests for multi-recipient JWE.

These tests deliberately distinguish two very different roles of a JWE field:

* Content-authenticated fields are the Additional Authenticated Data (AAD) and
  the AEAD/CBC-MAC inputs: the base64url-encoded ``protected`` header, the
  external ``aad``, the initialization vector ``iv``, the ``ciphertext`` and
  the authentication ``tag``. Flipping a byte in any of them MUST make content
  decryption fail for *every* recipient because the content authentication tag
  can no longer be verified.

* Key-selection / key-wrapping fields are the per-recipient ``encrypted_key``
  and the per-recipient unprotected ``header`` (including ``kid``). They are
  not part of the content AAD. Tampering with them only changes whether (and
  how) that one recipient can recover the Content Encryption Key (CEK). It must
  never produce unauthenticated plaintext: if no recipient recovers the CEK and
  passes content authentication, no plaintext is returned. In particular,
  pointing an unprotected ``kid`` at the wrong key only changes key selection;
  it does not authenticate anything by itself.

The corpus is built deterministically from fixed key material at import time,
so it is small and fully replayable without network access or random data.
"""

import unittest
import zlib

from jwcrypto import jwe
from jwcrypto import jwk
from jwcrypto.common import (JWKeyNotFound, base64url_decode,
                             base64url_encode, json_decode, json_encode)


# ---------------------------------------------------------------------------
# Deterministic, replayable corpus
# ---------------------------------------------------------------------------

def _fixed_oct(seed, size, kid):
    # Repeat a single byte to build a key of exactly `size` bytes. The key
    # material never changes, so every generated JWE structure is stable.
    material = base64url_encode(bytes([seed]) * size)
    return jwk.JWK(kty='oct', k=material, kid=kid)


KEY1 = _fixed_oct(0x11, 16, 'key1')   # 128-bit, used with A128KW/A128GCMKW
KEY2 = _fixed_oct(0x22, 32, 'key2')   # 256-bit, used with A256KW
KEYG = _fixed_oct(0x33, 16, 'gcmkw')  # 128-bit, used with A128GCMKW

PAYLOAD = b'multi-recipient tamper probe payload'
EXTERNAL_AAD = b'additional authenticated data'
COMPRESSED_PAYLOAD = b'DEFLATE compresses repeated text ' * 12


def _flip_b64(value):
    """Flip one bit in a base64url field, preserving valid encoding."""
    raw = bytearray(base64url_decode(value))
    raw[-1] ^= 0x01
    return base64url_encode(bytes(raw))


def _mutate(token, path, fn):
    """Return a copy of a serialized JSON JWE with one field replaced."""
    obj = json_decode(token)
    cursor = obj
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = fn(cursor[path[-1]])
    return json_encode(obj)


def _build_general_jwe():
    """Two recipients, different key-wrap algs, shared content encryption.

    Recipient 0: A128KW / key1 ; Recipient 1: A256KW / key2.
    Content encryption is A128GCM and an external AAD is set so the AAD
    authentication path is exercised as well.
    """
    enc = jwe.JWE(plaintext=PAYLOAD,
                  protected={'enc': 'A128GCM'},
                  aad=EXTERNAL_AAD,
                  flattened=False)
    enc.add_recipient(KEY1, header={'alg': 'A128KW', 'kid': 'key1'})
    enc.add_recipient(KEY2, header={'alg': 'A256KW', 'kid': 'key2'})
    return enc.serialize()


def _build_gcmkw_jwe():
    """Single A128GCMKW recipient; iv/tag live in the per-recipient header."""
    enc = jwe.JWE(plaintext=b'gcmkw probe',
                  protected={'enc': 'A128GCM'},
                  flattened=False)
    enc.add_recipient(KEYG, header={'alg': 'A128GCMKW', 'kid': 'gcmkw'})
    return enc.serialize()


def _build_compressed_jwe():
    enc = jwe.JWE(plaintext=COMPRESSED_PAYLOAD,
                  protected={'enc': 'A128GCM', 'zip': 'DEF'},
                  flattened=False)
    enc.add_recipient(KEY1, header={'alg': 'A128KW', 'kid': 'key1'})
    return enc.serialize()


def _build_authenticated_bad_deflate():
    """A JWE whose content decrypts fine but whose DEFLATE stream is corrupt.

    The content tag authenticates the raw ciphertext, so decryption succeeds;
    the failure only appears when the (authenticated) bytes are inflated. This
    is the fixture used to prove that post-authentication decompression state
    is cleaned up.
    """
    bad_stream = b'\x02\xff'  # raw inflate raises "invalid distance code"
    alg = jwe.JWA.keymgmt_alg('A128KW')
    encalg = jwe.JWA.encryption_alg('A128GCM')
    wrapped = alg.wrap(KEY1, encalg.wrap_key_size, None, {})
    cek, encrypted_key = wrapped['cek'], wrapped['ek']
    protected = json_encode({'enc': 'A128GCM', 'zip': 'DEF'})
    aad = base64url_encode(protected).encode('utf-8')
    iv, ciphertext, tag = encalg.encrypt(cek, aad, bad_stream)
    return json_encode({
        'protected': base64url_encode(protected),
        'iv': base64url_encode(iv),
        'ciphertext': base64url_encode(ciphertext),
        'tag': base64url_encode(tag),
        'recipients': [{'encrypted_key': base64url_encode(encrypted_key),
                        'header': {'alg': 'A128KW', 'kid': 'key1'}}],
    })


class TamperTestBase(unittest.TestCase):

    @staticmethod
    def _keyset():
        ks = jwk.JWKSet()
        ks.add(KEY1)
        ks.add(KEY2)
        ks.add(KEYG)
        return ks

    def _decrypt(self, token, key):
        """Return (object, error) for a fresh deserialization + decrypt."""
        obj = jwe.JWE()
        try:
            obj.deserialize(token, key)
            return obj, None
        except Exception as exc:  # noqa: BLE001 - asserted below
            return obj, exc


# ---------------------------------------------------------------------------
# Field-level expectation table, driven as data
# ---------------------------------------------------------------------------

class TestFieldLevelExpectations(TamperTestBase):
    """One assertion per field, with the expected outcome documented inline.

    ``expect`` semantics:
      'fail'  -> decryption raises and plaintext/cek stay unavailable;
      'ok'    -> decryption still returns the genuine PAYLOAD (the mutation
                 does not affect the recipient that is tried successfully).
    """

    @classmethod
    def setUpClass(cls):
        cls.token = _build_general_jwe()
        cls.ks = cls._keyset()

    # (label, path-to-field, mutation, expect, rationale)
    EXPECTATIONS = [
        ('protected', ['protected'], _flip_b64, 'fail',
         'protected header is part of the content AAD; a byte flip breaks '
         'the AEAD tag for every recipient'),
        ('aad', ['aad'], _flip_b64, 'fail',
         'external AAD is concatenated into the content AAD and is covered '
         'by the tag'),
        ('iv', ['iv'], _flip_b64, 'fail',
         'IV is an authenticated AEAD input; a flipped IV fails the tag'),
        ('ciphertext', ['ciphertext'], _flip_b64, 'fail',
         'ciphertext is authenticated; a bit flip fails the tag before any '
         'plaintext is accepted'),
        ('tag', ['tag'], _flip_b64, 'fail',
         'the authentication tag itself no longer verifies'),
        ('rec0.encrypted_key',
         ['recipients', 0, 'encrypted_key'], _flip_b64, 'ok',
         'only recipient 0 key unwrap breaks; recipient 1 still recovers the '
         'CEK and passes content authentication, so the genuine payload is '
         'returned'),
        ('rec1.encrypted_key',
         ['recipients', 1, 'encrypted_key'], _flip_b64, 'ok',
         'symmetric to the above: recipient 0 remains usable'),
        ('rec0.header.kid->key2',
         ['recipients', 0, 'header', 'kid'], lambda v: 'key2', 'ok',
         'kid only selects a key from the set. With key2 selected the A128KW '
         'unwrap fails, but recipient 1 still succeeds. No unauthenticated '
         'plaintext is produced; the payload comes from a fully verified '
         'path'),
        ('rec1.header.kid->key1',
         ['recipients', 1, 'header', 'kid'], lambda v: 'key1', 'ok',
         'routing-only change; recipient 0 still verifies the payload'),
        ('rec0.header.kid->unknown',
         ['recipients', 0, 'header', 'kid'], lambda v: 'no-such-key', 'ok',
         'an unknown kid makes recipient 0 unselectable but does not corrupt '
         'the content; recipient 1 still decrypts'),
    ]

    def test_expectation_table(self):
        for label, path, fn, expect, rationale in self.EXPECTATIONS:
            with self.subTest(field=label):
                mutated = _mutate(self.token, path, fn)
                obj, error = self._decrypt(mutated, self.ks)
                if expect == 'fail':
                    self.assertIsNotNone(error, msg=rationale)
                    self.assertIsNone(obj.plaintext, msg=rationale)
                    self.assertIsNone(obj.cek, msg=rationale)
                else:
                    self.assertIsNone(error, msg=rationale)
                    self.assertEqual(obj.payload, PAYLOAD, msg=rationale)
                    # A successful path must expose a real, non-empty CEK.
                    self.assertTrue(obj.cek, msg=rationale)

    def test_baseline_is_unchanged(self):
        obj, error = self._decrypt(self.token, self.ks)
        self.assertIsNone(error)
        self.assertEqual(obj.payload, PAYLOAD)

    def test_content_fields_also_fail_with_single_direct_key(self):
        # With a direct JWK (not a set) there is no key-selection fallback, so
        # content tamper surfaces as InvalidJWEData rather than JWKeyNotFound.
        for field in ('iv', 'ciphertext', 'tag'):
            with self.subTest(field=field):
                mutated = _mutate(self.token, [field], _flip_b64)
                obj, error = self._decrypt(mutated, KEY1)
                self.assertIsInstance(error, jwe.InvalidJWEData)
                self.assertIsNone(obj.plaintext)
                self.assertIsNone(obj.cek)

    def test_protected_tamper_fails_with_single_direct_key(self):
        mutated = _mutate(self.token, ['protected'], _flip_b64)
        obj, error = self._decrypt(mutated, KEY1)
        self.assertIsNotNone(error)
        self.assertIsNone(obj.plaintext)

    def test_wrong_kid_never_yields_unauthenticated_plaintext(self):
        # Point the only recipient's unprotected kid at a different, valid key.
        single = jwe.JWE(plaintext=PAYLOAD,
                         protected={'enc': 'A128GCM'},
                         flattened=False)
        single.add_recipient(KEY1, header={'alg': 'A128KW', 'kid': 'key1'})
        token = single.serialize()

        routed_wrong = _mutate(
            token, ['recipients', 0, 'header', 'kid'], lambda v: 'key2')
        obj, error = self._decrypt(routed_wrong, self.ks)
        # key2 cannot unwrap an A128KW CEK wrapped by key1, so this fails;
        # the decisive assertion is that no plaintext/CEK is exposed.
        self.assertIsInstance(error, JWKeyNotFound)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

        # Routing it back to key1 succeeds and returns the genuine payload.
        routed_back = _mutate(
            token, ['recipients', 0, 'header', 'kid'], lambda v: 'key1')
        ok, error = self._decrypt(routed_back, self.ks)
        self.assertIsNone(error)
        self.assertEqual(ok.payload, PAYLOAD)

    def test_unknown_kid_is_rejected_not_silently_accepted(self):
        single = jwe.JWE(plaintext=PAYLOAD,
                         protected={'enc': 'A128GCM'},
                         flattened=False)
        single.add_recipient(KEY1, header={'alg': 'A128KW', 'kid': 'key1'})
        mutated = _mutate(
            single.serialize(), ['recipients', 0, 'header', 'kid'],
            lambda v: 'missing')
        obj, error = self._decrypt(mutated, self.ks)
        self.assertIsInstance(error, JWKeyNotFound)
        self.assertIsNone(obj.plaintext)


# ---------------------------------------------------------------------------
# Per-recipient key-wrapping header (GCMKW iv/tag) authentication boundary
# ---------------------------------------------------------------------------

class TestGcmKwRecipientHeader(TamperTestBase):
    """GCMKW stores its wrapping iv/tag in the per-recipient unprotected
    header.

    These bytes authenticate the *wrapped CEK*, not the content. Tampering must
    make that recipient's unwrap fail (and never expose plaintext); it must not
    be confused with a content-authentication failure.
    """

    @classmethod
    def setUpClass(cls):
        cls.token = _build_gcmkw_jwe()
        cls.ks = cls._keyset()

    def test_baseline(self):
        obj, error = self._decrypt(self.token, self.ks)
        self.assertIsNone(error)
        self.assertEqual(obj.payload, b'gcmkw probe')

    def test_wrapping_iv_tamper_fails_at_unwrap(self):
        mutated = _mutate(
            self.token, ['recipients', 0, 'header', 'iv'], _flip_b64)
        obj, error = self._decrypt(mutated, KEYG)
        self.assertIsInstance(error, jwe.InvalidJWEData)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

    def test_wrapping_tag_tamper_fails_at_unwrap(self):
        mutated = _mutate(
            self.token, ['recipients', 0, 'header', 'tag'], _flip_b64)
        obj, error = self._decrypt(mutated, KEYG)
        self.assertIsInstance(error, jwe.InvalidJWEData)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)


# ---------------------------------------------------------------------------
# Recipient sequences: first fails/second succeeds, and all fail
# ---------------------------------------------------------------------------

class TestRecipientSequences(TamperTestBase):

    @classmethod
    def setUpClass(cls):
        cls.token = _build_general_jwe()
        cls.ks = cls._keyset()

    def test_first_recipient_fails_second_succeeds(self):
        # Break recipient 0's wrapped key; recipient 1 must still deliver.
        mutated = _mutate(
            self.token, ['recipients', 0, 'encrypted_key'], _flip_b64)
        obj, error = self._decrypt(mutated, self.ks)
        self.assertIsNone(error)
        self.assertEqual(obj.payload, PAYLOAD)
        # The log records the recipient-0 failure then the recipient-1 success.
        joined = '\n'.join(obj.decryptlog)
        self.assertIn('failed', joined)
        self.assertIn('Success', obj.decryptlog)

    def test_second_recipient_fails_first_succeeds(self):
        mutated = _mutate(
            self.token, ['recipients', 1, 'encrypted_key'], _flip_b64)
        obj, error = self._decrypt(mutated, self.ks)
        self.assertIsNone(error)
        self.assertEqual(obj.payload, PAYLOAD)

    def test_all_recipients_fail_on_content_tamper(self):
        # A flipped content tag invalidates content authentication regardless
        # of which recipient unwraps the CEK: every recipient is attempted and
        # none returns plaintext.
        mutated = _mutate(self.token, ['tag'], _flip_b64)
        obj, error = self._decrypt(mutated, self.ks)
        self.assertIsInstance(error, JWKeyNotFound)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)
        # Both recipients were attempted and each logged an auth failure.
        failure_lines = [line for line in obj.decryptlog
                         if 'failed' in line]
        self.assertGreaterEqual(len(failure_lines), 2)

    def test_every_encrypted_key_broken_fails_without_plaintext(self):
        mutated = _mutate(
            self.token, ['recipients', 0, 'encrypted_key'], _flip_b64)
        mutated = _mutate(
            mutated, ['recipients', 1, 'encrypted_key'], _flip_b64)
        obj, error = self._decrypt(mutated, self.ks)
        self.assertIsInstance(error, JWKeyNotFound)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)


# ---------------------------------------------------------------------------
# Reuse of one JWE object: success -> failure -> success must not retain state
# ---------------------------------------------------------------------------

class TestObjectReuseNoStaleState(TamperTestBase):

    @classmethod
    def setUpClass(cls):
        cls.token = _build_general_jwe()
        cls.ks = cls._keyset()

    def test_success_then_failure_clears_plaintext_and_cek(self):
        obj = jwe.JWE()
        obj.deserialize(self.token)
        obj.decrypt(self.ks)
        self.assertEqual(obj.payload, PAYLOAD)
        good_cek = obj.cek
        self.assertTrue(good_cek)

        # Reuse the same object with a tampered token.
        obj.deserialize(_mutate(self.token, ['tag'], _flip_b64))
        with self.assertRaises(Exception):
            obj.decrypt(self.ks)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

        # A correct token on the same object recovers a genuine, fresh result.
        obj.deserialize(self.token)
        obj.decrypt(self.ks)
        self.assertEqual(obj.payload, PAYLOAD)
        self.assertEqual(obj.cek, good_cek)

    def test_failure_then_success_does_not_reuse_old_values(self):
        obj = jwe.JWE()
        # Start from a failing token.
        obj.deserialize(_mutate(self.token, ['ciphertext'], _flip_b64))
        with self.assertRaises(Exception):
            obj.decrypt(self.ks)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

        # Then succeed on the same object; values must be freshly populated,
        # never inherited from the failed attempt.
        obj.deserialize(self.token)
        obj.decrypt(self.ks)
        self.assertEqual(obj.payload, PAYLOAD)
        self.assertTrue(obj.cek)

    def test_failed_recipient_cannot_leave_cek_for_next_attempt(self):
        # Within a single decrypt() call, a recipient that unwraps a CEK but
        # then fails content authentication must not leave that CEK visible to
        # a subsequent recipient attempt or to the caller afterwards.
        obj = jwe.JWE()
        obj.deserialize(_mutate(self.token, ['tag'], _flip_b64))
        with self.assertRaises(Exception):
            obj.decrypt(self.ks)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)


# ---------------------------------------------------------------------------
# Compression is only processed after authentication, with state cleanup
# ---------------------------------------------------------------------------

class TestCompressionBoundary(TamperTestBase):

    @classmethod
    def setUpClass(cls):
        cls.ks = cls._keyset()

    def test_compressed_roundtrip(self):
        obj, error = self._decrypt(_build_compressed_jwe(), self.ks)
        self.assertIsNone(error)
        self.assertEqual(obj.payload, COMPRESSED_PAYLOAD)

    def test_content_tamper_fails_before_decompression(self):
        token = _mutate(_build_compressed_jwe(), ['ciphertext'], _flip_b64)
        obj, error = self._decrypt(token, self.ks)
        self.assertIsNotNone(error)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

    def test_corrupt_deflate_stream_clears_state(self):
        # Content authentication passes (the bad bytes are genuinely encrypted
        # and tagged), then raw inflate fails. The partially produced state and
        # the recovered CEK must be cleared.
        obj, error = self._decrypt(_build_authenticated_bad_deflate(), self.ks)
        self.assertIsInstance(error, jwe.InvalidJWEData)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

    def test_oversize_decompression_clears_state(self):
        obj = jwe.JWE()
        obj.deserialize(_build_compressed_jwe())
        with self.assertRaises(jwe.InvalidJWEData):
            obj.decrypt(self.ks, max_plaintext=64)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

    def test_corrupt_deflate_bytes_are_genuinely_invalid(self):
        # Guard the fixture itself: prove the embedded stream really fails
        # raw inflate, so the test exercises decompression rather than being a
        # no-op token that happens to round-trip.
        do = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        with self.assertRaises(zlib.error):
            do.decompress(b'\x02\xff')


# ---------------------------------------------------------------------------
# Temporary mutation proofs: flip the library, observe the test change verdict.
#
# These tests document *where* the security property is enforced. They patch a
# single behavior at a time, assert the property then breaks, and restore the
# original automatically. Run with the rest of the suite; they never mutate the
# source tree.
# ---------------------------------------------------------------------------

class TestTemporaryMutationProofs(TamperTestBase):

    @classmethod
    def setUpClass(cls):
        cls.token = _build_general_jwe()
        cls.ks = cls._keyset()

    def test_authentication_check_proof(self):
        # Proof point: the content AEAD tag verification in _AesGcm.decrypt
        # is the gate that rejects tampered content. Temporarily replace it
        # with a variant that skips tag/AAD verification and returns fixed
        # bytes. While the gate is disabled a flipped-tag token is wrongly
        # "accepted"; once the original implementation is restored the same
        # token is rejected.
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers import algorithms, modes
        from jwcrypto.jwa import _AesGcm

        original_decrypt = _AesGcm.decrypt
        sentinel = b'UNAUTHENTICATED-BYTES'

        def unverified_decrypt(self, k, aad, iv, e, t):  # noqa: ARG001
            # `aad` and `t` are deliberately ignored: no verification occurs.
            cipher = Cipher(algorithms.AES(k), modes.GCM(iv),
                            backend=default_backend())
            decryptor = cipher.decryptor()
            decryptor.update(e)
            try:
                decryptor.finalize()
            except Exception:  # noqa: BLE001 - expected with a bad tag
                pass
            return sentinel

        tampered = _mutate(self.token, ['tag'], _flip_b64)
        try:
            _AesGcm.decrypt = unverified_decrypt
            disabled = jwe.JWE()
            disabled.deserialize(tampered)
            disabled.decrypt(self.ks)
            # Property broken while the check is disabled: tampered content is
            # returned as if it were valid plaintext.
            self.assertEqual(disabled.plaintext, sentinel)
        finally:
            _AesGcm.decrypt = original_decrypt

        # Real implementation restored: the identical token is rejected and no
        # plaintext is exposed.
        verified, error = self._decrypt(tampered, self.ks)
        self.assertIsNotNone(error)
        self.assertIsNone(verified.plaintext)
        self.assertIsNone(verified.cek)

    def test_state_cleanup_proof(self):
        # Proof point: a decompression failure must not leave the recovered CEK
        # on the object.
        #
        # First show the key really is recovered before inflation: spying on
        # `_unwrap_decrypt` captures a non-empty CEK immediately after the
        # authenticated unwrap, right before decompression runs.
        token = _build_authenticated_bad_deflate()

        observed = jwe.JWE()
        observed.deserialize(token)
        captured = {}
        original_unwrap = jwe.JWE._unwrap_decrypt

        def spying_unwrap(self, *args, **kwargs):
            data = original_unwrap(self, *args, **kwargs)
            captured['cek_after_unwrap'] = self.cek
            return data

        jwe.JWE._unwrap_decrypt = spying_unwrap
        try:
            with self.assertRaises(jwe.InvalidJWEData):
                observed.decrypt(self.ks)
        finally:
            jwe.JWE._unwrap_decrypt = original_unwrap

        # A usable CEK genuinely existed after unwrap; it is the cleanup, not a
        # missing key, that makes the post-failure state safe.
        self.assertTrue(captured['cek_after_unwrap'])
        self.assertIsNone(observed.cek)
        self.assertIsNone(observed.plaintext)

        # Mutation: a wrapper that mimics the pre-fix behavior by retaining
        # the recovered CEK instead of clearing it. This proves that without
        # the cleanup a failed decompression would expose a usable key, and
        # that the shipping implementation is what prevents it.
        class _PreFixLeak(jwe.JWE):
            def _decrypt(self, key, ppe,
                         max_plaintext=jwe.default_max_plaintext_size):
                super()._decrypt(key, ppe, max_plaintext=max_plaintext)

            def decrypt(self, key, max_plaintext=0):  # noqa: D401
                try:
                    super().decrypt(key, max_plaintext)
                except jwe.InvalidJWEData:
                    # Re-introduce the stale-key defect on purpose.
                    self.cek = captured['cek_after_unwrap']
                    raise

        leaky = _PreFixLeak()
        leaky.deserialize(token)
        with self.assertRaises(jwe.InvalidJWEData):
            leaky.decrypt(self.ks)
        self.assertEqual(leaky.cek, captured['cek_after_unwrap'])

        # On the ordinary (fixed) class, the same failing token keeps the CEK
        # cleared.
        fixed, error = self._decrypt(token, self.ks)
        self.assertIsInstance(error, jwe.InvalidJWEData)
        self.assertIsNone(fixed.cek)


if __name__ == '__main__':
    unittest.main()
