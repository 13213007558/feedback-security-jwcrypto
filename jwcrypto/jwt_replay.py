#!/usr/bin/env python
"""Offline, deterministic replay of a JWT acceptance decision.

Given a serialized token, a key and the exact verification time recorded
in a log, this tool reproduces the same claims-validation verdict the
library would have produced at that moment, without consulting the
system clock and therefore without any dependence on when the replay is
run.

Example:
    python -m jwcrypto.jwt_replay \\
        --token "$JWT" --key key.json --now 1700000000 \\
        --max-token-age 3600

Exit code is 0 when the token is accepted and 1 when it is rejected; the
machine-readable detail is printed to stdout in both cases.
"""

import argparse
import json
import sys

from jwcrypto import jwk, jwt


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Replay a JWT validation decision at a fixed time")
    parser.add_argument('--token', required=True,
                        help='the compact serialized JWT token')
    parser.add_argument('--key', required=True,
                        help='path to a JWK/JWKSet JSON file, or the '
                             'JSON content itself')
    parser.add_argument('--now', required=True, type=float,
                        help='verification time as a NumericDate '
                             '(seconds since the epoch, fractional '
                             'values allowed)')
    parser.add_argument('--leeway', type=int, default=None,
                        help='clock-skew leeway in seconds (defaults to '
                             'the library value, 60)')
    parser.add_argument('--max-token-age', dest='max_token_age',
                        type=float, default=None,
                        help='hard cap on token lifetime (exp - iat), '
                             'in seconds')
    parser.add_argument('--check-claims', dest='check_claims',
                        default=None,
                        help='optional JSON object of required claims')
    parser.add_argument('--algs', default=None,
                        help='optional comma separated allow list of '
                             'algorithms')
    parser.add_argument('--expected-type', choices=['JWS', 'JWE'],
                        default=None)
    return parser


def _load_key(spec):
    try:
        with open(spec, 'r', encoding='utf-8') as handle:
            data = handle.read()
    except (OSError, IOError):
        data = spec
    parsed = json.loads(data)
    if isinstance(parsed, dict) and 'keys' in parsed:
        return jwk.JWKSet.from_json(data)
    return jwk.JWK(**parsed)


def replay(token, key, now, leeway=None, max_token_age=None,
           check_claims=None, algs=None, expected_type=None):
    """Validate ``token`` at the fixed time ``now``.

    Returns a tuple ``(accepted, detail)`` where ``detail`` is a dict
    suitable for JSON serialization. The same arguments always produce
    the same result because the system clock is never read.
    """
    kwargs = {}
    if check_claims is not None:
        kwargs['check_claims'] = check_claims
    if algs is not None:
        kwargs['algs'] = algs
    if expected_type is not None:
        kwargs['expected_type'] = expected_type

    obj = jwt.JWT(**kwargs)
    if leeway is not None:
        obj.leeway = leeway

    detail = {'now': now, 'leeway': obj.leeway,
              'max_token_age': max_token_age}
    validate_kwargs = {'now': now}
    if max_token_age is not None:
        validate_kwargs['max_token_age'] = max_token_age
    try:
        obj.deserialize(token, key, **validate_kwargs)
    except Exception as exc:  # pylint: disable=broad-except
        detail['verdict'] = 'REJECTED'
        detail['error_type'] = type(exc).__name__
        detail['error'] = str(exc)
        return False, detail

    detail['verdict'] = 'ACCEPTED'
    detail['claims'] = json.loads(obj.claims)
    return True, detail


def main(argv=None):
    args = _build_parser().parse_args(argv)
    key = _load_key(args.key)
    check_claims = (json.loads(args.check_claims)
                    if args.check_claims is not None else None)
    algs = args.algs.split(',') if args.algs is not None else None

    accepted, detail = replay(
        args.token, key, args.now, leeway=args.leeway,
        max_token_age=args.max_token_age, check_claims=check_claims,
        algs=algs, expected_type=args.expected_type)

    print(json.dumps(detail, sort_keys=True, indent=2))
    return 0 if accepted else 1


if __name__ == '__main__':
    sys.exit(main())
