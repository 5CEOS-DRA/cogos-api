#!/usr/bin/env python3
# COGOS pinned-script process · int-factor · v1
# Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §8.
#
# Input  (stdin, JSON):  { "n": <positive int>, "now": <ISO-8601 string> }
# Output (stdout, JSON): { "n", "factors", "is_prime", "now" }
#
# Hard rules:
#   - 2 <= n <= 10**12 (enforced both client-side in JS wrapper and here)
#   - factors[] ascending (deterministic; trial-division emits in order)
#   - is_prime iff len(factors) == 1 (single prime factor of itself)
#   - now is echoed verbatim · operator-supplied determinism anchor
#
# This script is byte-pinned · its sha256 is part of every output_hash.
# Edits to this file mutate the entire downstream chain. That is by
# design (§8.5). Do not modify without a doctrine-event commit.

import json
import sys

MAX_N = 10 ** 12


def factor(n):
    out = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            out.append(d)
            n //= d
        d += 1
    if n > 1:
        out.append(n)
    return out


def fail(msg, code=3):
    sys.stderr.write(msg)
    sys.exit(code)


def main():
    raw = sys.stdin.read()
    if not raw:
        fail("EMPTY_STDIN")
    try:
        body = json.loads(raw)
    except Exception as e:
        fail("BAD_JSON: " + str(e), code=2)
    if not isinstance(body, dict):
        fail("BAD_INPUT: body must be a JSON object")
    n = body.get("n")
    now = body.get("now")
    if not isinstance(n, int) or isinstance(n, bool) or n < 2 or n > MAX_N:
        fail("BAD_INPUT: n must be int in [2, 10**12]")
    if not isinstance(now, str) or not now:
        fail("BAD_INPUT: now must be a non-empty ISO-8601 string")
    factors = factor(n)
    is_prime = len(factors) == 1
    out = {
        "n": n,
        "factors": factors,
        "is_prime": is_prime,
        "now": now,
    }
    # sort_keys+separators · stable canonical bytes from Python's side too.
    sys.stdout.write(json.dumps(out, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
