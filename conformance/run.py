#!/usr/bin/env python3
"""Cross-language conformance runner — Python.

Loads every vector in ./vectors and asserts the Python SDK's verify_card()
produces the expected verdict, plus that canonicalize() matches the recorded
canonical SHA-256. Exits non-zero on any mismatch.

    python conformance/run.py
"""
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
from nais_sdk import verify_card, canonicalize  # noqa: E402

vectors_dir = os.path.join(os.path.dirname(__file__), "vectors")
failures = 0
files = sorted(glob.glob(os.path.join(vectors_dir, "*.json")))

for f in files:
    vec = json.load(open(f))
    got = verify_card(vec["card"], vec["dnsKey"])

    ok_verified = got["verified"] == vec["expect"]["verified"]
    ok_present = got["present"] == vec["expect"]["present"]
    ok_canon = True

    if vec.get("canonicalSha256"):
        body = {k: v for k, v in vec["card"].items() if k != "signature"}
        sha = hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()
        ok_canon = sha == vec["canonicalSha256"]

    ok = ok_verified and ok_present and ok_canon
    if not ok:
        failures += 1
    extra = "" if ok else (
        f"  (verified={got['verified']}/{vec['expect']['verified']} "
        f"present={got['present']}/{vec['expect']['present']} canon={ok_canon} reason={got['reason']})"
    )
    print(f"{'PASS' if ok else 'FAIL'}  {vec['name']}{extra}")

print(f"\n[python] {len(files) - failures}/{len(files)} vectors passed")
sys.exit(1 if failures else 0)
