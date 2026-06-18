#!/usr/bin/env python3
"""Offline test of the Python SDK's direct-DNS resolve()/validate() pipeline.

DNS + card fetch are injected, so no network is touched. Exits non-zero on any
failed assertion.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
import nais_sdk  # noqa: E402

CARD_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "agent.json")
card = json.load(open(CARD_PATH))
kid = card["signature"]["kid"]
txt = f"v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k={kid}"
dns = lambda h: [txt]            # noqa: E731
fetch_ok = lambda u: card        # noqa: E731

# valid card → verified, valid, pay_to surfaced
r = nais_sdk.resolve("weatheragent.nais.id", lookup_txt=dns, fetch_card=fetch_ok)
assert r["signature"]["verified"] is True, "valid card should verify"
assert r["validation"]["valid"] is True, "valid card should validate"
s = nais_sdk.validate("weatheragent.nais.id", lookup_txt=dns, fetch_card=fetch_ok)
assert s["valid"] is True
assert s["mcp_endpoint"] == "https://weatheragent.nais.id/mcp"
assert s["pay_to"] == ["0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5"]

# tampered → not verified, pay_to withheld
tampered = copy.deepcopy(card)
tampered["payment"]["payTo"] = ["0xBAD"]
st = nais_sdk.validate("weatheragent.nais.id", lookup_txt=dns, fetch_card=lambda u: tampered)
assert st["signature_verified"] is False
assert st["valid"] is False
assert st["pay_to"] == []

# no record → raises
try:
    nais_sdk.resolve("weatheragent.nais.id", lookup_txt=lambda h: [], fetch_card=fetch_ok)
    raise AssertionError("expected ResolutionError for missing record")
except nais_sdk.ResolutionError:
    pass

# invalid domain → raises
try:
    nais_sdk.resolve("not a domain")
    raise AssertionError("expected ResolutionError for invalid domain")
except nais_sdk.ResolutionError:
    pass

print("[python] resolve/validate offline tests passed")
