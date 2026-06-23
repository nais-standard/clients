"""
nais_sdk — Python SDK for the Network Agent Identity Standard.

Resolution is fully decentralized: the SDK reads the agent's ``_agent`` DNS TXT
record itself, fetches the signed card over HTTPS, and verifies the signature
against the DNS-published key. There is no central resolver in the trust or
availability path — trust travels with the signed card.

Requires Python 3.8+. DNS lookups use ``dnspython``; signature verification uses
``cryptography`` (preferred) or ``PyNaCl``.
"""

import base64
import hashlib
import json
import urllib.request
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

__version__ = "1.0.1"
__all__ = [
    "resolve",
    "validate",
    "verify_card",
    "canonicalize",
    "normalize_domain",
    "parse_nais_txt",
    "NAISError",
    "ResolutionError",
]

MAX_CARD_BYTES = 1024 * 1024  # 1 MiB


class NAISError(Exception):
    """Base exception for all NAIS SDK errors."""


class ResolutionError(NAISError):
    """Raised when a domain cannot be resolved.

    Attributes:
        domain (str): The domain that failed to resolve.
    """

    def __init__(self, message: str, domain: str) -> None:
        super().__init__(message)
        self.domain: str = domain

    def __repr__(self) -> str:
        return f"ResolutionError(domain={self.domain!r}, message={str(self)!r})"


# ─────────────────────────────────────────────────────────────────────────────
# Signature verification — detached EdDSA JWS over the canonical card
# ─────────────────────────────────────────────────────────────────────────────

def canonicalize(value: Any) -> str:
    """Return the NAIS canonical JSON byte string (a subset of RFC 8785 / JCS).

    Object keys sorted ascending by code point, no whitespace, "/" and non-ASCII
    left unescaped, integers emitted as integers. Cards MUST NOT contain floats.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(value[k])
            for k in sorted(value.keys())
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("NAIS cards must not contain floating-point numbers")
    if value is None:
        return "null"
    return json.dumps(value, ensure_ascii=False)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature using cryptography or PyNaCl, whichever exists."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False
    except ImportError:
        pass

    try:
        import nacl.signing
        import nacl.exceptions

        try:
            nacl.signing.VerifyKey(public_key).verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
    except ImportError:
        raise NAISError(
            "Signature verification requires the 'cryptography' or 'PyNaCl' package"
        )


def verify_card(card: Dict[str, Any], dns_key: Optional[str]) -> Dict[str, Any]:
    """Verify a NAIS card's detached EdDSA JWS against the DNS-published key.

    The card is authentic only when it carries a valid Ed25519 signature over its
    own canonical body AND ``signature.kid`` equals the ``k=`` fingerprint from
    the ``_agent`` DNS record. Forging it needs both DNS control and the key.

    Returns a dict: ``present``, ``verified``, ``kid``, ``alg``, ``reason``.
    """
    out: Dict[str, Any] = {"present": False, "verified": False, "kid": None, "alg": None, "reason": None}
    sig = card.get("signature") if isinstance(card, dict) else None
    if not isinstance(sig, dict):
        out["reason"] = "no signature object"
        return out

    out["present"] = True
    out["kid"] = sig.get("kid")
    out["alg"] = sig.get("alg")

    if sig.get("alg") != "EdDSA":
        out["reason"] = "unsupported alg (expected EdDSA)"
        return out
    if not sig.get("kid") or not sig.get("jws"):
        out["reason"] = "signature missing kid or jws"
        return out
    if not str(sig["kid"]).startswith("ed25519:"):
        out["reason"] = "kid is not an ed25519 key"
        return out
    if not dns_key:
        out["reason"] = "no k= key published in the _agent DNS record to anchor trust"
        return out
    if dns_key != sig["kid"]:
        out["reason"] = "signature.kid does not match the DNS k= key"
        return out

    parts = str(sig["jws"]).split(".")
    if len(parts) != 3 or parts[1] != "":
        out["reason"] = "jws is not a detached compact JWS"
        return out
    protected_b64, _, sig_b64 = parts

    body = {k: v for k, v in card.items() if k != "signature"}
    try:
        payload = canonicalize(body).encode("utf-8")
    except ValueError as exc:
        out["reason"] = "canonicalization failed: " + str(exc)
        return out
    signing_input = (protected_b64 + "." + _b64url_encode(payload)).encode("ascii")

    public_key = _b64url_decode(str(sig["kid"])[len("ed25519:"):])
    if len(public_key) != 32:
        out["reason"] = "malformed ed25519 public key in kid"
        return out

    out["verified"] = _ed25519_verify(public_key, _b64url_decode(sig_b64), signing_input)
    if not out["verified"]:
        out["reason"] = "Ed25519 signature does not match the canonical card body"
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Domain / DNS / card fetching
# ─────────────────────────────────────────────────────────────────────────────

def normalize_domain(value: str) -> Optional[str]:
    """Normalize input to a bare lowercase hostname, or None if invalid."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.lower().startswith("http://"):
        s = s[7:]
    elif s.lower().startswith("https://"):
        s = s[8:]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if ":" in s:
        s = s.rsplit(":", 1)[0]
    s = s.lower().rstrip(".")
    if not s or len(s) > 253:
        return None
    labels = s.split(".")
    if len(labels) < 2:
        return None
    import re
    for label in labels:
        if len(label) > 63 or not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
            return None
    return s


def parse_nais_txt(raw: str) -> Dict[str, str]:
    """Parse a NAIS TXT record into a key/value dict (semicolon-delimited)."""
    out: Dict[str, str] = {}
    for seg in str(raw).split(";"):
        seg = seg.strip()
        eq = seg.find("=")
        if eq <= 0:
            continue
        out[seg[:eq].strip().lower()] = seg[eq + 1:].strip()
    return out


def _default_lookup_txt(host: str) -> List[str]:
    """Default DNS TXT lookup at _agent.<domain> using dnspython."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        raise NAISError("DNS resolution requires the 'dnspython' package")

    try:
        answers = dns.resolver.resolve(host, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        raise NAISError(f"DNS lookup error: {exc}")

    records: List[str] = []
    for rdata in answers:
        chunks = getattr(rdata, "strings", None)
        if chunks is not None:
            records.append("".join(c.decode("utf-8", "replace") if isinstance(c, bytes) else c for c in chunks))
        else:
            records.append(str(rdata).strip('"'))
    return records


def _default_fetch_card(url: str, timeout: int) -> Dict[str, Any]:
    """Default card fetcher: HTTPS only, no cross-host redirect, size-capped."""
    if not url.lower().startswith("https://"):
        raise ValueError("card URL must use HTTPS")

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        final = resp.geturl()
        if urllib.parse.urlparse(final).netloc != urllib.parse.urlparse(url).netloc:
            raise ValueError("card URL redirected to a different host")
        raw = resp.read(MAX_CARD_BYTES + 1)
    if len(raw) > MAX_CARD_BYTES:
        raise ValueError("card exceeds 1 MiB")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"card is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise ValueError("card is not a JSON object")
    return data


def validate_card(card: Dict[str, Any], expected_domain: str, signature: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a decoded card against the NAIS 1.0 schema (structural + signature)."""
    errors: List[str] = []
    warnings: List[str] = []

    if card.get("nais") is None:
        errors.append('Missing required field: nais — expected "nais": "1.0"')
    elif not str(card["nais"]).startswith("1."):
        warnings.append(f'Unexpected nais version "{card["nais"]}" — this SDK implements 1.x')

    if "cardVersion" not in card:
        errors.append("Missing required field: cardVersion (integer)")
    elif not isinstance(card["cardVersion"], int) or isinstance(card["cardVersion"], bool):
        errors.append("Field cardVersion must be an integer")

    if not card.get("updated"):
        warnings.append("Missing recommended field: updated (ISO 8601 timestamp)")
    if not card.get("name"):
        errors.append("Missing required field: name")

    if not card.get("domain"):
        errors.append("Missing required field: domain")
    elif str(card["domain"]).lower().rstrip(".") != expected_domain:
        errors.append(f'Field domain "{card["domain"]}" does not match resolved domain "{expected_domain}"')

    if not signature.get("present"):
        errors.append("Missing required field: signature — every NAIS 1.0 card MUST carry a detached EdDSA JWS")
    elif not signature.get("verified"):
        errors.append("Signature verification failed: " + (signature.get("reason") or "unknown reason"))

    if not card.get("mcp"):
        warnings.append("No MCP endpoint declared (mcp)")
    if "capabilities" in card:
        warnings.append('Field capabilities is deprecated in NAIS 1.0 — use free-form "tags"')

    payment = card.get("payment")
    if isinstance(payment, dict):
        if not payment.get("payTo"):
            warnings.append("payment present but payment.payTo is empty")
        elif not signature.get("verified"):
            warnings.append("payment.payTo MUST NOT be used: the card signature is not verified")

    snap = card.get("mcpSnapshot")
    if isinstance(snap, dict) and isinstance(snap.get("tools"), list) and snap.get("toolsHash"):
        computed = "sha256:" + hashlib.sha256(canonicalize(snap["tools"]).encode("utf-8")).hexdigest()
        if computed != snap["toolsHash"]:
            warnings.append("mcpSnapshot.toolsHash does not match the snapshot tools — snapshot may be stale or altered")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


# ─────────────────────────────────────────────────────────────────────────────
# Resolution
# ─────────────────────────────────────────────────────────────────────────────

def resolve(
    domain: str,
    timeout: int = 8,
    lookup_txt: Optional[Callable[[str], List[str]]] = None,
    fetch_card: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Resolve a NAIS agent domain directly.

    Reads the ``_agent`` DNS TXT record, fetches the signed card, and verifies
    its signature against the DNS-published key.

    Args:
        domain: The agent domain, e.g. ``"weatheragent.nais.id"``.
        timeout: HTTP timeout in seconds for the card fetch.
        lookup_txt: Optional override for DNS lookup (testing).
        fetch_card: Optional override for card fetching (testing).

    Returns:
        ``{ ok, domain, agent_host, dns, manifest_url, card, signature, validation }``

    Raises:
        ResolutionError: If the domain is invalid, has no NAIS record, or the
            card cannot be fetched.
    """
    if not domain or not isinstance(domain, str) or not domain.strip():
        raise ResolutionError("domain must be a non-empty string", str(domain))

    normalized = normalize_domain(domain)
    if normalized is None:
        raise ResolutionError("Invalid domain — provide a bare hostname such as weatheragent.nais.id", domain)

    do_lookup = lookup_txt or _default_lookup_txt
    do_fetch = fetch_card or (lambda url: _default_fetch_card(url, timeout))
    agent_host = "_agent." + normalized

    try:
        records = list(do_lookup(agent_host))
    except NAISError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ResolutionError(f"DNS lookup failed for {agent_host}: {exc}", normalized)

    nais_records = [r for r in records if "v=" in r]
    if not nais_records:
        raise ResolutionError(f"No NAIS TXT record found at {agent_host}", normalized)

    parsed = parse_nais_txt(nais_records[0])
    manifest_url = parsed.get("manifest") or f"https://{normalized}/.well-known/agent.json"

    try:
        card = do_fetch(manifest_url)
    except Exception as exc:  # noqa: BLE001
        raise ResolutionError(f"Failed to fetch card from {manifest_url}: {exc}", normalized)
    if not isinstance(card, dict):
        raise ResolutionError(f"Card at {manifest_url} is not a JSON object", normalized)

    signature = verify_card(card, parsed.get("k"))
    validation = validate_card(card, normalized, signature)

    return {
        "ok": True,
        "domain": normalized,
        "agent_host": agent_host,
        "dns": {"records": records, "parsed": parsed},
        "manifest_url": manifest_url,
        "card": card,
        "signature": signature,
        "validation": validation,
    }


def validate(domain: str, timeout: int = 8, **kwargs: Any) -> Dict[str, Any]:
    """Resolve and return a flattened, verification-aware summary.

    Accepts the same ``lookup_txt`` / ``fetch_card`` overrides as :func:`resolve`.

    Returns a dict with: ``valid``, ``domain``, ``version``, ``manifest_url``,
    ``mcp_endpoint``, ``has_mcp``, ``has_card``, ``signature_verified``,
    ``signature_reason``, ``key``, ``kid``, ``auth``, ``payments``, ``pay_to``,
    ``tags``, ``linked_agents``, ``warnings``, ``errors``. ``pay_to`` is
    populated only when the signature verifies. ``linked_agents`` is advisory:
    each linked domain must be resolved and verified independently.
    """
    r = resolve(domain, timeout=timeout, **kwargs)
    card = r["card"]
    sig = r["signature"]
    v = r["validation"]
    signature_verified = bool(sig.get("verified"))

    auth: List[str] = []
    for entry in card.get("auth") or []:
        if isinstance(entry, dict) and entry.get("scheme"):
            auth.append(str(entry["scheme"]))
        elif isinstance(entry, str):
            auth.append(entry)

    payment = card.get("payment") or {}
    payments = [str(payment["type"])] if payment.get("type") else []
    tags = [str(t) for t in card.get("tags")] if isinstance(card.get("tags"), list) else []

    pay_to: List[str] = []
    if signature_verified and isinstance(payment.get("payTo"), list):
        pay_to = [str(a) for a in payment["payTo"]]

    # Advisory pointers to related agents. A link confers no trust — each domain
    # must be resolved and verified independently before it is relied upon.
    linked_agents: List[Dict[str, Any]] = []
    for entry in card.get("linkedAgents") or []:
        if isinstance(entry, dict) and entry.get("domain"):
            linked_agents.append({
                "domain": str(entry["domain"]),
                "relation": str(entry["relation"]) if entry.get("relation") is not None else None,
                "verified": entry.get("verified") is True,
                "name": str(entry["name"]) if entry.get("name") is not None else None,
            })

    return {
        "valid": bool(r["ok"] and v["valid"] and signature_verified),
        "domain": r["domain"],
        "version": r["dns"]["parsed"].get("v"),
        "manifest_url": r["manifest_url"],
        "mcp_endpoint": card.get("mcp"),
        "has_mcp": bool(card.get("mcp")),
        "has_card": bool(card),
        "signature_verified": signature_verified,
        "signature_reason": None if signature_verified else sig.get("reason"),
        "key": r["dns"]["parsed"].get("k"),
        "kid": sig.get("kid"),
        "auth": auth,
        "payments": payments,
        "pay_to": pay_to,
        "tags": tags,
        "linked_agents": linked_agents,
        "warnings": v["warnings"],
        "errors": v["errors"],
    }
