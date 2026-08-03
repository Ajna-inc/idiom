#!/usr/bin/env python3
"""
ACA-Py OID4VCI issuance throughput benchmark (SD-JWT VC).

A standalone vanilla ACA-Py container (oid4vc + sd_jwt_vc plugins, no ledger, no
external auth server) is the issuer. A minimal Python holder drives the real
OID4VCI exchange over ACA-Py's public endpoints (token -> nonce -> credential
with an Ed25519 key-possession proof). Reported as creds/s — the counterpart of
idiom's oid4vci-issuance-bench.sh and credo-oid4vci-bench.ts.

Prereq: the `oid4vc-bench` container is running (see acapy-oid4vci-bench.sh).

  N=200 python3 acapy-oid4vci-bench.py
"""
import base64, json, os, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ADMIN = os.environ.get("ACAPY_ADMIN", "http://localhost:3001")
N = int(os.environ.get("N", "200"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "1"))
CONFIG_ID = os.environ.get("CONFIG_ID", f"UDbench{int(time.time())}")

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jreq(url, data=None, headers=None, form=False, method=None):
    h = {"content-type": "application/x-www-form-urlencoded" if form else "application/json"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=h, method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or "{}")


# ---- issuer setup (admin API), once ----
did = jreq(f"{ADMIN}/did/jwk/create", {"key_type": "ed25519"})["did"]
sup = jreq(
    f"{ADMIN}/oid4vci/credential-supported/create/sd-jwt",
    {
        "format": "vc+sd-jwt", "id": CONFIG_ID, "vct": "UniversityDegree",
        "cryptographic_binding_methods_supported": ["jwk"],
        "credential_signing_alg_values_supported": ["EdDSA"],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}},
        "sd_list": ["/given_name", "/family_name", "/degree"],
        "credential_metadata": {"claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["degree"]}]},
    },
)
supid = sup.get("supported_cred_id") or sup.get("id")


def make_offer():
    ex = jreq(
        f"{ADMIN}/oid4vci/exchange/create",
        {"supported_cred_id": supid, "did": did,
         "credential_subject": {"given_name": "Alice", "family_name": "Holder", "degree": "BSc"}},
    )
    exid = ex["exchange_id"]
    off = jreq(f"{ADMIN}/oid4vci/credential-offer?exchange_id={exid}&user_pin_required=false")
    return off["offer"]


# ---- one reused holder Ed25519 key ----
hk = Ed25519PrivateKey.generate()
hpub = hk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
holder_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(hpub)}


def sign_proof(aud, nonce):
    header = {"typ": "openid4vci-proof+jwt", "alg": "EdDSA", "jwk": holder_jwk}
    payload = {"aud": aud, "iat": int(time.time()), "nonce": nonce}
    si = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}".encode()
    sig = hk.sign(si)
    return f"{si.decode()}.{b64u(sig)}"


def redeem(offer):
    """Full holder flow against ACA-Py's public OID4VCI endpoints."""
    issuer = offer["credential_issuer"]
    meta = jreq(f"{issuer}/.well-known/openid-credential-issuer")
    code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
    tok = jreq(meta.get("token_endpoint", f"{issuer}/token"),
               {"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": code},
               form=True)
    access = tok["access_token"]
    nonce = tok.get("c_nonce")
    if not nonce:
        nonce = jreq(meta.get("nonce_endpoint", f"{issuer}/nonce"), {}, headers={"authorization": f"Bearer {access}"})["c_nonce"]
    cfg_id = offer["credential_configuration_ids"][0]
    proof = sign_proof(issuer, nonce)
    resp = jreq(meta["credential_endpoint"],
                {"credential_identifier": cfg_id, "proof": {"proof_type": "jwt", "jwt": proof}},
                headers={"authorization": f"Bearer {access}"})
    cred = resp.get("credential") or (resp.get("credentials") or [{}])[0].get("credential", "")
    if isinstance(cred, dict):
        cred = cred.get("credential", "")
    return 1 if isinstance(cred, str) and len(cred) > 40 else 0


# ---- warm up + validate one, then mint N offers (untimed) ----
redeem(make_offer())
offers = [make_offer() for _ in range(N)]

# ---- timed batch: holder flow (token -> nonce -> credential) ----
t0 = time.time()
if CONCURRENCY <= 1:
    ok = sum(redeem(o) for o in offers)
else:
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        ok = sum(ex.map(lambda o: redeem(o), offers))
d = time.time() - t0
print(f"  issued {ok}/{N} SD-JWT credentials in {d:.2f}s = {ok/d:.1f} creds/s (full OID4VCI HTTP path, ACA-Py oid4vc plugin)")
