#!/usr/bin/env python3
"""
CKYCRR 2.0 UAT tester -- Search API.

Wire format (reverse-engineered from the CERSAI Postman collection's captured requests):

    request body   {reId, requestId, timestamp, ckycInq:{ckycType, searchOption, encryptedData}}
    encryptedData  = JWS(RS256)  whose payload is  JWE(RSA-OAEP-256 + A256GCM, cty=text/plain)
                     i.e. ENCRYPT first (to CERSAI's public key), then SIGN (with our private key)
    transport      OAuth2 client_credentials bearer token + mutual TLS

Setup
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env && chmod 600 .env        # then fill in CLIENT_ID and CLIENT_SECRET

Configuration (.env next to this script; real environment variables take precedence)
    CLIENT_ID, CLIENT_SECRET   OAuth credentials issued by CERSAI. Read from .env, never from flags.
    RE_ID                      your reporting-entity code. Optional: falls back to the reId used in CERSAI's
                               sample collection and prints a note, so set it to your own.
    BASE_URL                   optional host override (default: the v2.1 testbed)

Certificates are found by filename anywhere under this folder (put them in certs/):
    mtls.crt, mtls.key                       your TLS client certificate and key
    encryption.key                           YOUR private key: signs requests, decrypts responses
                                             (assumption -- use --sign-key if CERSAI rejects the signature)
    testbed.enc.ckycregistry.co.in__.cer     CERSAI's encryption certificate: encrypts requests
    testbed.sign.ckycregistry.co.in__.cer    CERSAI's signing certificate: verifies responses
    secureapi.ckycregistry.co.in.cer         CERSAI's server chain (private root; trusted automatically)
  Only the TESTBED certificates are ever auto-selected. Production needs explicit flags.

Examples
    ./ckycrr_search_test.py selftest                                    offline, no credentials needed
    ./ckycrr_search_test.py token
    ./ckycrr_search_test.py search --option CKYC   --ckyc-no 12345678901234
    ./ckycrr_search_test.py search --option PAN    --pan ABCDE1234F
    ./ckycrr_search_test.py search --option MOBILE --mobile 9876543210
    ./ckycrr_search_test.py search --option CKYC   --ckyc-no 12345678901234 --dry-run
"""
import argparse
import base64
import getpass
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwcrypto import jwe, jwk, jws
    from jwcrypto.common import json_encode
except ImportError as exc:  # pragma: no cover
    sys.exit(f"Missing dependency ({exc.name}). Run:  pip install -r requirements.txt")

# Testbed host per API guide v2.1 section 3.1 (matches the CERSAI testbed certs in CKYCRR_Certificates/).
# The older Postman collection used https://secureapi-uat.ckycindia.dev:9443 -- pass --base-url to use it.
DEFAULT_BASE_URL = "https://testbed.secureapi.ckycregistry.co.in"
FALLBACK_RE_ID = "IN0145"  # reId used in CERSAI's Postman collection; set RE_ID in .env if yours differs

# Certificate files the script looks for under its own folder (testbed only -- prod is never auto-selected).
DISCOVER = {
    "mtls_cert": "mtls.crt",
    "mtls_key": "mtls.key",
    "enc_key": "encryption.key",
    "cersai_cert": "testbed.enc.ckycregistry.co.in__.cer",
    "cersai_sign_cert": "testbed.sign.ckycregistry.co.in__.cer",
}
TOKEN_PATH = "/api/ckyc/v1/generate-token"
SEARCH_PATH = "/api/ckyc/v1/search"

# Exactly the protected headers seen in CERSAI's captured requests.
JWE_PROTECTED = {"cty": "text/plain", "enc": "A256GCM", "alg": "RSA-OAEP-256"}
JWS_PROTECTED = {"alg": "RS256"}

TIMEOUT = (5, 30)  # connect, read


# --------------------------------------------------------------------------- helpers
def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fingerprint(secret: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(secret.encode())
    return digest.finalize().hex()[:8]


def summarize_html(text: str) -> str:
    import re
    m = re.search(r"<title>(.*?)</title>", text, re.S | re.I)
    return (m.group(1).strip() if m else text[:300]).replace("\n", " ")


def truncate(obj, limit=120):
    """Shorten long strings (photos, base64 blobs) so output stays readable."""
    if isinstance(obj, dict):
        return {k: truncate(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [truncate(v, limit) for v in obj]
    if isinstance(obj, str) and len(obj) > limit:
        return f"{obj[:limit]}...<{len(obj)} chars>"
    return obj


def pretty(obj, full=False) -> str:
    return json.dumps(obj if full else truncate(obj), indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- key loading
def load_public_jwk(path: str) -> jwk.JWK:
    """Public key from an X.509 certificate (PEM or DER) or a bare PEM public key."""
    data = Path(path).read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError:
            return jwk.JWK.from_pem(data)
    pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwk.JWK.from_pem(pem)


def load_private_jwk(path: str) -> jwk.JWK:
    return jwk.JWK.from_pem(Path(path).read_bytes())


# --------------------------------------------------------------------------- JOSE layer
def protect(plaintext: str, cersai_pub: jwk.JWK, sign_key: jwk.JWK) -> str:
    """plaintext JSON -> JWE (to CERSAI) -> JWS (signed by us) -> value of `encryptedData`."""
    enc = jwe.JWE(plaintext.encode("utf-8"), protected=json_encode(JWE_PROTECTED), recipient=cersai_pub)
    jwe_compact = enc.serialize(compact=True)
    sig = jws.JWS(jwe_compact.encode("ascii"))
    sig.add_signature(sign_key, alg=None, protected=json_encode(JWS_PROTECTED))
    return sig.serialize(compact=True)


def unprotect(token: str, decrypt_key: jwk.JWK, verify_pub: jwk.JWK = None):
    """
    Peel layers off an inbound `encryptedData` until JSON appears.
    The response layering is not documented, so this detects it: 3 segments = JWS, 5 = JWE.
    Returns (plaintext, layers_seen, signature_verified).
    """
    layers, verified, current = [], False, token.strip()
    for _ in range(4):
        segments = current.count(".") + 1
        if segments == 3:
            s = jws.JWS()
            if verify_pub is not None:
                s.deserialize(current, key=verify_pub)  # raises InvalidJWSSignature if wrong
                verified = True
            else:
                s.deserialize(current)
            layers.append("JWS" + (" (verified)" if verify_pub is not None else " (NOT verified)"))
            current = s.objects["payload"].decode("utf-8")
        elif segments == 5:
            e = jwe.JWE()
            e.deserialize(current, key=decrypt_key)
            layers.append("JWE (decrypted)")
            current = e.payload.decode("utf-8")
        else:
            break
        if current.lstrip().startswith(("{", "[")):
            break
    return current, layers, verified


def structure_of(token: str) -> dict:
    """Shape of a JWS(JWE) token -- used to compare our output against CERSAI's captured requests."""
    outer = token.split(".")
    inner = b64u_decode(outer[1]).decode().split(".")
    return {
        "jws_header": json.loads(b64u_decode(outer[0])),
        "jws_signature_bytes": len(b64u_decode(outer[2])),
        "jwe_segments": len(inner),
        "jwe_header": json.loads(b64u_decode(inner[0])),
        "jwe_wrapped_key_bytes": len(b64u_decode(inner[1])),
        "jwe_iv_bytes": len(b64u_decode(inner[2])),
        "jwe_tag_bytes": len(b64u_decode(inner[4])),
    }


# --------------------------------------------------------------------------- configuration
SCRIPT_DIR = Path(__file__).resolve().parent


def load_dotenv():
    """Load KEY=VALUE pairs from .env (script folder, then cwd) into os.environ.
    Real environment variables win over the file. Values are never printed."""
    for path in (SCRIPT_DIR / ".env", Path.cwd() / ".env"):
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.removeprefix("export ").partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


def find_in_tree(name):
    """First file called `name` under the script folder, skipping the virtualenv."""
    for hit in sorted(SCRIPT_DIR.rglob(name), key=lambda p: (len(p.parts), str(p))):
        if not {".venv", "__pycache__"} & set(hit.parts):
            return str(hit)
    return None


def resolve_paths(args):
    d = Path(args.cert_dir).expanduser() if args.cert_dir else None

    def pick(attr, name):
        value = getattr(args, attr)
        if value:
            return str(Path(value).expanduser())
        if d and (d / name).exists():
            return str(d / name)
        return find_in_tree(name)

    for attr, name in DISCOVER.items():
        setattr(args, attr, pick(attr, name))
    args.sign_key = str(Path(args.sign_key).expanduser()) if args.sign_key else args.enc_key
    args.ca_bundle = str(Path(args.ca_bundle).expanduser()) if args.ca_bundle else None
    if not args.ca_bundle and "ckycregistry.co.in" in args.base_url:
        # CERSAI's chain ends at "GlobalSign Non-Public Root R43", absent from every public trust store.
        args.ca_bundle = find_in_tree("secureapi.ckycregistry.co.in.cer")

    show = lambda p: str(Path(p).relative_to(SCRIPT_DIR)) if p and SCRIPT_DIR in Path(p).parents else (p or "-")
    print(f"host            {args.base_url}")
    print(f"mTLS cert/key   {show(args.mtls_cert)}  {show(args.mtls_key)}")
    print(f"our key         {show(args.enc_key)}  (signs requests, decrypts responses)")
    print(f"CERSAI enc cert {show(args.cersai_cert)}")
    print(f"CERSAI sig cert {show(args.cersai_sign_cert)}")
    print(f"server trust    {show(args.ca_bundle) if args.ca_bundle else 'system CA store'}")


def need(value, label, hint):
    if not value:
        sys.exit(f"error: {label} is not set. {hint}")
    if not Path(value).is_file():
        sys.exit(f"error: {label} not found at {value}")
    return value


def credentials():
    """CLIENT_ID / CLIENT_SECRET from .env or the environment (CKYCRR_-prefixed names also accepted)."""
    cid = os.environ.get("CLIENT_ID") or os.environ.get("CKYCRR_CLIENT_ID")
    secret = os.environ.get("CLIENT_SECRET") or os.environ.get("CKYCRR_CLIENT_SECRET")
    if (not cid or not secret) and not sys.stdin.isatty():
        sys.exit("error: CLIENT_ID / CLIENT_SECRET not found in .env or the environment.")
    cid = cid or input("client_id: ").strip()
    secret = secret or getpass.getpass("client_secret (hidden): ").strip()
    return cid, secret


def make_session(args) -> requests.Session:
    s = requests.Session()
    if args.mtls_cert and args.mtls_key:
        need(args.mtls_cert, "--mtls-cert", "")
        need(args.mtls_key, "--mtls-key", "")
        s.cert = (args.mtls_cert, args.mtls_key)
    else:
        print("warning: no mTLS cert configured -- the secure gateway will likely reject the handshake.", file=sys.stderr)
    if args.insecure:
        print("WARNING: --insecure disables server certificate verification. UAT only.", file=sys.stderr)
        s.verify = False
        requests.packages.urllib3.disable_warnings()
    elif args.ca_bundle:
        s.verify = need(args.ca_bundle, "--ca-bundle", "")
    return s


# --------------------------------------------------------------------------- API calls
def get_token(session, args) -> str:
    if args.token or os.environ.get("CKYCRR_TOKEN"):
        print("using bearer token supplied via --token/CKYCRR_TOKEN")
        return args.token or os.environ["CKYCRR_TOKEN"]
    cid, secret = credentials()
    resp = session.post(
        args.base_url + TOKEN_PATH,
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=TIMEOUT,
    )
    print(f"POST {TOKEN_PATH} -> HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        sys.exit(f"token endpoint returned non-JSON (HTTP {resp.status_code}): {summarize_html(resp.text)}")
    token = body.get("accessToken")
    if resp.status_code != 200 or not token:
        shown = {k: ("***" if "token" in k.lower() else v) for k, v in body.items()}
        sys.exit(f"token request failed:\n{pretty(shown)}")
    print(f"  token fp={fingerprint(token)}  expiresIn={body.get('expiresIn')}s  issuedAt={body.get('issuedAt')}")
    if args.show_token:
        print(f"  accessToken={token}")
    return token


def build_search_plaintext(args) -> str:
    if args.payload_file:
        return Path(args.payload_file).read_text().strip()
    if args.payload:
        json.loads(args.payload)  # validate early
        return args.payload
    o = args.option
    if o == "CKYC":
        if not args.ckyc_no:
            sys.exit("error: --ckyc-no is required for --option CKYC")
        return json.dumps({"ckycNo": args.ckyc_no})
    if o == "PAN":
        if not args.pan:
            sys.exit("error: --pan is required for --option PAN")
        return json.dumps({"ovdDetails": [{"ovdType": "C", "ovdNo": args.pan}]})
    if o == "OVD":
        if not (args.ovd_type and args.ovd_no):
            sys.exit("error: --ovd-type and --ovd-no are required for --option OVD")
        item = {"ovdType": args.ovd_type, "ovdNo": args.ovd_no}
        for key, val in (("fullName", args.full_name), ("dob", args.dob), ("gender", args.gender)):
            if val:
                item[key] = val
        return json.dumps({"ovdDetails": [item]})
    if o == "MOBILE":
        if not args.mobile:
            sys.exit("error: --mobile is required for --option MOBILE")
        return json.dumps({"mobile": args.mobile})
    if o == "VC":
        if not args.alias:
            sys.exit("error: --alias is required for --option VC")
        return json.dumps({"ckycAlias": args.alias})
    sys.exit(f"error: --option {o} has no builder; use --payload / --payload-file (see the guide, section 3.3)")


def search_option_for_wire(option: str) -> str:
    return "OVD" if option == "PAN" else option  # PAN is an OVD search with ovdType=C


def cmd_search(args):
    plaintext = build_search_plaintext(args)
    re_id = args.re_id or os.environ.get("RE_ID") or os.environ.get("CKYCRR_RE_ID")
    if not re_id:
        re_id = FALLBACK_RE_ID
        print(f"note: no RE_ID in .env -- using {re_id} from CERSAI's Postman collection. Confirm it is yours.")
    print(f"plaintext payload ({len(plaintext)} bytes): {plaintext if len(plaintext) < 400 else plaintext[:400] + '...'}")

    sign_key = load_private_jwk(need(args.sign_key, "signing key", "Put encryption.key in certs/ (or pass --enc-key / --sign-key)."))
    cersai_pub = None
    if args.dry_run and not args.cersai_cert:
        print("(dry-run without --cersai-cert: skipping encryption, showing the envelope shape only)")
        encrypted = "<encryptedData would be JWS(JWE(payload)) here>"
    else:
        cersai_pub = load_public_jwk(need(args.cersai_cert, "--cersai-cert",
                                          "CERSAI's PUBLIC encryption certificate is required to encrypt requests. "
                                          "Your two .crt files are self-signed (issuer == subject), i.e. they are yours."))
        encrypted = protect(plaintext, cersai_pub, sign_key)

    envelope = {
        "reId": re_id,
        "requestId": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "ckycInq": {"ckycType": args.ckyc_type, "searchOption": search_option_for_wire(args.option or "CKYC"),
                    "encryptedData": encrypted},
    }
    if args.dry_run:
        print("--- DRY RUN: nothing sent ---")
        print(pretty({**envelope, "ckycInq": {**envelope["ckycInq"], "encryptedData": encrypted[:60] + "..."}}))
        if cersai_pub:
            print("structure:", pretty(structure_of(encrypted)))
        return

    session = make_session(args)
    token = get_token(session, args)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "x-correlation-id": str(uuid.uuid4()),
        "x-idempotency-key": str(uuid.uuid4()),
    }
    if args.verbose:
        shown = {**headers, "Authorization": f"Bearer <fp={fingerprint(token)}>"}
        print("request headers:", pretty(shown))
    resp = session.post(args.base_url + SEARCH_PATH, json=envelope, headers=headers, timeout=TIMEOUT)
    print(f"POST {SEARCH_PATH} -> HTTP {resp.status_code}   correlation-id={headers['x-correlation-id']}")
    handle_response(resp, args)


def handle_response(resp, args):
    raw = resp.text
    try:
        body = resp.json()
    except ValueError:
        print(f"non-JSON response body: {summarize_html(raw)}")
        return
    out = {"http_status": resp.status_code, "response": body}
    inner = body.get("ckycInq", body) if isinstance(body, dict) else {}
    token = (inner.get("encryptedData") if isinstance(inner, dict) else None) or \
            (body.get("encryptedData") if isinstance(body, dict) else None)
    if token and resp.status_code < 400:
        try:
            dkey = load_private_jwk(need(args.enc_key, "--enc-key (decryption key)", "Put encryption.key in certs/ (or pass --enc-key)."))
            vkey = load_public_jwk(args.cersai_sign_cert) if args.cersai_sign_cert else None
            plain, layers, verified = unprotect(token, dkey, vkey)
            print(f"decoded layers: {' -> '.join(layers)}")
            if not verified:
                print("  note: response signature NOT verified (pass --cersai-sign-cert to verify)")
            try:
                out["decrypted"] = json.loads(plain)
            except ValueError:
                out["decrypted_text"] = plain
        except Exception as exc:  # decryption failure is diagnostic, not fatal
            print(f"could not decode encryptedData: {type(exc).__name__}: {exc}")
            print("  (wrong --enc-key, or CERSAI encrypted to a different cert than the one you registered)")
    print(pretty(out, full=args.full))
    if args.save:
        Path(args.save).write_text(json.dumps({"http_status": resp.status_code, "raw": raw,
                                               "decoded": out.get("decrypted", out.get("decrypted_text"))}, indent=2))
        print(f"saved -> {args.save}")


def cmd_token(args):
    session = make_session(args)
    get_token(session, args)


# --------------------------------------------------------------------------- offline self-test
def cmd_selftest(args):
    """Proves the JOSE layer offline: round-trip, tamper detection, and shape vs CERSAI's capture."""
    def new_key():
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return jwk.JWK.from_pem(pem)

    cersai, ours = new_key(), new_key()
    cersai_pub = jwk.JWK.from_json(cersai.export_public())
    ours_pub = jwk.JWK.from_json(ours.export_public())
    payload = json.dumps({"ckycNo": "12345678901234"})

    token = protect(payload, cersai_pub, ours)
    plain, layers, _ = unprotect(token, cersai, ours_pub)  # CERSAI decrypts + verifies our signature
    assert plain == payload, "round-trip mismatch"
    print(f"PASS round-trip           {' -> '.join(layers)}")

    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    try:
        unprotect(tampered, cersai, ours_pub)
    except Exception as exc:
        print(f"PASS tamper detection     rejected ({type(exc).__name__})")
    else:
        raise SystemExit("FAIL tampered signature was accepted")

    mine = structure_of(token)
    print("PASS our token structure:\n" + pretty(mine))
    if args.postman:
        coll = json.loads(Path(args.postman).expanduser().read_text())
        captured = None
        stack = list(coll["item"])
        while stack and not captured:
            it = stack.pop(0)
            if "item" in it:
                stack = it["item"] + stack
                continue
            raw = (it["request"].get("body") or {}).get("raw", "")
            if "encryptedData" in raw:
                body = json.loads(raw.replace("{{$guid}}", "x").replace("{{$isoTimestamp}}", "t"))
                captured = structure_of(body["ckycInq"]["encryptedData"])
        if not captured:
            raise SystemExit("no request with encryptedData found in the Postman collection")
        theirs = captured
        diffs = {k: (mine[k], theirs[k]) for k in mine if mine[k] != theirs[k]}
        if diffs:
            print("MISMATCH vs Postman capture:\n" + pretty({k: {"ours": a, "cersai": b} for k, (a, b) in diffs.items()}))
            raise SystemExit(1)
        print("PASS identical structure to the request captured in the Postman collection")
    print("\nselftest OK -- the crypto layer is consistent. It cannot prove CERSAI accepts it: that needs UAT.")


# --------------------------------------------------------------------------- CLI
def build_parser():
    # Shared flags live on each subcommand (not the top level), so they work after the
    # subcommand, which is how every example in the docstring writes them.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base-url", default=os.environ.get("BASE_URL") or os.environ.get("CKYCRR_BASE_URL") or DEFAULT_BASE_URL)
    common.add_argument("--cert-dir", default=os.environ.get("CKYCRR_CERT_DIR"),
                        help="folder holding mtls.crt, mtls.key, encryption.key")
    common.add_argument("--mtls-cert", default=os.environ.get("CKYCRR_MTLS_CERT"))
    common.add_argument("--mtls-key", default=os.environ.get("CKYCRR_MTLS_KEY"))
    common.add_argument("--enc-key", default=os.environ.get("CKYCRR_ENC_KEY"),
                        help="our private key (decrypts responses)")
    common.add_argument("--sign-key", default=os.environ.get("CKYCRR_SIGN_KEY"), help="defaults to --enc-key")
    common.add_argument("--cersai-cert", default=os.environ.get("CKYCRR_CERSAI_CERT"),
                        help="CERSAI public encryption certificate (encrypts requests)")
    common.add_argument("--cersai-sign-cert", default=os.environ.get("CKYCRR_CERSAI_SIGN_CERT"),
                        help="CERSAI public signing certificate (verifies responses)")
    common.add_argument("--ca-bundle", default=os.environ.get("CKYCRR_CA_BUNDLE"),
                        help="CA chain to trust for the server")
    common.add_argument("--insecure", action="store_true", help="skip server cert verification (UAT only)")
    common.add_argument("--token", help="reuse an existing bearer token (or set CKYCRR_TOKEN)")
    common.add_argument("--re-id")
    common.add_argument("-v", "--verbose", action="store_true")

    p = argparse.ArgumentParser(description="CKYCRR 2.0 UAT tester (Search API)",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest", help="offline crypto check (no network, no credentials)").add_argument(
        "--postman", help="Postman collection JSON: also compare our token shape to its captured request")

    t = sub.add_parser("token", parents=[common], help="fetch an OAuth token and show its fingerprint")
    t.add_argument("--show-token", action="store_true", help="print the full token (it is a credential)")
    t.set_defaults(func=cmd_token)

    s = sub.add_parser("search", parents=[common], help="call POST /api/ckyc/v1/search")
    s.add_argument("--option", choices=["CKYC", "PAN", "OVD", "MOBILE", "VC", "DEMOGRAPHIC", "PHOTO"], default="CKYC")
    s.add_argument("--ckyc-type", choices=["INDIVIDUAL", "LEGAL"], default="INDIVIDUAL")
    for flag in ("--ckyc-no", "--pan", "--mobile", "--alias"):
        s.add_argument(flag)
    s.add_argument("--ovd-type", help="A passport, B voter, C PAN, D DL, E Aadhaar, F NREGA, G NPR")
    s.add_argument("--ovd-no")
    s.add_argument("--full-name")
    s.add_argument("--dob", help="DD-MM-YYYY")
    s.add_argument("--gender", choices=["M", "F", "T"])
    s.add_argument("--payload", help="raw plaintext JSON, overrides the builders (needed for DEMOGRAPHIC/PHOTO/LEGAL)")
    s.add_argument("--payload-file")
    s.add_argument("--dry-run", action="store_true", help="build and show the request, send nothing")
    s.add_argument("--show-token", action="store_true")
    s.add_argument("--full", action="store_true", help="do not truncate long values in the output")
    s.add_argument("--save", help="write the raw + decoded response to this file")
    s.set_defaults(func=cmd_search)
    return p


def main():
    load_dotenv()  # before the parser is built: its defaults read from os.environ
    args = build_parser().parse_args()
    if args.command == "selftest":
        return cmd_selftest(args)
    resolve_paths(args)
    try:
        args.func(args)
    except requests.exceptions.SSLError as exc:
        sys.exit(f"TLS error: {exc}\n  - 'unknown ca': pass --ca-bundle with the CERSAI server chain\n"
                 f"  - 'certificate required / handshake failure': mTLS cert not accepted (is it registered with CERSAI?)")
    except requests.exceptions.RequestException as exc:
        sys.exit(f"request failed: {type(exc).__name__}: {str(exc)[:300]}")
    except requests.exceptions.Timeout as exc:
        sys.exit(f"timed out: {type(exc).__name__}\n  - nothing answered on that host/port; a blocked egress IP (whitelisting) also looks like this")
    except requests.exceptions.ConnectionError as exc:
        sys.exit(f"connection failed: {exc}\n  - is this machine's egress IP whitelisted by CERSAI? (blocked IPs just time out/reset)")


if __name__ == "__main__":
    main()
