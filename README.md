# CKYCRR 2.0 UAT tester

A small command-line tool for testing CERSAI's **CKYCRR 2.0** APIs from your own machine or a whitelisted server: fetch an OAuth token and call the **Search** API, with the request encryption and signing handled for you.

It exists because CKYCRR's `encryptedData` field is a nested JOSE token that Postman cannot build on its own, and because most connection failures (TLS, client certificates, whitelisting) are hard to tell apart without looking closely.

> **Status.** The crypto layer is verified offline and its output matches the structure of the request captured in CERSAI's own Postman collection. A full live call (token, then search) has **not** been completed yet: see [Known limitations](#known-limitations). Search is the only API covered.

## What it does

```
request body   { reId, requestId, timestamp, ckycInq: { ckycType, searchOption, encryptedData } }
encryptedData  = JWS (RS256)  whose payload is a  JWE (RSA-OAEP-256 + A256GCM, cty=text/plain)
                 i.e. encrypt first (to CERSAI's public key), then sign (with your private key)
transport      OAuth2 client_credentials bearer token + mutual TLS
```

Tokens are never printed in full (a short fingerprint is shown instead), and credentials are read from `.env`, never from command-line flags.

## Setup

Requires Python 3.9 or newer.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && chmod 600 .env
```

Edit `.env` and fill in `CLIENT_ID` and `CLIENT_SECRET`. Also set `RE_ID` to your own reporting-entity code: if it is blank the script falls back to the reId used in CERSAI's sample collection and prints a note saying so.

### Certificates

Put these in `certs/` (or anywhere under this folder; they are found by filename). **They are gitignored. Never commit them.**

| File | What it is | From |
|---|---|---|
| `mtls.crt`, `mtls.key` | Your TLS client certificate and private key | You (the cert must be signed by a CA CERSAI trusts) |
| `encryption.key` | Your private key. Signs requests, decrypts responses | You |
| `testbed.enc.ckycregistry.co.in__.cer` | CERSAI's encryption certificate. Encrypts requests | CERSAI onboarding bundle |
| `testbed.sign.ckycregistry.co.in__.cer` | CERSAI's signing certificate. Verifies responses (optional) | CERSAI onboarding bundle |
| `secureapi.ckycregistry.co.in.cer` | CERSAI's server certificate chain | CERSAI onboarding bundle |

Only the **testbed** certificates are ever selected automatically. Production requires passing every path explicitly.

The CERSAI server chain ends at a non-public GlobalSign root, so it is trusted automatically for `*.ckycregistry.co.in` hosts. Any other host uses your system trust store.

> `encryption.key` is assumed to be the key that both signs requests and decrypts responses. If CERSAI rejects your signature, try `--sign-key mtls.key`.

## Usage

Run the offline self-test first. It needs no credentials, certificates or network:

```bash
./ckycrr_search_test.py selftest
```

Then fetch a token, and search:

```bash
./ckycrr_search_test.py token
./ckycrr_search_test.py search --option CKYC   --ckyc-no 12345678901234
./ckycrr_search_test.py search --option PAN    --pan ABCDE1234F
./ckycrr_search_test.py search --option MOBILE --mobile 9876543210
```

Add `--dry-run` to any search to build and display the request without sending it.

| Search option | Flags |
|---|---|
| `CKYC` | `--ckyc-no` |
| `PAN` | `--pan` (sent as an OVD search with type `C`) |
| `OVD` | `--ovd-type`, `--ovd-no`, optional `--full-name`, `--dob DD-MM-YYYY`, `--gender` |
| `MOBILE` | `--mobile` |
| `VC` | `--alias` |
| `DEMOGRAPHIC`, `PHOTO`, legal entities | `--payload '<json>'` or `--payload-file` with the plaintext body from the API guide |

Other useful flags: `--base-url`, `--insecure` (skips server verification, testing only), `--save FILE` (**writes KYC response data to disk, so keep it out of git**), `--full` (do not truncate long values), `-v`.

### From a whitelisted server

CERSAI only accepts calls from whitelisted egress IPs, and a corporate TLS-inspection proxy (Netskope, Zscaler) breaks mutual TLS. `server_probe.sh` is a dependency-free curl script for testing from a server instead.

```bash
./server_probe.sh                      # stage 1: sends NO credentials; shows which hosts accept your client cert
./server_probe.sh token <base-url>     # stage 2: token request to one host; credentials come from .env
```

Copy `server_probe.sh`, `mtls.crt`, `mtls.key` and `secureapi.ckycregistry.co.in.cer` to the server, and a `.env` for stage 2. Delete the key afterwards.

## Reading the errors

| You see | It means |
|---|---|
| `CERTIFICATE_VERIFY_FAILED ... unable to get local issuer certificate` | The server's chain is not trusted. For `ckycregistry.co.in`, make sure `secureapi.ckycregistry.co.in.cer` is in `certs/` |
| Certificate issuer contains `goskope` / `netskope` | A TLS-inspection proxy is intercepting the connection. mTLS cannot pass through it, so test from a server |
| `400 No required SSL certificate was sent` | The server requires mutual TLS and received no client certificate |
| `400 The SSL certificate error` | The server rejected your client certificate. It must be signed by a CA the server trusts; self-signed certificates are refused |
| `HTTP 404` with `Unable to identify proxy for host` | TLS is fine, but no API is deployed on that host and path. Ask CERSAI which host serves your environment |
| Timeout or reset | Your egress IP is not whitelisted, or the port is blocked |
| `could not decode encryptedData` | Wrong `--enc-key`, or CERSAI encrypted to a different certificate than the one you registered |

## Known limitations

- **Search only.** Download, Create and Update are not implemented.
- **No successful live call yet.** Against the hosts tried so far, the testbed gateway had no APIs deployed, and the UAT gateway rejected self-signed client certificates. A CA-signed client certificate is needed.
- **Response layering is assumed.** The guide does not document how responses are wrapped, so the script detects it (a 3-part token is treated as a JWS, a 5-part token as a JWE). Pass `--cersai-sign-cert` to verify the response signature.
- **Header key order differs** from CERSAI's sample (`jwcrypto` sorts keys). Both parse identically as JSON.

## Keeping secrets out of git

`.gitignore` already excludes `.env`, every key and certificate type, CERSAI's PDFs and Postman collections (which embed live credentials in plaintext), and saved responses. Before your first push, check `git status` and `git diff --cached --stat` and confirm only the scripts, `README.md`, `requirements.txt`, `.env.example` and `.gitignore` are staged.

If a secret is ever committed, deleting it in a later commit does not remove it from history. Rotate it.
