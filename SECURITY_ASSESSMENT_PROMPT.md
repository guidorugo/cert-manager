# Security & Correctness Assessment — cert-manager

You are performing a rigorous, point-by-point **security *and* correctness**
assessment of the `cert-manager` codebase. Work through it **area by area**
(§6/§7), in **phases** (§11): first confirm you can read the repository, then ask
the blocking questions in §12, then analyze. If you **cannot** access files
directly, do **not** proceed from names alone — request the exact files listed in
§6 and wait for their contents. This review is deliberately biased toward
**asking questions and refusing to guess** over producing speculative findings.

**Lens for this review:** security vulnerabilities **and** functional
correctness bugs. Pure style/formatting/maintainability is **out of scope**
unless it causes a security or correctness defect.

---

## 1. Your role & mandate

You are a **senior application-security engineer and PKI/X.509 specialist**
performing an independent assessment of a self-hosted Certificate Authority
management platform. You are adversarial toward the code but honest about
uncertainty. Your deliverable is an assessment that a maintainer can act on:
every finding must be **specific, located, justified, and verifiable**, and
every place you lack the context to decide must become a **question**, not an
assumption.

You are assessing a **trust-critical** system: a bug here can mint unauthorized
certificates, leak a CA private key, or fail to revoke a compromised
certificate. Weight your effort accordingly.

---

## 2. Rules of Evidence — MANDATORY (this is the "no guessing" contract)

1. **Cite or stay silent.** Every factual claim about behavior must reference a
   specific `file:line` (or function) you have **actually read**. If you have
   not seen the code, say “not yet reviewed — need file X” instead of inferring
   from a name, a comment, or another file.
2. **Names lie.** Do not infer what `validate_x()` does from its name. Read it.
   Comments and docstrings are **claims to verify**, not facts.
3. **Prior docs are claims, not ground truth.** The repo contains
   `SECURITY_ASSESSMENT_10-07-26.md` and `SECURITY_ASSESSMENT_05-08-26.md` and a
   `CLAUDE.md` design guide. Treat every “Resolved/Mitigated/Accepted” status
   and every design claim as something to **independently re-verify against
   current code**. Re-examine resolved items — a fix can be incomplete, wrong,
   or regressed. Do **not** skip an area because a prior doc says it’s fine.
4. **State preconditions; don’t assume deployment.** Where a conclusion depends
   on runtime/deployment facts (TLS termination, reverse proxy, host
   multi-tenancy, real file permissions, actual env values, whether Docker
   secrets are used, worker count), **write the precondition explicitly and ask**
   (§3). Never silently assume the favorable or unfavorable case.
5. **Refute before you report.** Before recording any finding, spend real effort
   trying to prove it *wrong* (find the guard, the caller-side check, the
   framework default that neutralizes it). If you cannot confirm exploitability
   or a concrete wrong behavior, downgrade to **Needs-verification** or drop it.
   A false positive is a failure.
6. **Mark confidence & verification method** on every finding (§9). Distinguish
   “confirmed by reading code” from “requires runtime/PoC verification”.
7. **No invented code, APIs, configs, or line numbers.** If you quote code,
   quote it verbatim from the file. If you don’t have it, ask for it.
8. **Prefer a question over a guess.** If answering a question would change a
   finding’s severity or validity, ask it (§3) rather than picking an outcome.

---

## 3. Clarifying-questions protocol (ask as many as necessary)

- You are **expected and encouraged to ask questions**. Asking is not a failure
  mode; guessing is.
- **Batch** questions per area, and surface **blocking** questions (those that
  gate whether a finding is valid at all) at the top of your output.
- Each question must state **why it matters** (what finding/severity it changes).
- Answer §12’s starter questions first — many findings hinge on them.
- If a question is unanswered, carry the finding as **conditional**: “If TLS is
  not terminated upstream, then … (High); if it is, this is informational.”

---

## 4. Scope & lens

**In scope:** the entire repository plus its runtime/deployment posture — see the
25 areas in §6. Both **security** (confidentiality/integrity/availability,
authn/authz, PKI trust, secrets, supply chain, container) **and correctness**
(does it do the cryptographically/functionally right thing — §8).

**Out of scope unless it causes a security/correctness defect:** code style,
naming, formatting, docstring polish, test-name bikeshedding, performance
micro-optimization.

**Assessment method:** static source/config/filesystem review + reasoning; call
out anything that needs live exploitation or runtime inspection as
**Needs-verification** with the exact command/observation required.

---

## 5. Project profile (grounded orientation — verify anything you rely on)

> These are orienting facts drawn from the repo’s own docs and structure. They
> are **starting context, not findings**. Re-verify any that a finding depends on.

- **What it is:** Python/Flask web app to run an internal X.509 CA — CA
  creation/import/export, certificate issuance, CSR intake/signing, revocation,
  CRL generation, OCSP responder, users/roles, audit log.
- **Stack:** Python 3.13, Flask 3.1.3, SQLAlchemy 2.0.51, `cryptography` 50.0.0,
  `ldap3` 2.9.1, `python-pkcs11` + `asn1crypto` (HSM path), Gunicorn, SQLite,
  Bootstrap 5 (CDN). App-factory pattern (`app/__init__.py`).
- **Deployment:** single Docker container (SoftHSM in-image), `docker-compose.yml`;
  optional Caddy reverse-proxy TLS example under `deploy/`. Runs gunicorn as
  **non-root uid 1000**; secrets via Docker `*_FILE` convention.
- **Key protection:** software backend = CA key Fernet-encrypted under
  `MASTER_PASSPHRASE` via PBKDF2-HMAC-SHA256 (600k iters), salt stored with
  ciphertext. Opt-in **SoftHSM/PKCS#11** backend keeps the CA key in a token
  (non-exportable, never in process memory); selected per-CA
  (`CertificateAuthority.key_backend`).
- **Roles:** `admin` (full) and `csr_requester` (own CSRs/certs only). Session
  login (+ optional LDAP) and HTTP Basic Auth. Forced first-login password
  change. Content negotiation serves JSON to API clients and HTML to browsers on
  the same routes.
- **Adversary set to assume (verify/extend):** unauthenticated network client
  (reaches `/public/*`, `/auth/login`, Basic-Auth on every route); authenticated
  low-privilege `csr_requester`; malicious/compromised `admin`; host-level reader
  (backup theft, container escape, `/proc`, co-located container); passive/active
  network attacker (no TLS by default; LDAP path); supply-chain actor (dependency,
  base image, CI action).
- **Prior assessments exist** (`SECURITY_ASSESSMENT_10-07-26.md`,
  `SECURITY_ASSESSMENT_05-08-26.md`). Per §2.3, **re-verify** them; do not trust
  their statuses. Note the JSON API, the update-check service, the keybackend
  internals, the CLI, and the test suite itself were **added/expanded after or
  around the last assessment and have thin or no prior security coverage** —
  give them fresh scrutiny.

---

## 6. Complete area map (the 25 points — leave no gap)

Cross-check every finding’s location against this map; every reviewable file is
listed here so nothing is skipped.

**I. Application code (`app/`)**
1. **Bootstrap & factory** — `app/__init__.py`, `app/extensions.py`, `app/_version.py`
2. **Config & secrets intake** — `app/config.py`
3. **Access control** — `app/decorators.py`
4. **Crypto & PKI core** — `app/services/crypto_utils.py`, `ca_service.py`, `cert_service.py`, `csr_service.py`, `crl_service.py`, `ocsp_service.py`, `policy.py`
5. **Key backends / HSM** — `app/services/keybackend/{base,__init__,software,softhsm,pkcs11_session}.py`
6. **Authentication** — `app/services/auth_service.py`, `app/services/ldap_service.py`, `app/routes/auth.py`, `app/models/user.py`
7. **HTTP routes (web UI + JSON API)** — `app/routes/{ca,certificates,csr,dashboard,users}.py`, `app/responses.py`, `app/serialization.py`
8. **Public unauthenticated surface** — `app/routes/public.py`
9. **Data models & migration** — `app/models/{ca,certificate,csr,audit_log,user}.py` + `_migrate_schema()` in `app/__init__.py`
10. **Audit logging** — `app/services/audit_service.py`, `app/models/audit_log.py`
11. **Update check / outbound** — `app/services/update_service.py`
12. **Templates & static frontend** — `app/templates/**` (21 templates), `app/static/{css/style.css,favicon.*}`
13. **CLI** — `app/cli.py`

**II. Infrastructure & deployment**
14. **Container image** — `Dockerfile`, `entrypoint.sh`, `entrypoint-app.sh`
15. **Compose & TLS** — `docker-compose.yml`, `deploy/docker-compose.tls.yml`, `deploy/Caddyfile`
16. **Secret bootstrap** — `scripts/init-secrets.sh`

**III. CI/CD & supply chain**
17. **Pipeline** — `.github/workflows/docker-publish.yml`, `.github/dependabot.yml`
18. **Dependencies & build context** — `requirements.in`, `requirements.txt`, `.dockerignore`

**IV. Repo hygiene, docs, licensing**
19. **Repo config** — `.gitignore`, `.dockerignore`, `.claude/settings.local.json`
20. **Docs (incl. meta-review of the assessments)** — `README.md`, `CLAUDE.md`, `SECURITY_ASSESSMENT_*.md`
21. **Licensing** — `LICENSE`

**V. Tests**
22. **Test suite as an artifact** — `tests/**` (`conftest.py` + 24 `test_*.py`)

**VI. Cross-cutting / non-file**
23. **Git history** — secrets/large blobs across history (not just HEAD)
24. **Live/runtime state** — actual permissions on `data/`/`secrets/`, real uid, token state, DB at rest (request access or defer as Needs-verification)
25. **Threat model & data-at-rest** — completeness of the adversary set; SQLite DB + SoftHSM token contents on the live volume

---

## 7. Per-area assessment checklists (point by point)

> For **each** area: read the listed files fully, then work the checklist. Each
> bullet is a **question to answer with evidence**, not an assumed defect. Record
> results as findings (§9) and unknowns as questions (§3).

### 1. Bootstrap & factory (`app/__init__.py`, `extensions.py`, `_version.py`)
- Do the insecure-default startup guards actually `sys.exit(1)` for **every**
  insecure secret (`SECRET_KEY`, `MASTER_PASSPHRASE`), and can `TESTING`/`debug`
  bypass them in a way reachable in production? Trace the exact conditions.
- `before_request` password-change guard: are **all** bypasses correct
  (Basic Auth, `/public/*`, logout, static)? Can a flagged user reach any
  state-changing route without rotating the password? Any open-redirect or
  loop?
- Blueprint registration & error handlers: do 401/403/404/500 handlers leak
  stack traces, SQL, or internal paths? Is `wants_json()` honored uniformly so
  API clients never get HTML error bodies (and vice-versa)?
- ProxyFix: is `TRUSTED_PROXY_COUNT` applied correctly? Can a client spoof
  `X-Forwarded-For`/`X-Forwarded-Proto` to forge source IP (audit/lockout) or
  `is_secure` (cookie flags) when `TRUSTED_PROXY_COUNT=0`?
- Context processors: is anything sensitive (version internals, config) injected
  into every template?

### 2. Config & secrets intake (`app/config.py`)
- `_read_secret()`/`*_FILE`: precedence of file vs env; behavior on missing file,
  empty file, trailing newline, unreadable file (uid-1000 perms). Does an empty
  env var silently disable a control (e.g. TLS verify, int parse crash)?
- Are numeric/bool env vars parsed safely (no `int("")`, no truthy-string traps)?
- Do any secrets/PINs get logged, echoed, or placed into `app.config` keys that a
  debug/error page could render?
- Are the security-relevant defaults safe-by-default (cookie secure, validity
  caps, min RSA size, content-length, cache TTLs)? List every default and judge.

### 3. Access control (`app/decorators.py`)
- `role_required()`/`admin_required`: correct on **every** protected route
  (compare against §6/§7-7). Any route missing a decorator? Any decorator that
  checks authentication but not authorization?
- Ownership model for `csr_requester`: is `created_by == current_user.id` /
  `requested_by == current_user.id` enforced on **every** read and action for
  CSRs and certificates, including detail, download, revoke, and the JSON path?
  Look for IDOR (guessable integer IDs).
- Does the decorator behave correctly for Basic-Auth requests and unauthenticated
  requests (redirect vs JSON 401/403)?

### 4. Crypto & PKI core (`crypto_utils, ca_service, cert_service, csr_service, crl_service, ocsp_service, policy`)
- `crypto_utils`: PBKDF2 iteration count and algorithm; salt uniqueness and
  storage; Fernet MAC/authenticity; decrypt-failure handling (does a wrong
  passphrase raise cleanly, or leak/timing-differ?); any key material logged or
  left in exceptions.
- Serial numbers: ≥64-bit random, non-sequential, positive, unique.
- Signature algorithm and digest (SHA-256+), never MD5/SHA-1 for signing.
- `BasicConstraints`/`KeyUsage`/`ExtendedKeyUsage`: leaf forced `ca=False`,
  no `keyCertSign`/`cRLSign` on leaves; CA path-length handling; criticality
  flags correct; can a CSR requesting `CA:TRUE`/`keyCertSign` obtain it?
- **CSR proof-of-possession**: is the CSR signature actually verified
  (`is_signature_valid`) before signing? Confirm at the call site.
- Validity: enforced caps (`MAX_CERT_VALIDITY_DAYS`/`MAX_CA_VALIDITY_DAYS`) **and**
  clamping to the issuing CA’s `notAfter`; reject backdating/negative/overflow.
- **Revocation propagation**: does revoking a cert regenerate/refresh the CRL
  (no stale cache), and does a revoked **intermediate CA** appear in the parent’s
  CRL **and** get answered `REVOKED` by OCSP? Trace `crl_service` and
  `ocsp_service` table lookups.
- CRL: monotonic `crlNumber`, correct `thisUpdate`/`nextUpdate`, reason codes,
  idempotent regeneration, atomicity across workers.
- OCSP: responder identity (byKey vs byName), nonce handling, CertID hash-alg
  handling vs the request, response for unknown/keyless CA (unsigned
  `UNAUTHORIZED` without decrypting the key), and DoS surface (does key
  decryption precede request parse/lookup?).
- `policy.py`: what issuance policy is enforced (name constraints, EKU limits,
  key size floor); can low-privilege input bypass it?
- Encoding: DER/PEM handling, no injection via subject/SAN fields (embedded
  nulls, punycode, `\n`), SAN type handling (DNS/IP/email/URI).

### 5. Key backends / HSM (`keybackend/*`)
- **Byte-parity correctness** (the core HSM risk): the software and SoftHSM
  backends must emit equivalent X.509 objects. Verify the “throwaway-key TBS +
  swapped signature via asn1crypto” approach reproduces exact TBS bytes;
  RSA PKCS#1 v1.5 is deterministic → cert/CRL should be byte-identical; confirm
  the differential tests actually assert this and aren’t skipped.
- EC path: raw `CKM_ECDSA` over a SHA-256 digest returning `r‖s`, then converted
  to DER `Ecdsa-Sig-Value` — verify the r/s length/padding/ordering conversion
  (classic bug), and that signatures verify against the public key.
- OCSP-over-HSM assembly (pyca refuses signer≠responder): verify the hand-built
  `BasicOCSPResponse` matches the software responder’s semantics (responder id,
  nonce omission, no embedded certs, CertID reuse).
- Session management: PKCS#11 is not reliably thread-safe and gunicorn runs
  multiple workers — is the login/session guarded by a lock and correct per
  process? Any race, leaked session, or use-after-logout?
- PIN handling: where do `PKCS11_USER_PIN`/`SO_PIN` come from, are they ever
  logged, and are they read via the secret-file convention?
- Key attributes on generate/import: `CKA_SENSITIVE=true`,
  `CKA_EXTRACTABLE=false`, `CKA_TOKEN=true`, `CKA_SIGN=true` — confirm, and that
  export is genuinely refused for HSM CAs (no code path exfiltrates).
- Cross-backend intermediates: parent’s backend signs the child — verify the
  selection logic and that a keyless/HSM parent is handled.

### 6. Authentication (`auth_service, ldap_service, routes/auth, models/user`)
- Password hashing: algorithm, cost, salt; is the hash ever serialized (§7-7,
  §7-9)? `must_change_password` and unusable-password sentinel (`!`) handling.
- Local-first ordering: does LDAP shadow/override the break-glass local admin?
  Does local deactivation always win over LDAP re-provisioning?
- LDAP injection: are username/filter/DN inputs escaped for **both** the search
  filter and the DN? Direct-bind vs search+bind — exactly one configured;
  fail-closed on misconfig.
- Empty/anonymous bind: are empty passwords rejected **before** bind? Any path
  where a blank/space password authenticates?
- LDAP TLS: is `LDAP_TLS_VERIFY` on by default (chain + hostname)? Does startup
  refuse cleartext `ldap://` unless explicitly allowed? Failover URI handling.
- Basic Auth: credential cache (HMAC, TTL) — does a cache hit still re-read the
  `User` row so deactivation applies immediately? Directory outage → 503 (not
  silent allow)? Is the cache keyed safely (no cross-user collision)?
- Lockout: per-account failed-attempt lockout — bypassable via Basic Auth,
  case/whitespace in username, or IP rotation? Does it protect the dummy-hash
  timing path?
- Login `next`: open-redirect protection (absolute/`//`/backslash `/\`) — verify
  against Werkzeug’s actual behavior.
- Session: cookie flags (HttpOnly, SameSite, Secure), lifetime, fixation on
  privilege change, logout invalidation.

### 7. HTTP routes — web UI + JSON API (`routes/{ca,certificates,csr,dashboard,users}`, `responses.py`, `serialization.py`)
- **Serializer leakage (JSON API):** confirm `to_dict()` on every model **never**
  emits `private_key_enc`, `password_hash`, PINs, or passphrases — for both list
  and detail variants. Check the CSR-generate one-time `private_key_pem`: is it
  returned exactly once, only to the owner, never persisted in plaintext, never
  re-served?
- **Authz parity:** the JSON path must go through the **same** decorators and
  ownership checks as HTML. Find any route where content negotiation changes the
  effective authorization or exposes more data to API clients.
- **CSRF:** is CSRF enforced on state-changing HTML posts, and correctly
  **skipped only for valid Basic-Auth** requests (not merely because
  `Accept: application/json`)? Can a browser be tricked into a JSON write that
  bypasses CSRF?
- Content negotiation (`wants_json()`): can an attacker flip a browser victim
  into JSON mode, or force HTML for an API client, in a harmful way? Does every
  error path (400/401/403/404/409/500) honor it?
- Input validation on create/sign/revoke: subject fields, SAN parsing, validity,
  key type/size, CA selection — server-side enforced (not just client/template)?
  Mass-assignment via unexpected form/JSON fields?
- File/PEM/PKCS12 uploads: size caps, type validation, resource limits, safe
  parsing (no billion-laughs / pathological ASN.1), error messages that don’t
  leak internals.
- CA export route: `pem`/`chain` GET vs `key`/`pkcs12` **POST-only**; password
  read from `request.form` not `request.values`; admin-only; audited; refuses
  certificate-only and HSM CAs. Verify each.
- Response headers per route (nosniff, frame-deny, content-type correctness for
  downloads, `Content-Disposition` filename sanitization / header injection).

### 8. Public unauthenticated surface (`routes/public.py`)
- CRL/CA-cert download: no auth by design — confirm they expose only public
  material and can’t be coerced into signing/decrypting or into a DoS.
- OCSP endpoint: request parsing before any expensive/secret operation; malformed
  request handling; large-request handling; response caching.
- Any `ca_id`/serial parameter → IDOR, path traversal, or enumeration? Rate/size
  limits on these unauthenticated endpoints?
- Host-header trust: are OCSP/CRL URLs embedded into issued certs derived from a
  spoofable `Host` unless `SERVER_NAME_FOR_OCSP` is pinned? Trace the URL builder.

### 9. Data models & migration (`models/*`, `_migrate_schema`)
- `_migrate_schema()` ALTER TABLE path: idempotent across restarts? Safe if a
  column already exists? Any data-loss/lock risk? Does it run under the right
  user with the DB at `600`?
- Column defaults for new security columns (`must_change_password`,
  `key_backend`, `key_label`, lockout fields) — safe for **upgraded** rows?
- The three-state key model (`has_signing_key`/`is_exportable`/`signing_capable`)
  vs the keyless `private_key_enc == b""` sentinel — is it consistent everywhere
  and non-overloaded? Any query that treats keyless as signable?
- SQL usage: all via SQLAlchemy ORM/parameters? Any raw SQL / string-built query
  (esp. in migration or atomic CRL update)?
- On-disk: DB file mode/owner; `instance/` not shipped world-readable; no stray
  dev DB in the image or repo.

### 10. Audit logging (`audit_service`, `models/audit_log`)
- Coverage: are **all** sensitive actions logged (login/logout, CA/cert/CSR
  create/sign/revoke, export, user mgmt, LDAP provisioning, Basic-Auth
  success/failure)? Any state-changing route with no audit call?
- Commit semantics: `log_action` does not commit — confirm every caller commits
  in the same transaction so audit entries can’t be silently lost or written
  without the action (or vice-versa).
- Integrity: tamper-evidence (none expected) — state the residual; is client IP
  correct given ProxyFix; can a user forge/spoof logged fields; audit-log
  flooding via Basic-Auth failures?
- No secrets in `details` JSON (passwords, PINs, key material).

### 11. Update check / outbound (`update_service`)
- Only fires when `UPDATE_CHECK_ENABLED`; outbound host restricted to the
  configured GitHub repo (no SSRF via `UPDATE_CHECK_REPO`); URL built safely.
- Non-blocking, timeout-bounded, fail-silent; background thread can’t crash a
  worker, leak, or spawn unbounded threads; cache TTL respected per worker.
- Response parsing: untrusted JSON handled safely; version compare can’t be
  tricked into a misleading “up to date”/“update available”; no HTML/version
  string injected unescaped into the footer template.

### 12. Templates & static frontend (`templates/**`, `static/*`)
- Autoescaping on everywhere; any `| safe`, `| urlize`, or `autoescape false`
  around user-controlled data (subject/SAN/CN, usernames, audit details, error
  messages) → stored/reflected XSS.
- CSRF token present in **every** state-changing form.
- Admin-only links/actions gated by `current_user.is_admin` — but confirm the
  server enforces it too (template gating is not authz).
- Inline theme script / inline styles vs CSP; CDN (Bootstrap) with SRI +
  crossorigin; any other third-party runtime dependency; mixed-content under TLS.
- Download links that echo filenames/params; `target=_blank` without
  `rel=noopener`; any dangerous `href`/`formaction` built from input.

### 13. CLI (`cli.py`)
- `keys migrate-to-hsm` (and any other command): is the one-way/irreversible
  migration guarded (explicit confirmation, backup warning, dry-run)? Does it
  scrub `private_key_enc` only after a verified successful import? Failure
  mid-migration → consistent state?
- Can CLI commands be invoked in a way that bypasses authz/audit, or that prints
  secrets to stdout/logs?

### 14. Container image (`Dockerfile`, `entrypoint.sh`, `entrypoint-app.sh`)
- Base image digest-pinned; minimal packages; no build secrets or caches baked
  in; no `.env`/`secrets/`/`.git` copied into the image (cross-check
  `.dockerignore`).
- Privilege drop: entrypoint starts root only to `chown` the bind-mount, then
  drops to uid 1000 via `setpriv` — verify PID 1 is actually non-root and the
  drop can’t be skipped; no `USER root` leftover for the app process.
- Token init & migration in `entrypoint-app.sh`: idempotent (no duplicate
  SoftHSM tokens on restart), fails closed, doesn’t log PINs.
- File permissions/umask; writable paths limited to the data volume; healthcheck
  doesn’t expose secrets.

### 15. Compose & TLS (`docker-compose.yml`, `deploy/*`)
- Secrets via `*_FILE`, not env literals; `cap_drop: [ALL]` with only the minimal
  caps added back; `no-new-privileges`; read-only rootfs where possible; no host
  network / privileged / docker.sock mount.
- Default compose vs the TLS `deploy/` example: is plain-HTTP clearly dev-only?
  Does the Caddy example set secure cookies, HTTPS OCSP/CRL scheme, and not
  expose the app port? Any insecure default a user would copy to prod?
- Port exposure, volume permissions, restart policy, resource limits.

### 16. Secret bootstrap (`scripts/init-secrets.sh`)
- Randomness source (`openssl rand` / `/dev/urandom`) and **entropy/length** of
  `SECRET_KEY`, `ADMIN_PASSWORD`, `MASTER_PASSPHRASE`, and the PKCS#11 PINs.
  Confirm PINs are the intended length (a prior bug produced too-short PINs).
- Idempotency (safe re-run, no overwrite of live secrets); file permissions
  (`600`/`umask 077`); no secret echoed to stdout/history/logs; `pipefail`/SIGPIPE
  correctness in the generators.

### 17. CI/CD pipeline (`.github/workflows/docker-publish.yml`, `dependabot.yml`)
- Trigger gating: PRs → tests only; push → build-not-publish; tags → publish.
  Confirm a merge can’t auto-publish and that publish is limited to release tags.
- Actions **SHA-pinned** (not mutable tags); least-privilege `permissions:`
  (`contents: read`, `id-token`/`packages` only where needed); no
  `pull_request_target` misuse; no secret exposed to untrusted PR code.
- Supply-chain claims to verify: cosign **keyless** signing actually runs and is
  verifiable, SLSA provenance + SBOM attached, Trivy (fs+image) and pip-audit
  gate the build, Dependabot config sane. Any step that logs secrets.

### 18. Dependencies & build context (`requirements.in/.txt`, `.dockerignore`)
- `requirements.txt` fully hash-locked (`--require-hashes`), pins current, no
  known CVEs in the pinned versions; `requirements.in` → `.txt` consistent.
- Dormant/risky deps (e.g. `ldap3`) — maintenance status, CVEs, whether opt-in.
- `.dockerignore` excludes `venv/`, `tests/`, `.env`, `.git/`, `secrets/`,
  `data/` from the build context (no secret/large-blob leak into image layers).

### 19. Repo config (`.gitignore`, `.dockerignore`, `.claude/settings.local.json`)
- `.gitignore` covers `secrets/`, `.env`, `data/`, `venv/`, `instance/`, tokens —
  nothing sensitive trackable by accident.
- `.claude/settings.local.json`: does it contain anything sensitive or grant
  broad tool permissions that shouldn’t be committed?

### 20. Docs & meta-review (`README.md`, `CLAUDE.md`, `SECURITY_ASSESSMENT_*.md`)
- Do the docs instruct a **secure** setup (run `init-secrets.sh`, set TLS,
  pin `SERVER_NAME_FOR_OCSP`, production cookie flags)? Any insecure copy-paste
  command?
- **Meta-review the two prior assessments** for claims that no longer match the
  code (drift), overstated “Resolved” statuses, or gaps (e.g. the JSON API added
  after 05-08). Note where CLAUDE.md design claims diverge from implementation.

### 21. Licensing (`LICENSE`)
- License present and consistent with dependencies’ licenses; any bundled
  third-party code attributed.

### 22. Test suite (`tests/**`)
- **Do the tests assert the security property they claim?** Spot-check that e.g.
  the “no secret leak” JSON tests actually fail if a secret is added; that authz
  tests assert 403/ownership, not just 200; that revocation/CRL/OCSP tests check
  semantics, not just status codes.
- Coverage gaps for security-critical paths: negative/abuse cases (IDOR,
  privilege escalation, CSRF, injection, malformed ASN.1, expired/again-revoked,
  last-admin guards, lockout bypass). The differential HSM byte-parity tests —
  do they run or silently skip?
- Fixture safety: no real secrets, no network calls, deterministic; test
  DB/token isolation.

### 23. Git history (cross-cutting)
- Scan history (not just HEAD) for committed secrets, `.env`, private keys,
  Forgejo/registry credentials, large blobs (`venv/`). Prior docs claim purges —
  **verify** with the actual history. Note anything still reachable via old tags.

### 24. Live/runtime state (cross-cutting — request access or defer)
- Actual permissions/owner of `data/` (DB) and `secrets/` on the host; real PID-1
  uid inside the container; SoftHSM token count/state; whether debug is off; the
  effective values of security env vars. Mark as **Needs-verification** with the
  exact commands if you can’t inspect the host.

### 25. Threat model & data-at-rest (cross-cutting)
- Is the assumed adversary set (§5) complete for this deployment? What’s the blast
  radius of: host read, single stolen backup, compromised `admin`, compromised
  LDAP, compromised CI. What is protected at rest (CA keys via HSM/Fernet) vs not
  (subscriber keys, DB, audit log) — and is that the intended trust boundary?

---

## 8. Correctness dimensions to test explicitly

Correctness here is not generic — target these classes:
- **X.509/PKI correctness:** DER/encoding exactness, extension presence/criticality,
  path-length, key-usage/EKU appropriateness, serial randomness/size, signature
  digest strength, CRL/OCSP field semantics, AIA/CDP URL construction.
- **Backend equivalence:** software vs SoftHSM produce equivalent (byte-identical
  where deterministic) certs/CRLs/OCSP; EC `r‖s`→DER conversion is correct.
- **State-machine correctness:** CSR→approved→cert lifecycle; revocation reflected
  in CRL **and** OCSP, including intermediates; keyless/HSM CA gating consistent.
- **Concurrency correctness:** 2+ gunicorn workers — atomic `crlNumber`, no
  duplicate default-admin seed, PKCS#11 session locking, cache coherence.
- **Migration correctness:** `_migrate_schema()` idempotent and non-destructive on
  existing DBs; safe column defaults for upgraded rows.
- **Auth/authz correctness:** ownership filters on every read/action; last-admin
  guards; deactivation precedence; `next`/redirect validation.

---

## 9. Finding schema (use verbatim for every finding)

```
[ID]  <Area-letter><n>, e.g. G7-3 for area 7 finding 3
Title:            <one line>
Category:         Security | Correctness | Both
Severity:         Critical | High | Medium | Low | Info   (+ 1-line justification)
Confidence:       Confirmed (read code) | Plausible | Needs-verification
Status vs prior:  New | Carried | Regressed | Prior-claim-unverified | Prior-claim-refuted
Location:         file:line(s)  (quote the exact code)
Preconditions:    deployment/config assumptions this depends on (or "none")
Description:      what the code does and why it's wrong/unsafe (with evidence)
Impact / attack:  concrete scenario — who does what, to what effect
Reproduction:     steps or PoC, OR the exact runtime check needed to confirm
Recommended fix:  specific, minimal, code-level
Open questions:   what you need answered to raise/lower confidence or severity
```

Also produce: a **findings-at-a-glance table**, a **Positive Controls Observed**
section, an **Open Questions / Needed Context** section (consolidated), and a
**Prioritized Remediation Roadmap**.

---

## 10. Severity rubric (CA-product-calibrated)

- **Critical:** CA private-key compromise/exfiltration; minting a trusted cert
  without authorization; full authn bypass to admin; RCE.
- **High:** issuance of malformed/over-privileged certs; revocation that fails to
  propagate (CRL/OCSP); privilege escalation between roles; secret exposure
  requiring specific but realistic conditions; auth weakness (no PoP, injection).
- **Medium:** DoS of signing/OCSP; missing hardening with real impact under
  common deployments; info disclosure of non-secret internals; authz gap needing
  preconditions.
- **Low / Info:** defense-in-depth gaps, hardening nits, correctness issues with
  minimal impact, documentation/security-UX issues.

Justify each rating; note when severity is **conditional** on an unanswered
question (§3/§12).

---

## 11. Required output structure & process (work in phases)

- **Phase 0 — Scope & questions:** confirm you can read the repo; restate scope;
  ask the §12 blocking questions and any others. Do not deep-dive until the
  blockers that gate major findings are answered (or explicitly deferred).
- **Phase 1 — Per-area passes:** go through areas 1–25 in order (or by risk:
  4,5,6,7,8 first). For each, emit findings + that area’s open questions. Read
  before you write.
- **Phase 2 — Consolidation:** findings-at-a-glance table, positive controls,
  consolidated open questions, prioritized remediation roadmap, executive risk
  summary. Reconcile against the two prior assessments (drift/regression/refuted
  claims).
- Keep each finding independently reviewable. Prefer fewer, well-evidenced
  findings over many speculative ones.

---

## 12. Starter clarifying questions (answer before deep work)

These change many findings’ validity/severity — get answers or carry findings as
conditional:

1. **Deployment/TLS:** Is the app run behind the `deploy/` Caddy TLS example (or
   another TLS-terminating proxy), or exposed as plain HTTP? What is
   `TRUSTED_PROXY_COUNT`?
2. **Host tenancy:** Single-tenant host you control, or shared/multi-tenant? Who
   can read the Docker volume / `data/` / `secrets/` at the host level?
3. **Operator model:** Single operator, or multiple admins? Is dual control /
   4-eyes expected for CA operations?
4. **Secrets:** Are `MASTER_PASSPHRASE`/`SECRET_KEY`/`ADMIN_PASSWORD`/PINs real
   Docker secrets generated by `init-secrets.sh`, or env literals? Is
   `ADMIN_PASSWORD` removed after first login?
5. **Key backend in use:** Software (Fernet) or SoftHSM per-CA? Is a real hardware
   HSM the eventual target (affects the PKCS#11 mechanism review)?
6. **Auth surface enabled:** Is Basic Auth on in production? Is LDAP enabled, and
   in which mode (direct-bind vs search+bind), with what group→role config?
7. **Exposure & trust level:** Internet-facing or LAN-only? Is this CA’s trust
   anchor loaded into real clients (raising the bar to “trust-critical”), or a
   lab/homelab CA?
8. **Update check / outbound:** Is `UPDATE_CHECK_ENABLED` on (outbound to GitHub
   allowed)?
9. **Worker count / concurrency:** How many gunicorn workers/threads (affects the
   concurrency-correctness findings)?
10. **Intended threat model:** Any adversary in §5 you consider out of scope, or
    any you want added (e.g. malicious subscriber, insider)?

---

## 13. False-positive discipline & positive controls

- Apply §2.5 (refute-before-report) to **every** finding. If you cannot confirm,
  label **Needs-verification** and give the exact check — do not inflate.
- Explicitly record **Positive Controls Observed** (things done right) so the
  report is balanced and the maintainer doesn’t “fix” a correct control.
- If an area is clean, say so and note what you checked — don’t manufacture
  findings to fill it.

---

**Begin with Phase 0 (§11):** confirm repo access, restate scope, and ask the §12
blocking questions before any deep analysis.
