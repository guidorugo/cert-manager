# Security Assessment — cert-manager (X.509 CA Management Platform)

> Application-security & PKI review of the `cert-manager` Flask application.
> **Assessment date: 2026-08-05.** Method: source, repository, and filesystem inspection plus verification against the pinned runtime dependencies (no live exploitation).
> This is a **re-assessment** superseding `SECURITY_ASSESSMENT_10-07-26.md` (2026-07-10). It re-verifies every prior finding against the current code and covers the substantial new attack surface added since: **LDAP authentication** (session + Basic Auth, with a credential cache), the **CA import overhaul** (encrypted keys, PKCS#12, chain bundles, certificate-only imports), **CA private-key export**, and a dependency upgrade.

## Scope Statement

Covers the application in its entirety: cryptographic/PKI logic (`app/services/`), authentication/authorization including the new LDAP path (`app/routes/auth.py`, `app/services/auth_service.py`, `app/services/ldap_service.py`, `app/decorators.py`, `app/models/user.py`), key/secret management (`crypto_utils.py`, `Config`, env handling), CA import/export (`app/services/ca_service.py`, `app/routes/ca.py`), the public unauthenticated interface (`app/routes/public.py`), data storage (SQLite models, on-disk permissions), the container/compose runtime, the GitHub Actions pipeline, dependencies (`requirements.txt`), and repository hygiene (`.git`). Analysis was by source/repository/filesystem inspection and verification against installed dependency source (`cryptography==50.0.0`, `ldap3==2.9.1`); no live exploitation was performed. Where a conclusion depends on deployment specifics (reverse proxy, TLS termination, host multi-tenancy), the precondition is stated inline.

**Threat model assumed:** the app is published as a public GitHub repo and public GHCR image intended for real deployment as a working CA. Adversaries: unauthenticated network clients (reach `/public/*`, `/auth/login`, Basic-Auth on every route), authenticated low-privilege users (`csr_requester`), a malicious/compromised operator (`admin`), a host-level reader (backup theft, container escape, `/proc`, co-located container), a passive/active network attacker (no TLS by default; LDAP path), and supply-chain actors (dependency, base image, CI action).

---

## Assessment Provenance, AI Assistance & Cost

This project and this assessment were produced with AI assistance from Anthropic's Claude models. The figures below are derived from the **actual Claude Code session transcripts** for this repository (`~/.claude/projects/-multimedia-projects-cert-manager/*.jsonl`, per-message `usage` records summed by model) and public per-token list pricing.

| Role | Model | Model ID | When |
|---|---|---|---|
| Original project build & first assessment | Claude Opus 4.8 | `claude-opus-4-8` | Jul 2026 (first assessment 2026-07-10). *Commit co-author trailers referenced "Claude Opus 4.6"; the transcript `model` field records `claude-opus-4-8` as the serving model.* |
| Today's feature development (LDAP auth, CA import/export, dark theme, dependency upgrade) | Claude Fable 5 | `claude-fable-5` | 2026-08-05, "max" effort |
| **This re-assessment** | Claude Fable 5 | `claude-fable-5` | 2026-08-05, "max" effort, with **4 parallel review sub-agents on Claude Opus 4.8** (`claude-opus-4-8`) |

**Token usage & cost (actual).** Pricing per 1M tokens — input / output / cache-write (5-min TTL, 1.25×) / cache-read (0.1×): `claude-fable-5` = \$10 / \$50 / \$12.50 / \$1.00 · `claude-opus-4-8` = \$5 / \$25 / \$6.25 / \$0.50.

| Phase | Model | Input | Output | Cache write | Cache read | Cost |
|---|---|--:|--:|--:|--:|--:|
| Original build + 1st assessment (Jul) | Opus 4.8 | 81,762 | 487,596 | 2,073,419 | 11,031,909 | **\$31.07** |
| Today: features + this assessment (Aug 5) | Fable 5 | 108,490 | 2,565,631 | 6,904,718 | 210,326,151 | **\$426.00** |
| Today: review sub-agents | Opus 4.8 | 30,042 | 6,930 | 55,248 | 112,254 | **\$0.72** |
| **Grand total (all Claude work on this repo)** | — | — | — | — | — | **≈ \$457.80** |

- **≈ 234 million billable tokens** total; the dominant line is cache-read (≈ 221M tokens). A long single "max"-effort session re-reads its large cached context each turn, billed at the 0.1× cache-read rate — for Fable 5 that alone is ≈ \$210 of the \$426.
- Today's \$426 covers **all** of the day's work (removing the Claude co-author trailer, dark theme, dependency upgrade, LDAP Phases 1–2, CA import overhaul, CA export, live testing, **and** this assessment). The assessment is the tail of that shared session and is not separately isolable.
- Figures are provider-list-price **estimates** for the assistance tokens; they are **not a bill** and exclude any subscription, tooling, or human-review time.

> **AI-assistance disclosure caveat.** Because both the code and its review were produced by the same model family, this assessment is **not an independent third-party audit.** For a trust-critical CA, an independent human security review and a formal audit (WebTrust/ETSI-style) remain necessary before production trust is placed in this CA.

---

## What changed since the 2026-07-10 assessment

**Improved / newly-hardened (positive):**
- **Dependencies upgraded and verified current** — every pin is the latest on PyPI (`cryptography 50.0.0`, `gunicorn 26.0.0` — well past CVE-2024-1135/6827, `Flask 3.1.3`, `SQLAlchemy 2.0.51`, `Flask-WTF 1.3.0`, `python-dotenv 1.2.2`, `ldap3 2.9.1`). Empty-string config hardening prevents an empty env var from silently disabling `LDAP_TLS_VERIFY` / crashing on `int("")`.
- **OCSP responder now mirrors the request's CertID hash algorithm** (SHA-1/224/256/384/512 with SHA-256 fallback) — fixes a real interop bug where stock `openssl ocsp` reported "no status found."
- **LDAP surface is well-built** — LDAP injection is fully defended, empty/anonymous-bind is closed, bind handling is fail-closed (verified against ldap3 2.9.1 source), TLS is verified (chain + hostname) by default, and local-first ordering means LDAP can't shadow the break-glass admin. See Positive Controls.
- **CA import is hardened** — in-bundle chain links are signature-verified, loops/disconnected certs rejected, key↔cert match enforced, `ca=True` required, 64 KB caps on all formats; issuance always forces `ca=False`.
- **Certificate-only (keyless) CA guards are complete and consistent** across issuance, CSR signing, CRL generation, sub-CA creation, OCSP (returns unsigned `UNAUTHORIZED` **without** decrypting), key/PKCS#12 export, public CRL, and the issuing/parent dropdowns.

**New attack surface (this assessment's focus):**
- **LDAP authentication** for session login and HTTP Basic Auth, with an in-memory credential cache → new findings **D6, D7, E3** and amplification of **D1/D3**.
- **CA private-key export** endpoint (`/ca/<id>/download?format=key|pkcs12`) → new finding **A7** (direct key-exfiltration channel; the export is admin-only and audited, but the key leaves in the clear).
- **CA import** of encrypted keys / PKCS#12 / chains → assessed clean apart from an unverified top-of-chain parent link (folded into A7/B-notes).

**Still unremediated from 2026-07-10:** the structural PKI and key-protection findings (A1, B1, B2, B3, C1, E1, and most Medium/Low items) were **not** addressed by this session's feature work and **persist**. See "Status of prior findings."

---

### Findings at a glance

Status legend: **NEW** (new since 2026-07-10) · **Carried** (unchanged) · **Revised** (severity/finding re-scoped) · **Resolved** (fixed).

| # | Severity | Status | Finding | Layer |
|---|---|---|---|---|
| A1 | **Critical** | Carried | All CA private keys protected by one env-var passphrase; no HSM; single point of compromise | Key Mgmt |
| A7 | **High** | NEW · partly fixed | CA private-key **export over HTTP** — secret-in-GET **fixed in v1.0.1**; unencrypted key PEM, HTTPS enforcement & dual-control residuals open | Key Mgmt |
| A2 | Medium* | Revised | App DB (encrypted keys, hashes, audit) world-readable on host (*High on a shared host); stale `instance/` DB too | Storage |
| A3 | Medium | ✅ **Resolved** | Live Forgejo password was in `.git/config` — **rotated & de-embedded 2026-08-05** | Secrets |
| A4 | Medium | Carried | Insecure defaults (`admin/admin`) in `.env.example`/compose | Secrets |
| A5 | Medium | Carried | Subscriber private-key escrow (server generates+stores+serves keys) | Key Mgmt |
| A6 | Low | ✅ **Resolved** | `venv/` was in git history — **purged 2026-08-05** (history + tags rewritten, force-pushed) | Supply chain |
| B1 | **High** | Carried | CSR proof-of-possession never verified (`is_signature_valid` absent) | PKI |
| B2 | **High** | Carried | Revocation does not propagate to published CRL (stale cache) | PKI |
| B3 | **High** | Carried | Revoked intermediate CAs never listed in parent CRL/OCSP | PKI |
| B4 | Medium | Carried | No issuance policy limits (validity, path length, name constraints) | PKI |
| B5 | Medium | Carried | Weak key sizes accepted (RSA < 2048), incl. from low-priv users | PKI |
| B6 | Low | Carried | OCSP signs with CA key directly, no nonce (replayable) | PKI |
| C1 | **High** | Carried | Unauthenticated OCSP forces CA-key decrypt (600k PBKDF2) per request → DoS; key decrypt precedes parse | API/DoS |
| C2 | Medium | Carried | No `MAX_CONTENT_LENGTH` — unbounded request bodies | API/DoS |
| C3 | Medium | Carried | Leaf PKCS#12 export password via GET; weak `changeit` default | API |
| C4 | Low-Med | Carried | Host-header injection into issued-cert OCSP/CRL URLs (default behavior) | API |
| C5 | Low-Med | Carried | Open-redirect via backslash in `next` (Werkzeug emits `/\` unencoded) | API |
| D1 | Medium | Carried | No rate limiting / lockout / MFA on login or Basic Auth | AuthN |
| D2 | Medium | Carried | Migration grants `role='admin'` to all pre-existing users | AuthZ |
| D3 | Medium | Carried | Basic Auth default-on over plaintext; failed attempts flood audit; `_burn_hash` CPU amplification | AuthN |
| D4 | Low | Carried | No multi-party authorization for CA operations (now incl. key export) | AuthZ |
| D5 | Low | Carried | Default-admin creation race; ADMIN_PASSWORD not rotated after first boot | AuthN |
| D6 | Medium | **NEW** | LDAP: configuring only the admin group grants **every** directory user a `csr_requester` account | AuthZ |
| D7 | Low | **NEW** | LDAP: credential cache masks directory-side password/disable/role changes for up to TTL | AuthN |
| D8 | Low | **NEW** | CSRF fully skipped for Basic Auth — browser-cached credentials enable CSRF | AuthN |
| E1 | **High** | Carried | No TLS in shipped stack; secure-cookie/OCSP-scheme default insecure | Transit |
| E2 | Low | Carried | Runtime CDN dependency; no CSP (SRI present); inline theme script needs nonce under CSP | Transit |
| E3 | Medium | **NEW** | LDAP: plaintext `ldap://` silently allowed; no TLS guardrail at startup | Transit |
| F1 | Medium | Carried | Key material not zeroizable; resident in memory/swap/core dumps | Runtime |
| F2 | Medium | Carried | Debug mode exposes Werkzeug debugger and bypasses insecure-default checks | Runtime |
| F3 | Low | Carried | CRL number increment race across workers | Runtime |
| G1 | Medium | Carried | Audit log not tamper-evident; no anomaly alerting | Logging |
| G2 | Low | Carried | `remote_addr` without `ProxyFix` — wrong client IP in logs/limits | Logging |
| H1 | Medium | Carried | Container runs as root; no hardening in compose | Container |
| H2 | Low-Med | Carried | Base image pinned by mutable tag; no image vuln scan | Container |
| I1 | Medium | Carried | No dependency hash/lockfile integrity pinning (transitive deps float) | Supply chain |
| I2 | Low-Med | Carried | No SCA/vulnerability scanning in CI | Supply chain |
| I3 | Low | **NEW** | `ldap3` is at latest (2.9.1) but the project is dormant (no release since 2021) | Supply chain |
| J1 | Medium | Carried | CI actions pinned by mutable tags, not commit SHAs | CI/CD |
| J2 | Medium | Carried | No image signing / provenance / SBOM | CI/CD |

Counts: **1 Critical, 8 High, 20 Medium, 12 Low/Low-Med** across 41 findings (5 new, 3 revised, 31 carried).

**Remediated since publication (2026-08-05):** **A3** (Forgejo credential rotated and de-embedded), **A6** (`venv/` purged from history + tags), and the secret-in-GET portion of **A7** (CA `key`/`pkcs12` export made POST-only, password read from the form only; shipped in **v1.0.1**). A7's remaining items (unencrypted key PEM, mandatory HTTPS, dual control) remain open. All other prior findings stand.

---

## A. Secrets & Key Management

### [CRITICAL] A1 — All CA private keys are protected only by a single environment-variable passphrase — *Carried*
Every CA (and escrowed subscriber) private key is Fernet-encrypted with a key derived by PBKDF2 (600k iters) from one process-wide `MASTER_PASSPHRASE` (`app/config.py:7`), read from an env var and resident for the process lifetime. Any actor who can read the environment (`/proc/<pid>/environ`, `docker inspect`, a crash dump, the compose `.env`) obtains the single secret that decrypts **all** CA keys. No HSM/KMS, no per-CA key wrapping, no split knowledge.
**Now compounded by A7** — a leaked *URL/log* or a compromised admin session can exfiltrate a CA key directly, without even needing the passphrase.
**Impact:** total loss of the trust anchor — forge any certificate, sign rogue sub-CAs. **Fix:** move CA key operations behind a KMS/HSM (SoftHSM/PKCS#11 → hardware); interim, per-CA HKDF-wrapped keys sourced from a secrets manager, and require passphrase re-entry for signing rather than holding it resident.

### [HIGH] A7 — CA private-key export over HTTP (NEW)
`GET|POST /ca/<id>/download?format=key|pkcs12` (`app/routes/ca.py:209-255`) is a **new** export path. It is correctly `@admin_required` and audit-logged (`download_ca_private_key` / `export_ca_pkcs12`) and refuses certificate-only CAs — but the key nonetheless leaves the trust boundary in the clear:
- **Unencrypted PKCS#8 PEM** (`export_ca_key_pem`, `ca_service.py:452-461`, `NoEncryption()`) served over the default cleartext HTTP stack (E1).
- **PKCS#12 export password read via `request.values`** (`ca.py:248`), which merges query args + form and the route allows GET — so `GET /ca/<id>/download?format=pkcs12&password=SECRET` puts the bundle password in access/proxy logs and browser history (same class as C3). *(This was introduced today and is a one-line fix: read from `request.form` and require POST.)*
- **Empty default export password** (`ca.py:248` default `""`) — an admin omitting the field exports the CA key in a bundle with no protection.
- **GET-reachable key export** (`ca.py:209` `methods=["GET","POST"]`) → CA-key PEM URL captured in history/logs/`Referer`.

**Who/impact:** a compromised admin session, a shoulder-surfed URL, or a proxy access log now yields CA private keys directly — a materially larger blast radius than A1's DB+passphrase path, and it defeats the "keys never leave the app" assumption. Combined with D4 (single admin, no dual control) one actor suffices. **Fix:** require POST and read the password only from the form; require a strong non-empty PKCS#12 password; never emit unencrypted key PEM (encrypt exports, or gate behind step-up re-auth + dual control); mandate HTTPS for these routes.

### [MEDIUM] A2 — Application database is world-readable on the host — *Revised (was High)*
`data/cert-manager.db` is mode `0644` (root); a stale `instance/cert-manager.db` (Feb, not gitignored) is also `0644`. These hold the Fernet-encrypted CA keys, password hashes, and audit log. Any local user or co-located container reading the path can copy them (feeds A1). **Revised to Medium** because it is purely a local filesystem-permissions issue on what appears to be a single-operator host with non-default secrets; **it rises to High on any shared/multi-tenant host.** **Fix:** `chmod 600` DB + `.env`; own by a non-root service UID; `chmod 700 data/`; delete the stale `instance/` DB and gitignore `instance/`; encrypt backups.

### [MEDIUM] A3 — Forgejo credential in `.git/config` — ✅ *Resolved 2026-08-05*
`.git/config` is per-clone local metadata (regenerated on every clone), so the embedded Forgejo password was a **local-disk exposure only — never distributed in a clone** and never in git history. **Resolved:** the account password was rotated (old value confirmed dead), the credential de-embedded from the remote URL and moved to a mode-`600` `credential.helper store`; the same de-embedding was applied to the other local repos that reused it (`CatDetection`, `CatDetection-backup`, `Felisight`), and a sweep confirms none remain. *Operational follow-up: record the new password in a password manager, and check any n8n/automation that used the account password (webhooks use a URL/secret and are unaffected).*

### [MEDIUM] A4 — Insecure default secrets in code and `.env.example` — *Carried*
`.env.example` ships `ADMIN_USERNAME=admin`/`ADMIN_PASSWORD=admin`; `docker-compose.yml:15` uses `${ADMIN_PASSWORD:-admin}` (unlike `SECRET_KEY`/`MASTER_PASSPHRASE`, which fail-closed with `:?`). The `_check_security` guard rejects the three exact insecure defaults (good) but only exact-string-matches (a weak-but-different passphrase passes) and is bypassed in debug (F2). A predictable `SECRET_KEY` enables session forgery. **Fix:** remove real-looking defaults; require secrets with no fallback; enforce a minimum-entropy check rather than exact denylist; use `${ADMIN_PASSWORD:?...}`. *(Positive: the new LDAP config defaults are safe — `LDAP_TLS_VERIFY` defaults true, and empty-env hardening prevents silent disablement.)*

### [MEDIUM] A5 — Subscriber private-key escrow — *Carried*
Server-side certificate generation stores the subscriber key (`Certificate.private_key_enc`) and serves it via `/certificates/<id>/download-key` (admin) or PKCS#12. Concentrates risk and breaks non-repudiation. CSR-generated keys are correctly shown once and not stored. **Fix:** prefer CSR-based issuance; if server-side generation is offered, deliver once and do not persist (mirror the CSR flow), or make escrow opt-in with a destruction policy.

### [LOW] A6 — `venv/` in git history — ✅ *Resolved 2026-08-05*
The initial commit added `venv/` (~70 MB / 3,839 blobs); it was gitignored in the working tree but remained in history, so — unlike A3 — it **was** distributed to anyone cloning the repo. No secret was in it (`.env` was never committed), so the impact was clone bloat and a pinned old-dependency snapshot rather than an exploitable vuln. **Resolved:** history was rewritten (`filter-branch`, all commits + the `v1.0.0`/`v1.0.1` tags) to drop `venv/` and force-pushed to GitHub and Forgejo; all non-`venv` blobs verified byte-identical and the commit graph preserved (77 commits). A fresh clone now carries **0 `venv` objects** and a `.git` of ~0.5 MB (was ~52 MB); the GitHub releases survived the tag rewrite.

---

## B. Cryptographic Implementation & PKI Correctness

### [HIGH] B1 — CSR proof-of-possession is never verified — *Carried*
`x509.load_pem_x509_csr()` parses but does not verify the CSR self-signature; `csr.is_signature_valid` appears nowhere (`cert_service.sign_csr` `:80`; `csr_service.import_csr/parse_csr`). A `csr_requester` can upload a CSR embedding a third party's public key with a bogus signature and the CA signs it. **Fix:** reject `not csr.is_signature_valid` at import and signing; enforce key-strength (B5) at the same point.

### [HIGH] B2 — Revocation does not propagate to the published CRL — *Carried*
`revoke_certificate` (`crl_service.py:26-37`) and `revoke_ca` (`:40-74`) flip DB flags but never regenerate or clear the cached `ca.crl_pem`; `get_crl_pem/der` (`:129-141`) serve the cached CRL unconditionally when present, **even after its `next_update` expires**. Revocation reaches CRL consumers only when an admin manually POSTs `/ca/<id>/crl`. **Fix:** regenerate (or null) the issuing CA's `crl_pem` on every revocation; in `get_crl_*` regenerate when the cached `next_update` has passed.

### [HIGH] B3 — Revoked intermediate CAs never appear in the parent CRL/OCSP — *Carried*
`generate_crl` enumerates only `Certificate` rows (`crl_service.py:105`) and OCSP looks up only the `Certificate` table (`ocsp_service.py:63-65`); sub-CA certificates live in `certificate_authorities`, so a revoked intermediate's serial is never emitted on the parent CRL nor answered `REVOKED` by OCSP (returns `UNAUTHORIZED`). This defeats revocation in the exact case — CA compromise — where it matters most (arguably Critical for a CA product). **Fix:** include revoked child-CA serials in the issuing CA's CRL and answer OCSP for them; regenerate the parent CRL on sub-CA revocation.

### [MEDIUM] B4 — No issuance policy limits — *Carried*
`validity_days` is uncapped (TLS certs can exceed 398 days; a cert can outlive its issuer), intermediates are created with `path_length=None` (unlimited chaining) and no `NameConstraints`, and any `csr_requester` may request any CN/SAN. **Fix:** cap validity per profile, reject `not_after > CA.not_after`, default `path_length=0` for issuing CAs, support Name Constraints, and validate the profile server-side.

### [MEDIUM] B5 — Weak key sizes accepted — *Carried*
`key_size` is parsed from the form with no minimum; RSA < 2048 is accepted (`_generate_key`), and CSR-supplied keys are not strength-checked. **Fix:** enforce RSA ≥ 2048 (prefer 3072/4096 for CAs) and EC P-256/384/521 only, server-side.

### [LOW] B6 — OCSP signs with the CA key directly and omits nonces — *Carried (partially mitigated)*
Responses are signed by the CA key on every request (no delegated `id-kp-OCSPSigning` responder) and the request nonce (RFC 8954) is not echoed → replayable. *Mitigation added this session:* the responder now mirrors the request's CertID hash algorithm (interop fix) and keyless CAs answer `UNAUTHORIZED` without decrypting — but the nonce and delegated-responder gaps remain. **Fix:** issue a delegated OCSP-signing certificate; echo the nonce; keep short `next_update`.

---

## C. API & Interface Security / Denial of Service

### [HIGH] C1 — Unauthenticated OCSP forces CA-key decryption per request → DoS — *Carried*
`POST /public/ocsp/<ca_id>` is unauthenticated and `@csrf.exempt`. `build_ocsp_response` calls `decrypt_private_key` (600k PBKDF2 + Fernet) at `ocsp_service.py:56` — **before** parsing the request (`:58`) and **before** the cert lookup (`:63`) — with no decrypted-key caching and rate limiting off by default. A flood of empty/garbage POSTs trivially exhausts CPU on the 2 gunicorn workers. Compounded by C2 (no body cap). *(Keyless-CA OCSP now short-circuits without decrypting — but keyed CAs, the norm, still decrypt.)* **Fix:** parse + look up before decrypting; cache the decrypted key/signing context with a TTL (or use a KMS); enable rate limiting on `/public/*` with a shared backend; set `MAX_CONTENT_LENGTH`; pre-generate CRLs so public GETs never trigger key decryption or DB writes.

### [MEDIUM] C2 — No global request-size limit — *Carried*
`MAX_CONTENT_LENGTH` is unset; the OCSP endpoint `request.get_data()` buffers an arbitrarily large body before parsing, and import handlers `read()` files before the 64 KB check. **Fix:** set a conservative app-wide `MAX_CONTENT_LENGTH` (e.g. 256 KB–1 MB) and a tighter cap on the OCSP body.

### [MEDIUM] C3 — Leaf PKCS#12 export password via GET; weak default — *Carried*
`certificates.download` reads `request.args.get("password", "changeit")` (`certificates.py:242`) — password in the URL (logs/history/`Referer`) and a well-known weak default. *(The new CA-export instance of this is folded into A7.)* **Fix:** accept the export password via POST only, require it (no default), enforce minimum length.

### [LOW-MEDIUM] C4 — Host-header injection into issued-certificate OCSP/CRL URLs — *Carried*
When `SERVER_NAME_FOR_OCSP` is at its default `localhost:5000` (the **default** compose value), the OCSP AIA URL baked into every issued cert is built from `request.host` (`certificates.py:52-54,95`; `csr.py:134-136,163`), which is attacker-controllable; there is no Flask `SERVER_NAME` / host allowlist. **Fix:** require an explicit `SERVER_NAME_FOR_OCSP` in production (never derive from `request.host`); set Flask `SERVER_NAME` / a trusted-host allowlist; have the proxy enforce a canonical Host.

### [LOW-MEDIUM] C5 — Open-redirect via backslash in `next` — *Carried (confirmed exploitable)*
`_is_safe_url` (`auth.py:9-14`) allows any `startswith("/")` that is not `//`, but does not handle `\`. Confirmed: Werkzeug 3.1.6 emits `Location: /\evil.com` **unencoded**, which browsers normalize to `//evil.com` → off-site redirect after login. **Fix:** parse with `urlsplit`, require empty scheme **and** netloc, reject `\` and control chars (or use `url_has_allowed_host_and_scheme`).

---

## D. Authentication & Authorization

### [MEDIUM] D1 — No rate limiting, lockout, or MFA — *Carried (amplified by LDAP)*
Login and Basic Auth have no throttle/lockout; rate limiting is off by default and, when enabled, uses per-worker `memory://`. The credential cache stores only **successful** auths, so every failed guess takes the full path — and with LDAP enabled, each Basic-Auth failure drives a **fresh directory bind** (online guessing + potential directory-side account-lockout DoS). **Fix:** enable rate limiting by default with a shared backend, stricter on `/auth/login` and Basic-Auth; per-account failed-attempt throttling before hitting LDAP; admin MFA; a password policy.

### [MEDIUM] D2 — Migration escalates all pre-existing users to admin — *Carried*
`_migrate_schema` runs `ADD COLUMN role ... DEFAULT 'admin'` (`app/__init__.py:240-242`), contradicting the model default `csr_requester`. Any legacy account becomes admin on upgrade, unaudited. *(Real-world impact is limited — pre-role installs only had admins — but it violates fail-safe defaults.)* The new `auth_source DEFAULT 'local'` migration is correct. **Fix:** default the added column to `csr_requester` and promote the known bootstrap admin explicitly; log migration-time assignments.

### [MEDIUM] D3 — Basic Auth default-on over plaintext; audit flooding; hash amplification — *Carried*
`BASIC_AUTH_ENABLED` defaults true; with no TLS (E1) Base64 creds go in the clear. `check_basic_auth` runs on **every** request; each failed attempt writes+commits a `basic_auth_failed` audit row and runs an expensive scrypt hash (`check_password`/`_burn_hash` → `generate_password_hash`). An unauthenticated attacker can flood the audit table and burn CPU with a trivial `Authorization: Basic dXNlcjo=` stream. **Fix:** refuse Basic Auth without HTTPS; rate-limit and coalesce repeated failures; cap/sample failed-auth audit writes; compare against a single precomputed dummy hash instead of generating one per request.

### [LOW] D4 — No multi-party authorization for CA operations — *Carried (more relevant post-A7)*
Any single admin can create/revoke CAs, sign CSRs, and now **export CA private keys** (A7) with no dual control. One compromised admin account is catastrophic. **Fix:** role separation + m-of-n approval for CA key generation, sub-CA issuance, revocation, and key export; per-operation step-up re-auth.

### [LOW] D5 — Default-admin creation race; non-rotating admin password — *Carried*
`_create_default_admin` does check-then-insert per worker (race on the unique username), and `ADMIN_PASSWORD` seeds only first boot. **Fix:** seed once in the entrypoint guarded by the unique constraint; document rotation.

### [MEDIUM] D6 — LDAP admin-group-only config grants every directory user access (NEW)
In `_map_role` (`auth_service.py:107-111`), the **requester** group is the only required-membership gate. If an admin sets `LDAP_ADMIN_GROUP_DN` but leaves `LDAP_REQUESTER_GROUP_DN` empty — a natural "grant admins only" configuration — a directory user in **neither** group falls through to `return "csr_requester"`, so **anyone who can bind to the directory** is auto-provisioned a CSR-requester account on the CA app. **Fix:** treat *any* configured group DN as enabling required membership (deny users matching no mapped group when at least one group is configured); document loudly that "no groups configured = open to all directory users."

### [LOW] D7 — LDAP credential cache masks directory-side changes for up to TTL (NEW)
A Basic-Auth cache hit skips the LDAP bind **and** `_sync_role`; the freshness check re-reads only the local `User` row (`authenticate_basic:229`). So **local** deactivation/deletion/role edits apply immediately (correct), but a **directory-side** password change, disable, or admin-group removal keeps working at the cached DB role for up to `BASIC_AUTH_CACHE_TTL_SECONDS` (default 60). The docstring's "deactivation, role changes … apply immediately" is only true for local-DB changes. **Fix:** correct the docstring; consider not caching admin-role/LDAP entries, or a shorter TTL.

### [LOW] D8 — CSRF fully skipped for Basic Auth incl. browser-cached credentials (NEW)
`ConditionalCSRFProtect.protect` returns early when `g.basic_auth_used` (`extensions.py:18-21`). Correct for curl/scripts, but browsers cache Basic-Auth credentials per-origin and auto-attach them to cross-site state-changing POSTs, setting `basic_auth_used=True` and disabling CSRF for that request. *(Ordering verified correct; session-cookie requests still get CSRF, and `SameSite=Lax` covers the cookie path.)* **Fix:** document that Basic Auth is for non-browser clients only; optionally gate the exemption on a non-browser signal (require a custom header, or exempt only cookie-less requests).

---

## E. Data in Transit

### [HIGH] E1 — No TLS in the shipped stack; secure-transport defaults insecure — *Carried*
Gunicorn binds plain HTTP `0.0.0.0:5000`; compose publishes `5000:5000` with no TLS terminator. `SESSION_COOKIE_SECURE` defaults false and `OCSP_URL_SCHEME` defaults `http`. As delivered, session cookies, Basic-Auth credentials, imported/exported private keys (A7), and LDAP-derived sessions traverse the network unencrypted. **Fix:** ship/require a TLS-terminating proxy; default `SESSION_COOKIE_SECURE=true` and `OCSP_URL_SCHEME=https` for production; add HSTS; refuse Basic Auth (and key export) without HTTPS.

### [LOW] E2 — Runtime CDN dependency; no CSP — *Carried*
Only `X-Content-Type-Options`/`X-Frame-Options` are set; no CSP/HSTS/Referrer-Policy. SRI on the Bootstrap CDN is correctly present. Note: the new dark-theme inline `<script>` blocks (`base.html`) would require a nonce/hash (not `'unsafe-inline'`) if a strict CSP is added. **Fix:** add CSP/HSTS/Referrer-Policy; self-host Bootstrap; nonce the inline theme scripts.

### [MEDIUM] E3 — LDAP plaintext silently allowed; no startup TLS guardrail (NEW)
`_build_server` only wraps TLS/StartTLS when the URI is `ldaps://` or `LDAP_USE_STARTTLS` is true (`ldap_service.py:80-87`). With the defaults (`LDAP_USE_STARTTLS=false`) and a plain `ldap://` URI, every end-user bind and the `LDAP_BIND_PASSWORD` service bind transit in cleartext; `_validate_ldap_config` never checks transport encryption, so the app boots into plaintext auth. **Fix:** refuse to boot (or require an explicit `LDAP_ALLOW_PLAINTEXT=true` opt-in) when `LDAP_ENABLED`, the URI is `ldap://`, and StartTLS is off. *(Positive: when TLS **is** used, it verifies chain + hostname by default — see Positive Controls.)*

---

## F. Runtime Security

### [MEDIUM] F1 — Key material not zeroizable; memory-resident — *Carried*
Decrypted keys and the passphrase are ordinary Python objects (immutable `bytes`/`str`), not wiped after use; they can persist in memory, swap, and core dumps. **Fix:** minimize key lifetime; disable swap/core dumps for the process; prefer an HSM/KMS so plaintext keys never enter the app (A1).

### [MEDIUM] F2 — Debug mode exposes the Werkzeug debugger and bypasses the insecure-default guard — *Carried*
`_check_security` returns early under `app.debug` (`app/__init__.py:137`); as shipped (gunicorn, no `FLASK_DEBUG`) the checks run — but running with `--debug`/`FLASK_DEBUG=1` in production both disables insecure-default rejection and exposes the PIN-guarded Werkzeug console (RCE). **Fix:** never enable debug in production; keep the guard active regardless of debug; document prominently.

### [LOW] F3 — Non-atomic CRL number increment — *Carried*
`ca.crl_number += 1` then commit is not atomic across the 2 workers; concurrent CRL generation can duplicate/skip a CRL number. **Fix:** use an atomic DB update / row lock, or serialize CRL generation.

---

## G. Logging, Monitoring & Audit Integrity

### [MEDIUM] G1 — Audit log not tamper-evident; no anomaly alerting — *Carried*
`audit_logs` rows are plain, mutable SQLite; anyone with DB/app write access can alter history, and there is no external retention or alerting on high-risk actions (key export, CA revoke, role change). **Fix:** hash-chain or sign entries; ship to an external append-only store; alert on high-risk actions.

### [LOW] G2 — `remote_addr` without `ProxyFix` — *Carried*
`audit_service` uses `request.remote_addr` and the limiter keys on `get_remote_address`, with no `ProxyFix`. Behind the (required, E1) reverse proxy, every audit entry records the proxy IP and rate limiting buckets all clients together. **Fix:** wrap with `ProxyFix` configured for the exact trusted hop count (do not trust XFF blindly).

---

## H. Container & Infrastructure

### [MEDIUM] H1 — Container runs as root; no hardening — *Carried*
No `USER` in the Dockerfile (gunicorn runs as uid 0); compose has no `read_only`, `cap_drop`, `security_opt: no-new-privileges`, or `user:`. **Fix:** add a non-root `USER` (own `/app/data`), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, read-only rootfs, resource limits, a healthcheck.

### [LOW-MEDIUM] H2 — Base image pinned by mutable tag; no image scanning — *Carried*
`FROM python:3.13-slim` (mutable tag); no Trivy/Grype scan. **Fix:** pin `python:3.13-slim@sha256:...` and update via Dependabot; add an image-vuln scan.

---

## I. Dependency & Supply Chain

### [MEDIUM] I1 — No dependency integrity pinning — *Carried*
Top-level versions use `==` (and are all current-latest — see Positives), but there are no artifact hashes and no lockfile; transitive deps float (`werkzeug`, `jinja2`, `pyasn1` via `ldap3`, etc.). **Fix:** generate a hashed lock (`pip-compile --generate-hashes` / `uv pip compile`) and build with `--require-hashes`.

### [LOW-MEDIUM] I2 — No SCA/vulnerability scanning in CI — *Carried*
The workflow builds/pushes with no `pip-audit`/OSV/Trivy gate. **Fix:** add `pip-audit`/OSV-Scanner + Trivy; fail on high/critical; schedule periodic re-scans.

### [LOW] I3 — `ldap3` is at latest but dormant (NEW)
`ldap3==2.9.1` is genuinely the newest published release, so it is not "outdated" — but the project has shipped nothing since 2021 and will not receive security patches. Usage is otherwise well-hardened. **Fix:** accept with awareness; monitor for a maintained fork; keep `pyasn1` on a known-good pin.

---

## J. CI/CD Pipeline

### [MEDIUM] J1 — GitHub Actions pinned by mutable tags — *Carried*
`actions/checkout@v4`, `docker/*-action@v3/v5/v6` are mutable major tags on a job holding `packages: write`. A tag re-point can exfiltrate `GITHUB_TOKEN` or poison the published image. *(Permissions are correctly scoped `contents: read`/`packages: write`, and PR builds skip login/push — good.)* **Fix:** pin every action to a full commit SHA; update via Dependabot.

### [MEDIUM] J2 — No image signing, provenance, or SBOM — *Carried*
Published GHCR images are not cosign-signed, carry no SLSA provenance, and no SBOM. **Fix:** cosign keyless signing, `provenance: true` + `sbom: true` on build-push-action; document verification; avoid trusting mutable `:latest` in production.

---

## K. Error Handling & Information Disclosure — *Carried (positive)*
Routes consistently catch broad `Exception`, log full traces server-side (`logger.exception`), and return generic client messages; public CRL/OCSP return generic 500s (and now a clean 404 for keyless-CA CRLs — added this session). No SQL injection (parameterized ORM; the only raw SQL is static DDL in `_migrate_schema`), no `subprocess`/`os.system`, no `pickle`/`yaml.load`, Jinja autoescaping on with no `|safe` sinks. The OCSP hash-algorithm handling uses an allowlist (no oracle). Residual risk is tied to F2 (debug). Keep debug off in production and ensure logs never capture request bodies containing private keys (relevant to A7/import).

---

## L. Compliance Gaps (Consolidated) — *Carried, + LDAP transport*

| Standard | Gap | Findings |
|---|---|---|
| CA/B BR §6.2 / NIST SP 800-57 Pt.2 | No HSM/FIPS key protection; env-var passphrase; no offline root/key ceremony/split knowledge; **key export in the clear** | A1, A7, D4, F1 |
| CA/B BR §4.9 / RFC 5280 §5 | Revocation not reliably published (stale CRL; sub-CAs absent from CRL/OCSP); OCSP replay/no nonce | B2, B3, B6 |
| RFC 2986 / RFC 4211 | Proof-of-possession not enforced on CSR signing | B1 |
| CA/B BR §6.3.2 / §7.1 | Validity uncapped; no Name Constraints; unlimited path length | B4 |
| CA/B BR §6.1.5 | Weak key sizes accepted | B5 |
| CA/B BR §5 / WebTrust | No separation of duties / multi-person control; audit log not tamper-evident | D4, G1 |
| Transport | No TLS in shipped stack; LDAP plaintext allowed | E1, E3 |

---

## Positive Controls Observed

Real security investment; preserve and build on these:

- **Cryptography-at-rest:** 600k-iteration PBKDF2-HMAC-SHA256 with per-encryption random salt; Fernet (AES-128-CBC + HMAC-SHA256).
- **Correct X.509 construction:** 160-bit random serials, SHA-256 signatures, correct `BasicConstraints`/`KeyUsage` for leaf (`ca=False`, no `key_cert_sign`) vs CA; issuance **always forces `ca=False`** so a CSR requesting `CA:TRUE` cannot obtain a CA cert.
- **CA import hardening (NEW surface, verified clean):** in-bundle chain links signature-verified (`verify_directly_issued_by`), loops/disconnected certs rejected, key↔cert public-key match enforced, `ca=True` required, 64 KB caps on PEM/key/PKCS#12.
- **Certificate-only (keyless) CA guards are complete and consistent** across issuance, CSR signing, CRL generation, sub-CA creation, OCSP (unsigned `UNAUTHORIZED` **without** decrypting), key/PKCS#12 export, public CRL, and issuing/parent dropdowns (`signing_capable()`).
- **LDAP surface (NEW, verified against ldap3 2.9.1 source):** username fully escaped in both DN (`escape_rdn`) and filter (`escape_filter_chars`) — no raw-username path reaches a bind/filter; empty/whitespace password rejected before any bind (anonymous-bind closed, test-covered); bind handling fail-closed (`auto_bind` raises on `bound=False`, `auto_referrals=False`, `read_only=True`, `get_info=NONE`); ambiguous multi-match searches rejected; **TLS verified (chain + hostname) by default** on both `ldaps://` and StartTLS paths; **local-first ordering** so LDAP cannot shadow the break-glass admin; unusable-password sentinel `"!"` can never authenticate.
- **CredentialCache design:** per-process `os.urandom(32)` HMAC key, `hmac.compare_digest`, plaintext password never stored, wrong-password miss does not evict a valid entry (anti-poisoning), TTL/eviction enforced, every hit re-reads the `User` row and re-checks username + `is_active` (local deactivation/rename/deletion apply immediately; guards against id reuse).
- **AuthZ:** RBAC with ownership enforcement (`csr_requester` sees only its own CSRs/certs; `requested_by` propagates on CSR signing — **no IDOR**), private-key download admin-only, all CA/user routes `@admin_required`, last-admin/self-deactivation guards; the new CA export is admin-only, audit-logged, and filename-sanitized.
- **Web hygiene:** CSRF (deliberate, documented Basic-Auth bypass — see D8), login timing-attack mitigation (`_burn_hash`), username-in-log sanitization, `X-Content-Type-Options`/`X-Frame-Options`, SRI on CDN assets, `Content-Disposition` CR/LF/quote sanitization on every download, parameterized ORM (no SQLi), autoescaped templates.
- **Dependency currency (NEW this session):** every pin verified as the current PyPI latest, past the known gunicorn/cryptography CVEs; empty-env config hardening prevents silent disablement of `LDAP_TLS_VERIFY`.

---

## Executive Risk Summary

Since the 2026-07-10 review the project has **added capability faster than it has closed its structural risks.** The new LDAP authentication and CA import paths are, to their credit, carefully built — LDAP injection is fully defended and fail-closed, and CA import verifies chains and forces `ca=False` — so they introduce no new Critical/High auth-bypass or mis-issuance primitive. The dependency upgrade genuinely removed a stale-dependency gap. But the crown-jewel weaknesses are unchanged: every CA key is still guarded by a single environment-variable passphrase co-located with a world-readable database (A1/A2), the CA still signs CSRs without proof-of-possession (B1) and fails to publish revocation to CRLs for both certificates and intermediate CAs (B2/B3), the unauthenticated OCSP endpoint still amplifies the deliberately-slow KDF into a trivial denial-of-service (C1), and the shipped stack still terminates no TLS (E1). On top of that unresolved base, this session added a **direct CA private-key export channel** (A7): the key now leaves the trust boundary as an unencrypted PEM over cleartext HTTP, with a PKCS#12 password that can land in a query-string log and an empty default — a materially larger blast radius that a single compromised admin (D4) can trigger, recorded only in a mutable audit log (G1). LDAP adds three configuration footguns (an admin-group-only policy silently admits the whole directory, a 60-second credential-cache window over directory-side revocation, and plaintext binds allowed at startup) that are Medium individually but compound the authentication weaknesses. The net posture: the newest code is the strongest, but it sits on a foundation whose key-protection, revocation, DoS, and transport gaps still provide a credible path from a modest foothold to full trust-anchor compromise.

## Prioritized Remediation Roadmap

**Immediate (0–2 weeks) — critical/blocking**
- **A7:** require POST for CA key/PKCS#12 export and read the password only from the form (one-line fix for the `request.values` leak); require a strong non-empty PKCS#12 password; stop emitting unencrypted key PEM (encrypt, or gate behind step-up re-auth + dual control); mandate HTTPS for these routes.
- ~~**A3:** rotate the Forgejo password and remove it from `.git/config` (credential helper / SSH).~~ ✅ **Done 2026-08-05.**
- **A2:** `chmod 600` the DB and `.env`, own by a non-root UID, delete the stale `instance/` DB.
- **C1/C2:** parse+lookup before decrypting in OCSP, cache the decrypted key, set `MAX_CONTENT_LENGTH`, enable rate limiting on `/public/*` (shared backend), pre-generate CRLs.
- **B1/B5:** enforce CSR proof-of-possession (`is_signature_valid`) and a key-size floor at signing/creation.
- **B2/B3:** regenerate/invalidate CRLs on cert **and** sub-CA revocation and include revoked sub-CAs in the parent CRL/OCSP.
- **E1/E3/D3:** require TLS; flip secure defaults (`SESSION_COOKIE_SECURE`, `OCSP_URL_SCHEME=https`); refuse Basic Auth and LDAP plaintext without transport encryption.
- **A4/F2:** remove `admin:admin` from examples/compose (`:?` fail-closed), enforce a minimum-entropy check, keep the guard active in debug.

**Short-term (1–3 months) — high severity & foundational hardening**
- **D6:** make any configured LDAP group DN a required-membership gate; document the open-to-all default.
- **D2:** default the migrated `role` column to least privilege; audit current assignments.
- **D1/D8/D7:** rate limiting + lockout by default (shared backend), admin MFA, a password policy; scope the Basic-Auth CSRF exemption to non-browser clients; correct the credential-cache docstring and shorten/segment its TTL.
- **H1/G2:** run the container non-root with `cap_drop`/`no-new-privileges`/read-only rootfs + resource limits; add `ProxyFix`.
- **A7/C3/C5/C4/E2:** POST-only key/P12 exports with strong passwords; harden `_is_safe_url` (backslash); pin `SERVER_NAME_FOR_OCSP`; add CSP/HSTS and self-host Bootstrap (nonce the theme scripts).
- **B4:** enforce issuance-profile limits server-side (max validity, `not_after ≤ CA.not_after`, path length, Name Constraints); stop escrowing subscriber keys by default (A5).

**Medium-term (3–6 months) — systematic improvements & tooling**
- **A1/F1:** KMS/HSM-backed CA key operations (SoftHSM/PKCS#11 → hardware), or per-CA HKDF-wrapped keys from a secrets manager.
- **G1:** tamper-evident, externally-retained audit logging with anomaly alerting on high-risk actions (key export, CA revoke, role change).
- **I1/I2/I3/H2/J1/J2:** hash-locked dependencies (`--require-hashes`), digest-pinned base image, SHA-pinned CI actions, Trivy/pip-audit gates, cosign signing + SLSA provenance + SBOM; track the dormant `ldap3`.
- **B6:** delegated OCSP-signing certificate with nonce support.

**Long-term (ongoing) — continuous practices & compliance**
- Offline-root / online-issuing-intermediate architecture with a documented key ceremony, split knowledge, and DR; separation of duties and dual control for CA key generation, sub-CA issuance, revocation, and **key export** (D4, A7, L).
- Formalize a Certificate Policy/CPS aligned to CA/Browser Forum BRs, RFC 5280, and NIST SP 800-57; schedule dependency/image re-scans, key-rotation and revocation drills, and audit-log reviews.
- **Obtain an independent human security review** (this assessment was AI-produced by the same model family that wrote the code — see Provenance).

---

*Live-secret status: the Forgejo password was **rotated and de-embedded on 2026-08-05** (A3 resolved). The values in `.env` should still be rotated if they have ever been exposed. A7's PKCS#12-password-via-`request.values` issue was fixed in **v1.0.1**.*
