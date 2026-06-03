# Odysseus — Security Risk Assessment

**Date:** 2026-06-03
**Scope:** Full codebase review (auth, agent tool execution, SSRF/egress, secrets/vault, prompt-injection defenses, deployment posture).
**Context:** Single-user, self-hosted on a personal machine (macOS), goal = "as secure as possible."
**Reviewers:** Multi-agent source review; every Critical/High finding below was re-verified by reading the cited code directly.

> This document is for planning. It is meant to be handed to a planning assistant (claude.ai) to turn into a prioritized work plan. Each finding has a stable ID, a location, an exploit path, and a concrete fix.

---

## 1. Overall posture

**Grade: B / "above-average for a self-hosted AI app, with a few sharp edges."**

The project takes security seriously and it shows: bcrypt + 256-bit session tokens, real TOTP 2FA, a proxy-aware loopback-trust check, Fernet encryption-at-rest for mail credentials, a genuine (not theater) CSP nonce pipeline, a fixpoint DOM-XSS sanitizer, vault passwords kept off `argv`, SSRF-hardened web-fetch, and a fail-closed non-admin tool gate. The `THREAT_MODEL.md` is honest about what it does and does not defend.

The weaknesses cluster in three places:

1. **The one threat the model promises to defend — prompt injection — has an exploitable path to full, persistent account takeover** (read the session-token file via the agent's own file tool). This is the most important issue in this document.
2. **A real SSRF (`/v1/chat` `base_url`) is documented as fixed but is not.**
3. **Local file permissions and a few deployment defaults leak secrets to other local users / the LAN.**

### Trust-model note (important for severity)
The project **intentionally** treats a logged-in admin as having shell/file/RCE access ("treat it like an admin console"). So "admin can run bash" is *not* a vulnerability here. Severities below are judged against what the project *does* try to stop: **unauthenticated access, non-admin → admin escalation, prompt-injection acting on untrusted content, and internal services leaking.** Findings that break those promises are rated high even if they "only" require prompt injection, because stopping prompt injection is the stated goal.

---

## 2. Severity legend

| Level | Meaning |
|---|---|
| **Critical** | Breaks a core security promise; realistic path to full compromise. Fix first. |
| **High** | Serious; exploitable under conditions the user will plausibly hit. |
| **Medium** | Real weakness; needs a precondition or has bounded blast radius. |
| **Low / Info** | Hardening, defense-in-depth, or accepted-risk documentation. |

---

## 3. Findings

### CRITICAL

#### C1 — Prompt injection → agent file tool reads `data/auth.json` → session-token theft / persistent takeover
- **Where:** `src/tool_execution.py:84-85` (`_tool_path_roots` adds `DATA_DIR` to the read/write allowlist) + `src/tool_execution.py:42-48` (`_SENSITIVE_BASENAMES` does **not** list `auth.json`/`sessions.json`) + `core/auth.py` (auth.json holds bcrypt hash, **live session tokens**, TOTP secret, plaintext backup codes).
- **What/why:** `read_file`/`write_file` are admin-only, but **the path argument is model-controlled** (the file header at `tool_execution.py:28-33` says so). The agent's writable/readable root includes the entire `data/` directory, which contains the app's own credential store. A prompt injection delivered through untrusted content (a web page, an email the agent reads, a saved memory) can instruct the agent to `read_file data/auth.json` and exfiltrate a valid session token → instant account takeover with **no password and no 2FA**, or `write_file data/auth.json` to overwrite the admin password hash. This turns "injection runs inside one chat turn" into "persistent full-account compromise," which is exactly the blast radius the threat model claims to contain.
- **Fix:** Carve the app's state out of the tool roots. Either confine the file tools to a dedicated `data/agent_workspace/` instead of all of `data/`, or add an explicit deny in `_is_sensitive_path` for any resolved path under `DATA_DIR` matching `{auth.json, sessions.json, settings.json, vault*, *.db, tokens*, .app_key}`.
- **Effort:** Low.

#### C2 — `POST /v1/chat` `base_url` SSRF is unfixed (THREAT_MODEL gap #2 claims it is)
- **Where:** `routes/webhook_routes.py:234-373` (`base_url` taken from request body at `:282`, passed to `build_chat_url` at `:291`, fetched via `llm_call_async` at `:362`). `check_outbound_url` is **never** called on this path — confirmed it appears only in `url_safety.py`, `embedding_routes.py`, `gallery_routes.py`.
- **What/why:** Any holder of a `chat`-scoped API token (which per THREAT_MODEL gap #4 includes paired mobile/companion tokens) can supply an arbitrary `base_url` and make the server issue an outbound request to it, with the response returned to the caller. Reachable targets: `http://169.254.169.254/...` (cloud metadata — less relevant on a laptop but relevant if ever cloud-hosted), and **localhost/LAN services** (ChromaDB `:8100`, Ollama `:11434`, SearXNG `:8080`, the app's own admin API). Read-SSRF with exfiltration.
- **Aggravator:** `src/endpoint_resolver.py:117-130` (`resolve_url`) can *rewrite* the host to a Tailscale peer IP (`100.64.0.0/10`) **after** any validation, so a check at the route is a TOCTOU unless the guard sits at the actual `httpx` call.
- **Fix:** Add `check_outbound_url(base_url, block_private=True)` to the `/v1/chat` handler before `build_chat_url`, **and** add it as a chokepoint inside `llm_call`/`llm_call_async` (`src/llm_core.py`) on the final resolved URL so every base_url feature inherits it and the Tailscale rewrite is covered. Also correct the false "PR #1039 fixes this" line in `THREAT_MODEL.md:77`.
- **Effort:** Low–Medium.

---

### HIGH

#### H1 — Secret files written world-readable (`0644`)
- **Where (verified on disk):** `data/auth.json`, `data/app.db`, `data/sessions.json`, `.env` are all `-rw-r--r--`. Code: `core/atomic_io.py:atomic_write_json` never `chmod`s; `setup.py:111-112` writes auth.json with plain `open`; `core/database.py:31` lets SQLite create the DB at default umask. (Note: `src/secret_storage.py:44` *does* chmod `.app_key` to `0600` — so this is an inconsistency, not a deliberate choice.)
- **What/why:** Any other local user on the machine can read the admin bcrypt hash, the **live TOTP secret + plaintext backup codes** (fully defeats 2FA), all session tokens, and the entire chat history / personal docs (the DB body is *not* encrypted — only mail-credential columns are). On a single-user Mac with FileVault the practical risk is lower, but it's a one-line-each fix.
- **Fix:** `chmod 600` auth.json/sessions.json/app.db/scheduled_emails.db/.env on write; create `data/` as `0700`. Add an optional `mode=0o600` param to `atomic_write_json` and apply it before `os.replace`.
- **Effort:** Low.

#### H2 — File-tool sensitive deny-list is materially incomplete + case-sensitive
- **Where:** `src/tool_execution.py:42-53` (deny-list), `:64-65` (exact-case comparison), `:88-108` (`tool_path_extra_roots` opt-in roots).
- **What/why:** Two compounding issues that widen C1/H1 once an admin adds a broader root (an expected, documented action):
  - **Incomplete list:** misses `~/.aws/credentials`, `~/.config/gcloud`, `~/.azure`, `~/.kube/config`, `~/.docker/config.json`, `.git-credentials`, `.npmrc`, `.pypirc`, browser cookie DBs, `*.pem`, `*.key`, `id_dsa`. Only `id_rsa/ed25519/ecdsa` are covered.
  - **Case-sensitive:** comparison is exact-case, but macOS (APFS default) and Windows are case-*insensitive*, so `~/.SSH/id_rsa` or `data/AUTH.JSON` opens the real file while dodging the deny-list. This defeats the C1 and H1 fixes too unless addressed together.
- **Fix:** Prefer an **allowlist-only** model for extra roots (deny-lists are inherently incomplete). Expand `_SENSITIVE_BASENAMES`/patterns. Casefold both sides (`os.path.normcase`) on case-insensitive platforms.
- **Effort:** Low–Medium.

#### H3 — `require_admin` header path skips the loopback check; `X-Odysseus-Owner` can impersonate an admin
- **Where:** `core/middleware.py:30-32` (header-direct admin grant with **no** `_is_trusted_loopback`), vs `app.py:265` (middleware path correctly ANDs loopback). `app.py:270-277` (`X-Odysseus-Owner` sets `request.state.current_user` to any existing user, incl. an admin). `X-Odysseus-Internal-Token` is also in the CORS `allow_headers` (`app.py:100`).
- **What/why:** Defense-in-depth gap forming an escalation chain *if* the internal-tool token leaks (it's per-process random by default — good — but can be pinned via `ODYSSEUS_INTERNAL_TOKEN` env, and is accepted cross-origin). `require_admin` trusts a correct token header alone; and `X-Odysseus-Owner: <admin>` stamps `current_user` to that admin, which `require_admin` then reads (the "this is just attribution" comment is inaccurate — attribution and authz read the same field).
- **Fix:** Add `and _is_trusted_loopback(request)` to the header check in `require_admin` (share the helper from `app.py`). Refuse to impersonate admins via `X-Odysseus-Owner` (or carry impersonation in a separate `request.state.impersonated_owner` that authz never reads). Drop `X-Odysseus-Internal-Token` from CORS `allow_headers`.
- **Effort:** Low.

#### H4 — CORS `allow_credentials=True` with unvalidated `ALLOWED_ORIGINS`
- **Where:** `app.py:88-92`. Cookie is `SameSite=Lax` + `HttpOnly` (`routes/auth_routes.py:138-148`); there is **no separate CSRF token**.
- **What/why:** Default is safe (localhost). But there's no guard against an operator setting `ALLOWED_ORIGINS=*` (a common shortcut) — Starlette would then reflect any origin *with credentials*, allowing any website to make authenticated cross-origin requests on the victim's cookie. CSRF defense rests entirely on `SameSite=Lax` + tight CORS, so the two are coupled: loosen CORS and you lose CSRF protection too.
- **Fix:** At startup, reject/normalize `ALLOWED_ORIGINS` — never allow `*` when `allow_credentials=True`; require scheme+host(+port). Default `SECURE_COOKIES=true` for any non-loopback deployment. Consider an explicit CSRF token for state-changing routes if you ever expose this.
- **Effort:** Low.

---

### MEDIUM

#### M1 — Mid-loop tool output is not wrapped in the untrusted-context guard (biggest prompt-injection coverage gap)
- **Where:** `src/agent_loop.py:~1150-1165` appends tool results as plain `tool`/`user` messages labeled `[Tool execution results]`. `untrusted_context_message` (`src/prompt_security.py`) is **not** applied here, and `mcp_servers/*` never reference it.
- **What/why:** *Prefetched* web/RAG/email context IS correctly wrapped before the turn (`chat_processor.py`, `chat_helpers.py`). But content pulled **during** the loop via tool calls — email bodies (email MCP server), fetched web pages, RAG hits — reaches the model with only the one global policy line to resist injection. This is the practical vector that makes C1/C2 reachable.
- **Fix:** Route tool-result text (especially email/web/RAG MCP servers) through `untrusted_context_message`, or at minimum prepend `UNTRUSTED_CONTEXT_HEADER` to the `[Tool execution results]` block.
- **Effort:** Medium.

#### M2 — Vault endpoints reachable by the agent via `app_api`
- **Where:** `src/tool_implementations.py:2681-2687` — `_APP_API_BLOCKLIST_PREFIXES` blocks `/api/auth`, `/api/tokens`, `/api/admin`, `/api/backup/restore` but **not `/api/vault`**. `app_api` rides the internal-tool token (admin).
- **What/why:** A prompt-injected agent can call `POST /api/vault/unlock` (online password guessing against the vault, with attacker-supplied `master_password`) and `POST /api/vault/lock`/`logout` (DoS on the user's vault). `get_config` omits the secret session key, so no direct secret leak, but unlock/lock are state-changing and should never be agent-reachable.
- **Fix:** Add `"/api/vault"` to `_APP_API_BLOCKLIST_PREFIXES`.
- **Effort:** Trivial.

#### M3 — DNS-rebinding / TOCTOU in outbound validation
- **Where:** `src/url_safety.py:74-90`, `src/webhook_manager.py:80-125`, `src/search/content.py:53-89`. All validate via `getaddrinfo`, then make a *separate* connection that re-resolves DNS.
- **What/why:** A hostname under attacker control can return a public IP at validation time and `127.0.0.1`/metadata at connect time (classic rebinding). The webhook code even documents this as a "partial defense."
- **Fix:** Resolve once, validate the IP, then connect to that literal IP with the original `Host`/SNI preserved (pin the connection to the vetted address).
- **Effort:** Medium.

#### M4 — `check_outbound_url` allows private/loopback by default
- **Where:** `src/url_safety.py:43-44,51` (`block_private=False` default); `embedding_routes.py:253`, `gallery_routes.py:931` default the env flags off.
- **What/why:** By design (local-first), the embedding/gallery URL fetchers can be pointed at localhost/LAN services unless `EMBEDDING_BLOCK_PRIVATE_IPS`/`IMAGE_BLOCK_PRIVATE_IPS` is set. Metadata IP and non-http(s) are always blocked (good), so this is internal-service SSRF, not cloud-cred theft. Defensible locally, but undocumented for gallery and easy to forget when exposing.
- **Fix:** A single global `BLOCK_PRIVATE_EGRESS` flag; document the lockdown vars; the C2 chat fix should default to blocking private.
- **Effort:** Low.

#### M5 — 2FA backup codes: 32-bit entropy, non-constant-time check, plaintext at rest
- **Where:** `core/auth.py:365` (`secrets.token_hex(4)` = 32 bits ×8), `:384-390` (`code in backup` uses `==`), stored plaintext in `auth.json`.
- **Fix:** `secrets.token_urlsafe(10)` (≥80 bits); constant-time compare each via `secrets.compare_digest`; store hashed.
- **Effort:** Low.

#### M6 — Auth rate limiting is proxy-blind
- **Where:** `routes/auth_routes.py:90,104,121` key on `request.client.host`. Behind the documented Cloudflare tunnel, that's `127.0.0.1` for *every* external user → one shared bucket (either lets distributed attacks share a high ceiling, or locks everyone out at once). Ceiling of 15/min is also high for a login endpoint.
- **Fix:** Rate-limit per-username in addition to per-IP; derive a trusted client IP from a configured trusted-proxy `X-Forwarded-For` *for rate-limiting only* (kept separate from the loopback-trust decision); lower the login ceiling and add per-account backoff.
- **Effort:** Medium.

#### M7 — systemd unit binds `0.0.0.0` by default (Linux installs only)
- **Where:** `odysseus-ui.service:11` (`--host 0.0.0.0`), copied + auto-started by `install-service.sh`. (All other launchers — `start-macos.sh`, Docker compose, Windows — default to `127.0.0.1`.)
- **What/why:** Not relevant to a macOS laptop, but if you ever run the Linux service it exposes the UI to the whole LAN. Auth is on, so not wide open, but it contradicts the loopback-default posture.
- **Fix:** Default the unit to `--host 127.0.0.1`; add systemd hardening (`NoNewPrivileges`, `ProtectHome=read-only`, `ProtectSystem=strict`, `PrivateTmp`).
- **Effort:** Low.

#### M8 — `write_file` follows symlinks; no `O_NOFOLLOW`/TOCTOU guard
- **Where:** `src/tool_execution.py:546-553` (`makedirs` + `open(...,"w")`). `realpath` is checked on the pre-existing prefix, but the leaf can be a symlink pointing outside the allowlist, and `open` follows it.
- **Fix:** `os.open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|...)` on the final component; re-validate containment on the opened fd.
- **Effort:** Low.

#### M9 — Dependencies effectively unpinned; floating container tags
- **Where:** `requirements.txt` (25/27 deps unpinned, incl. `cryptography`, `bcrypt`, `pyotp`, `fastapi`); `docker-compose.yml` `chromadb/chroma:latest` and untagged `ntfy` (while searxng IS pinned, with a comment explaining why floating tags are dangerous).
- **What/why:** Non-reproducible builds; a yanked/compromised upstream is pulled silently on the next install (supply-chain). 
- **Fix:** Pin with `==` or a lockfile (`uv lock`/`pip-compile` with hashes); pin chromadb + ntfy by digest.
- **Effort:** Medium.

#### M10 — bash/python tools buffer output unboundedly; no resource limits
- **Where:** `src/tool_execution.py:219-231,468-512`. Full stdout/stderr accumulate in memory; truncation to `MAX_OUTPUT_CHARS` happens only *after* the process ends. No `RLIMIT_AS/CPU/NOFILE/NPROC`; 1-hour timeout is generous.
- **What/why:** Within the accepted "admin RCE" model, but `cat /dev/zero` / fork bombs (accidental or injected) can OOM/hang the box.
- **Fix:** Cap bytes in the reader (stop appending past ~2×limit); `preexec_fn` with `resource.setrlimit` on POSIX.
- **Effort:** Low–Medium.

---

### LOW / INFO

- **L1 — Uploaded HTML/SVG served inline (narrow stored XSS).** `src/upload_handler.py:221-242` is a deny-list; `.html`/`.svg` pass and `download_file` (`upload_routes.py:87-152`) sends them with a guessed `Content-Type` and **no `Content-Disposition: attachment`**. Mitigated by `nosniff` + same-origin CSP + owner-scoping. **Fix:** force `Content-Disposition: attachment` and hard-deny `text/html`/`image/svg+xml`. Path traversal itself is well-defended; no zip-slip (no extraction).
- **L2 — CSP keeps `style-src 'unsafe-inline'` and trusts `cdn.jsdelivr.net` without SRI.** `core/middleware.py:90-100`. Script-src is locked to nonce (good); style risk is visual-only. A jsdelivr compromise would execute in-origin. **Fix:** add SRI to jsdelivr `<script>`s or self-host them.
- **L3 — Username enumeration via timing.** `core/auth.py:411-415` returns early for unknown users without a dummy bcrypt. **Fix:** compare against a fixed dummy hash.
- **L4 — Session not rotated on 2FA enable/disable.** (Password change *does* revoke other sessions — good.) **Fix:** revoke sessions on 2FA toggle.
- **L5 — Fail-open privilege defaults when `AUTH_ENABLED=false`.** `require_admin` + `auth_helpers` default missing/unknown privileges to permitted. Intended for single-user, but a footgun if auth is ever disabled on an exposed box. **Fix:** warn at startup; fail closed on unknown privilege keys.
- **L6 — DB not encrypted at rest** (only mail-credential columns via Fernet, key in same dir). For a laptop, rely on **FileVault**; document this in `SECURITY.md`. SQLCipher if stronger at-rest is wanted.
- **L7 — Login verifies password twice** (`auth_routes.py:125` + `create_session`), minor perf/timing. 
- **L8 — Version constant mismatch** (`core/constants.py` `0.9.1` vs `src/constants.py` `1.0.0`) — maintenance hazard, dedupe.

---

## 4. Recommended remediation order

**Do now (highest value, mostly one-liners):**
1. **C1** — keep file tools out of `data/` (or deny auth.json/sessions.json/*.db). *The single most important fix.*
2. **H1** — `chmod 600` the secret files + `0700` on `data/`.
3. **M2** — add `/api/vault` to the app_api blocklist.
4. **H3** — loopback check on `require_admin`; no admin impersonation via `X-Odysseus-Owner`.
5. **C2** — SSRF guard on `/v1/chat` base_url (+ chokepoint in `llm_call`).

**Next (closes the prompt-injection exposure properly):**
6. **H2** — allowlist-only file roots + casefold + expanded deny-list.
7. **M1** — wrap mid-loop tool output as untrusted context.
8. **H4** — validate `ALLOWED_ORIGINS`; default secure cookies off-loopback.

**Then (hardening):**
9. M3 (DNS pinning), M4 (egress flag), M5 (backup codes), M6 (rate limiting), M8 (O_NOFOLLOW), M10 (rlimits), M9 (pin deps), M7 (systemd, if Linux), and the Low/Info items.

---

## 5. Quick local-hardening checklist (do these today, no code changes)

```sh
# 1. Lock down secret files + data dir
chmod 700 data
chmod 600 data/auth.json data/sessions.json data/app.db data/scheduled_emails.db .env

# 2. Confirm safe defaults in .env
#    AUTH_ENABLED=true        (default)
#    LOCALHOST_BYPASS=false   (default)
#    APP_BIND=127.0.0.1       (do NOT bind 0.0.0.0)
#    ALLOWED_ORIGINS=http://localhost,http://127.0.0.1   (never *)
```

- Set your own `ODYSSEUS_ADMIN_PASSWORD` before first boot; enable TOTP 2FA.
- Keep **FileVault** on — it's the real at-rest protection for the SQLite DB.
- Don't expose the port to the LAN/internet. If you ever must, front it with HTTPS, set `SECURE_COOKIES=true`, a tight `ALLOWED_ORIGINS`, and turn on the private-egress block flags.
- Be cautious feeding the agent untrusted web pages / emails until **C1** and **M1** are fixed — that's the live prompt-injection path.

---

## 6. What's done well (don't regress these)

- **Session/token crypto:** `secrets.token_hex(32)` (256-bit), server-issued, 7-day TTL, revoked on logout/delete/rename, orphan-checked every validate. Bcrypt with constant-time `checkpw`.
- **Loopback trust is proxy-aware:** `_is_trusted_loopback` (`app.py:237-251`) rejects anything carrying `cf-*`/`x-forwarded-*`/`forwarded` headers, so tunnels can't inherit local trust. Internal-tool token is per-process random + `compare_digest`.
- **Non-admin tool gate is fail-closed:** malformed tool names treated as blocked; non-admins have blocked tools stripped from the schema *and* the MCP manager nulled (`agent_loop.py:1375-1380`).
- **Background jobs don't bypass the gate** and use `shlex.quote` + script-file execution (no string-interp injection).
- **Web-fetch / deep-research SSRF is solid** (`src/search/content.py`): scheme allowlist, all-A/AAAA-record checks, redirect re-validation, fail-closed on unresolvable hosts. Webhook destination validation is the strongest in the repo (IPv6-mapped handling, re-validation at delivery, regression-tested).
- **Secrets-at-rest for mail creds:** Fernet, key chmod `0600`, fail-closed decrypt. Deep recursive `settings_scrub` keeps secrets out of non-admin API responses.
- **Vault master password passed on stdin, never argv/env** (regression-tested).
- **XSS:** allowlist DOM sanitizer that re-cleans to a fixpoint; real per-request CSP nonce injected into all inline scripts; script-src has no `unsafe-inline`.
- **Deployment defaults** (except the systemd unit): app + ChromaDB + SearXNG + ntfy all bind `127.0.0.1`; container drops root via `gosu`; ChromaDB telemetry disabled; no app telemetry.
- **No secrets committed:** `.env` is gitignored and never tracked; `.env` == `.env.example` with all secret lines commented.

---

## 7. Open questions for the planning session

- Will you ever expose this beyond localhost (tunnel/LAN)? If yes, H4/M6/M3/M4 jump in priority.
- Do you use the API/companion tokens? That decides how urgent **C2** is.
- Appetite for a real shell/file **sandbox** (THREAT_MODEL gap #1, issue #1058 — bubblewrap/container/seccomp)? That's the durable fix for the whole prompt-injection-to-RCE class, vs. the point fixes C1/H2 above.
- Acceptable to pin dependencies now (may require a test pass), or defer?
