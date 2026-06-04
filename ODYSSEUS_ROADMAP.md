# Odysseus Roadmap

**Created:** 2026-06-03
**Source of truth for Phase 1:** `SECURITY_RISKS.md` (finding IDs C1, C2, H1–H4, M1–M10, L1–L8).
**Sequencing rule:** Phase 1 must be 100% complete before any Phase 2 work begins. Phase 2 before Phase 3.

### How to use this file
- Status markers: `[ ]` open · `[x]` done — append the commit SHA when checking a box.
- Every task names the exact file(s) and line range to change. Line numbers are from the 2026-06-03 tree; re-confirm before editing (a fix in one sprint can shift lines for later ones in the same file — `src/tool_execution.py` and `app.py` are touched repeatedly).
- Commit messages follow the house style (short, lower-case-after-first-cap, no `feat`/`refactor`/`fix:` prefixes, no trailing period, no AI trailer). One finding ID per commit where practical, e.g. `Confine agent file tools to data workspace (C1)`.
- **Plan only — no code in this document.**

---

## PHASE 1 — SECURITY

> Nothing else ships until every finding below is `[x]` with a SHA. Section structure mirrors `SECURITY_RISKS.md` §4.

### Sprint 1 — Critical path (C1, H1, M2, H3, C2)

#### [x] C1 — Critical — Agent file tools can read `data/auth.json` (token theft → persistent takeover) — `9fd1ba8`
- **Files:** `src/tool_execution.py:76-108` (`_tool_path_roots`, esp. `:84-85` adds `DATA_DIR`); `src/tool_execution.py:42-73` (`_SENSITIVE_BASENAMES` / `_is_sensitive_path`).
- **Fix:** Confine `read_file`/`write_file` to a dedicated `data/agent_workspace/` instead of the whole `DATA_DIR`. If keeping `DATA_DIR` as a root, add a hard deny in `_is_sensitive_path` for any resolved path under `DATA_DIR` matching `{auth.json, sessions.json, settings.json, vault*, *.db, *.db-wal, *.db-shm, tokens*, .app_key, integrations.json}`.
- **Effort:** Low.

#### [x] H1 — High — Secret files written world-readable (0644) — `266c395`
- **Files:** `core/atomic_io.py` (`atomic_write_json` — add `mode` param, `os.chmod(tmp, mode)` before `os.replace`); `core/auth.py:160-165` (`_save` → pass `mode=0o600`); `setup.py:111-112` (chmod auth.json after write); `core/database.py:30-33` (chmod the SQLite file 0600 on create, or create `data/` as 0700 at startup).
- **Fix:** Persist auth.json/sessions.json/app.db/scheduled_emails.db at 0600; create `data/` at 0700. Mirror the existing `safe_chmod(..., 0o600)` pattern from `src/secret_storage.py:44`.
- **Effort:** Low.

#### [x] M2 — Medium — Vault endpoints reachable by the agent via `app_api` — `0d5a822`
- **Files:** `src/tool_implementations.py:2681-2687` (`_APP_API_BLOCKLIST_PREFIXES`).
- **Fix:** Add `"/api/vault"` to the blocklist tuple.
- **Effort:** Trivial.

#### [x] H3 — High — `require_admin` header path skips loopback check; `X-Odysseus-Owner` admin impersonation — `b154eca`
- **Files:** `core/middleware.py:29-36` (header-direct grant — add loopback requirement); `app.py:237-251` (`_is_trusted_loopback` — move into `core/middleware` so both share it); `app.py:270-277` (`X-Odysseus-Owner` impersonation); `app.py:94-104` (drop `X-Odysseus-Internal-Token` from CORS `allow_headers`).
- **Fix:** In `require_admin`, require `_is_trusted_loopback(request)` alongside the token match. Refuse `X-Odysseus-Owner` impersonation of admins (or store it in a separate `request.state.impersonated_owner` that authz never reads). Remove the internal-token header from CORS.
- **Effort:** Low.
- **Done:** Moved `is_trusted_loopback` to `core/middleware.py` (single shared impl); `require_admin` now requires token **and** loopback; removed `X-Odysseus-Internal-Token` from CORS `allow_headers`. Tests in `tests/test_require_admin_loopback.py`.
- **Deviation:** Kept `X-Odysseus-Owner` attribution (did NOT refuse admin impersonation). Reaching that branch already requires the internal token + trusted loopback, which already grants full admin — impersonation adds no authority. Refusing it would break the agent attributing the admin's own notes/calendar/gallery (the loopback caller sets `X-Odysseus-Owner` to the session owner, which here is the admin — see `src/tool_implementations.py:2489`). The escalation surface (token-without-loopback, CORS exposure) is closed instead.

#### [x] C2 — Critical — `/v1/chat` `base_url` SSRF unfixed — `ab4384d`
- **Files:** `routes/webhook_routes.py:234-373` (guard `body.base_url` before `:291`); `src/llm_core.py` (`llm_call` ~`:795`, `llm_call_async` ~`:942` — add a `check_outbound_url` chokepoint on the final resolved URL); `src/endpoint_resolver.py:117-130` (`resolve_url` rewrites host — chokepoint must run after this); `THREAT_MODEL.md:77` (correct the false "PR #1039 fixes this").
- **Fix:** `check_outbound_url(base_url, block_private=True)` in the `/v1/chat` handler, **and** the same guard inside `llm_call`/`llm_call_async` on the post-resolve URL so the Tailscale rewrite (M-aggravator) is covered. Add `100.64.0.0/10` to private ranges.
- **Effort:** Low–Medium.
- **Done:** `/v1/chat` validates a caller-supplied `base_url` with `check_outbound_url(block_private=CHAT_BLOCK_PRIVATE_IPS default true)` → blocks loopback/LAN/CGNAT/metadata; explicit `100.64.0.0/10` block added to `url_safety._classify` (Python's `is_private` misses it). `llm_call`/`llm_call_async` gained `_guard_outbound_target[_async]` (metadata/link-local block on every dispatch). `THREAT_MODEL.md` corrected. Tests in `tests/test_chat_base_url_ssrf.py`.
- **Note:** The `llm_call` chokepoint uses `block_private=False` (metadata-only) by necessity — `block_private=True` there would break every local model (Ollama/llama.cpp/LAN/Tailnet all resolve to private IPs). The Tailscale-rewrite vector is instead closed at the handler: caller base_urls are validated with `block_private=True`, and `check_outbound_url` fails closed on the unresolvable hostnames that would trigger `resolve_url`'s Tailnet rewrite.

**Sprint 1 gate:** C1, H1, M2, H3, C2 all `[x]` ✅ **COMPLETE**

---

### Sprint 2 — Close prompt injection properly (H2, M1, H4)

#### [ ] H2 — High — File-tool deny-list incomplete + case-sensitive
- **Files:** `src/tool_execution.py:42-53` (expand `_SENSITIVE_BASENAMES`/patterns); `:56-73` (`_is_sensitive_path` — casefold via `os.path.normcase` on case-insensitive platforms); `:88-108` (`tool_path_extra_roots` — prefer allowlist-only).
- **Fix:** Add `.aws .azure .kube .docker .config .mozilla .terraform.d`, patterns `credentials *.pem *.key id_dsa .git-credentials .npmrc .pypirc Cookies login.keychain*`. Casefold both sides of every comparison. Treat extra roots as an explicit allowlist, not deny-list-only.
- **Effort:** Low–Medium.

#### [ ] M1 — Medium — Mid-loop tool output not wrapped as untrusted context
- **Files:** `src/agent_loop.py:~1150-1165` (where tool results are appended as `tool`/`user` messages); `src/prompt_security.py` (`untrusted_context_message`, `UNTRUSTED_CONTEXT_HEADER`); `mcp_servers/email_server.py`, `mcp_servers/rag_server.py` (email/RAG output).
- **Fix:** Route tool-result text (email bodies, fetched web pages, RAG hits especially) through `untrusted_context_message`, or at minimum prepend `UNTRUSTED_CONTEXT_HEADER` to the `[Tool execution results]` block.
- **Effort:** Medium.

#### [ ] H4 — High — CORS `allow_credentials=True` with unvalidated `ALLOWED_ORIGINS`
- **Files:** `app.py:88-105` (validate env at startup); `routes/auth_routes.py:138-148` (default `SECURE_COOKIES=true` off-loopback).
- **Fix:** Reject `*` when credentials are on; require fully-qualified origins (scheme+host[+port]); warn on misconfig at boot. Optionally add a CSRF token for state-changing routes if exposure is planned.
- **Effort:** Low.

**Sprint 2 gate:** H2, M1, H4 all `[x]`.

---

### Sprint 3 — Hardening (M3–M10, L1–L8)

#### [ ] M3 — Medium — DNS-rebinding / TOCTOU in outbound validation
- **Files:** `src/url_safety.py:74-90`; `src/webhook_manager.py:80-125`; `src/search/content.py:53-89`.
- **Fix:** Resolve once, validate the IP, then connect to that literal IP with original `Host`/SNI preserved (pin the vetted address). **Effort:** Medium.

#### [ ] M4 — Medium — `check_outbound_url` allows private/loopback by default
- **Files:** `src/url_safety.py:43-44,51`; `routes/embedding_routes.py:253`; `routes/gallery_routes.py:931`.
- **Fix:** Single global `BLOCK_PRIVATE_EGRESS` flag; document the lockdown vars; chat path defaults to blocking private. **Effort:** Low.

#### [ ] M5 — Medium — 2FA backup codes weak (32-bit, non-constant-time, plaintext)
- **Files:** `core/auth.py:365` (entropy), `:384-390` (comparison + storage).
- **Fix:** `secrets.token_urlsafe(10)` (≥80 bits); constant-time `secrets.compare_digest` per code; store hashed. **Effort:** Low.

#### [ ] M6 — Medium — Auth rate limiting proxy-blind
- **Files:** `routes/auth_routes.py:90,104,121`; `src/rate_limiter.py`.
- **Fix:** Rate-limit per-username + per-IP; derive trusted client IP from configured trusted-proxy XFF (for limiting only); lower login ceiling + per-account backoff. **Effort:** Medium.

#### [ ] M7 — Medium — systemd unit binds `0.0.0.0` by default (Linux only)
- **Files:** `odysseus-ui.service:12` (change to `--host 127.0.0.1`, add `NoNewPrivileges`/`ProtectHome`/`ProtectSystem=strict`/`PrivateTmp`); `install-service.sh`.
- **Fix:** Loopback default + systemd hardening. **Effort:** Low.

#### [ ] M8 — Medium — `write_file` follows symlinks (no `O_NOFOLLOW`)
- **Files:** `src/tool_execution.py:537-553` (`_write`).
- **Fix:** `os.open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|...)` on the leaf; re-validate containment on the opened fd. **Effort:** Low.

#### [ ] M9 — Medium — Dependencies unpinned; floating container tags
- **Files:** `requirements.txt`; `docker-compose.yml` (`chromadb/chroma:latest`, untagged `ntfy`).
- **Fix:** Pin with `==` or a lockfile (`uv lock`/`pip-compile --generate-hashes`); pin chromadb + ntfy by digest. **Effort:** Medium.

#### [ ] M10 — Medium — bash/python tools buffer output unboundedly; no rlimits
- **Files:** `src/tool_execution.py:219-231` (`_reader`), `:466-512` (subprocess exec).
- **Fix:** Stop appending past ~2×`MAX_OUTPUT_CHARS`; `preexec_fn` with `resource.setrlimit` (AS/CPU/NOFILE/NPROC) on POSIX. **Effort:** Low–Medium.

#### [ ] L1 — Low — Uploaded HTML/SVG served inline (narrow stored XSS)
- **Files:** `src/upload_handler.py:221-242` (deny-list); `routes/upload_routes.py:87-152` (`download_file`).
- **Fix:** Force `Content-Disposition: attachment`; hard-deny `text/html`/`image/svg+xml`. **Effort:** Low.

#### [ ] L2 — Low — CSP keeps `style-src 'unsafe-inline'`; jsdelivr without SRI
- **Files:** `core/middleware.py:90-100`; `static/index.html` (jsdelivr `<script>` tags).
- **Fix:** Add SRI to jsdelivr scripts or self-host them. **Effort:** Low–Medium.

#### [ ] L3 — Low — Username enumeration via timing
- **Files:** `core/auth.py:411-415` (`verify_password`).
- **Fix:** Run a dummy `bcrypt.checkpw` against a fixed hash when the user is absent. **Effort:** Low.

#### [ ] L4 — Low — Session not rotated on 2FA enable/disable
- **Files:** `core/auth.py` (2FA enable/disable paths); `routes/auth_routes.py`.
- **Fix:** Revoke other sessions on 2FA toggle (mirror `change_password`). **Effort:** Low.

#### [ ] L5 — Low — Fail-open privilege defaults when `AUTH_ENABLED=false`
- **Files:** `core/middleware.py:38-45`; `src/auth_helpers.py` (privilege getters).
- **Fix:** Startup warning; fail closed on unknown privilege keys. **Effort:** Low.

#### [ ] L6 — Low — DB body not encrypted at rest
- **Files:** `SECURITY.md` (document FileVault reliance); optional SQLCipher path.
- **Fix:** Document; FileVault is the practical control on a laptop. **Effort:** Low (doc).

#### [ ] L7 — Low — Login verifies password twice
- **Files:** `routes/auth_routes.py:125` + `core/auth.py:417-421` (`create_session`).
- **Fix:** Add `create_session_for_user(username)` that skips re-verification. **Effort:** Low.

#### [ ] L8 — Low — Version constant mismatch
- **Files:** `core/constants.py` (`APP_VERSION=0.9.1`) vs `src/constants.py` (`APP_VERSION=1.0.0`).
- **Fix:** Single source of truth; import one from the other. **Effort:** Low.

**Sprint 3 gate:** M3–M10 and L1–L8 all `[x]`.

### Phase 1 completion criteria
Every finding above is `[x]` with a commit SHA. Recommend a final regression pass on the existing SSRF/auth tests (`tests/test_webhook_ssrf_resilience.py`, vault/auth tests) plus new tests for C1 (deny auth.json), C2 (block private base_url), H2 (casefold/expanded deny-list).

---

## PHASE 2 — PERFORMANCE

> Begins only after Phase 1 is complete. Each item: current state → target → files → effort.

### [ ] P2.1 — Context window default (raise effective floor toward 32k)
- **Current:** `src/context_budget.py:17` `DEFAULT_BUDGET = 6000`; `src/agent_loop.py:1527` reads `agent_input_token_budget` default `6000`; `compute_input_token_budget` (`context_budget.py:21-55`) already auto-scales to 85% of the *discovered* model context (`DEFAULT_HARD_MAX=200_000`). The 6000 floor only bites when the model's context window is **unknown** (`model_context.py` discovery fails) — then it hard-caps at 6000. `src/context_compactor.py:40` `SMALL_CONTEXT_LIMIT = 8192` triggers aggressive trimming below that.
- **Target:** 32k safe default when the window can't be discovered, without over-sending to genuinely small models.
- **Files:** `src/context_budget.py:17` (raise `DEFAULT_BUDGET` to e.g. 32000, or add a `DEFAULT_WHEN_UNKNOWN`); `src/model_context.py:35-260` (make discovery more robust so the unknown-window path is rarely hit — it already probes llama.cpp `/slots` `n_ctx`); `src/context_compactor.py:40` (re-tune `SMALL_CONTEXT_LIMIT` so 32k doesn't trip aggressive trimming).
- **Effort:** Low (the scaling machinery already exists; this is tuning + better discovery).

### [ ] P2.2 — Frontend load time & bundle size
- **Current:** `static/` is **11 MB**, no build step / no minification (`package.json` has no bundler). `static/app.js` 176 KB, `static/index.html` 195 KB with **44 `<script>` tags**, `static/style.css` **1.1 MB**, `static/js/` 5 MB across **76 modules** (e.g. `document.js` 434 KB, `slashCommands.js` 261 KB, `emailLibrary.js` 245 KB), `static/lib/` 3.2 MB of heavy libs (`xlsx.full.min.js` 952 KB, `html2pdf.bundle.min.js` 906 KB, `docx.umd.min.js` 743 KB, `mammoth.browser.min.js` 642 KB). Served with `Cache-Control: no-cache` on `.js/.css/.html` (`app.py:369-385`) → conditional re-validation every load.
- **Target:** Cut first-load bytes substantially; defer heavy/rarely-used code.
- **Files:** `static/index.html` (the 44 script tags — lazy-load modal/feature modules); `static/lib/*` (load `xlsx`/`docx`/`mammoth`/`html2pdf` only when a doc feature is used — dynamic `import()`); `static/style.css` (split the 1.1 MB sheet per-view or purge unused); `app.py:369-385` (use content-hashed filenames + long cache instead of `no-cache`, so revalidation isn't needed every load); optionally add a minify step to `package.json`/Dockerfile.
- **Effort:** Medium–High (lazy-loading libs is Medium; full bundling/minify pipeline is High).

### [ ] P2.3 — Database queries & indexing (SQLite)
- **Current:** `core/database.py` is already well-indexed (owner/session_id/composite indexes on `sessions`, `chat_messages`, `documents`, `gallery_images`, etc.). **But** the SQLite pragma listener (`core/database.py:43-48`) sets only `foreign_keys=ON` — **no WAL mode, no `synchronous=NORMAL`, no `busy_timeout`**. `connect_args={"check_same_thread": False}` with the default pool.
- **Target:** Better read/write concurrency and fewer "database is locked" stalls.
- **Files:** `core/database.py:43-48` (add `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `PRAGMA busy_timeout=5000`, `PRAGMA cache_size`); audit hot read paths (`core/session_manager.py`, `routes/history_routes.py`, `routes/session_routes.py`) for N+1 patterns once WAL is in.
- **Effort:** Low (pragmas) + Medium (N+1 audit).

### [ ] P2.4 — ChromaDB / memory retrieval speed
- **Current:** `src/chroma_client.py:59` uses `chromadb.HttpClient` (network hop to the docker service). Embeddings via local fastembed ONNX (`src/embeddings.py:101-150`), cached under `data/fastembed_cache`. Memory search `src/memory_vector.py:90-104` queries per call, `k=8`, cosine HNSW. RAG `src/rag_vector.py:203` similar.
- **Target:** Lower retrieval latency (embedding gen + query round-trip).
- **Files:** `src/embeddings.py` (confirm the fastembed model is a process-singleton, not re-instantiated per call; add an in-memory LRU cache keyed on query text so repeat queries skip embedding); `src/memory_vector.py:39-41`, `src/rag_vector.py:67-69` (tune HNSW: `hnsw:construction_ef`, `hnsw:search_ef`, `hnsw:M` in collection metadata); `src/chroma_client.py:59` (connection reuse / keep-alive; consider embedded `PersistentClient` for single-machine to drop the HTTP hop).
- **Effort:** Medium.

### [ ] P2.5 — Model loading & warmup
- **Current:** `app.py:880-908` pre-warms the tool index (embedding model + ChromaDB) and pings up to 5 LLM endpoints at startup as fire-and-forget tasks; `_keepalive_loop` (`app.py:910-920`) re-pings every 60s. Good — first-turn latency is already addressed. The cost is the one-time fastembed model load (~1–3s).
- **Target:** Keep first-turn fast; avoid redundant warmups.
- **Files:** `app.py:880-920` (verify warmup doesn't double-load the embedding model that `src/embeddings.py` also lazy-loads; share one instance); `src/model_discovery.py` (cache discovered context windows to disk so `model_context.py` discovery — see P2.1 — doesn't re-probe every boot).
- **Effort:** Low.

### [ ] P2.6 — Streaming response latency (time-to-first-token)
- **Current:** Before the first token, `src/agent_loop.py:1382-1394` runs request setup + RAG tool selection (`get_tools_for_query`, `tool_index.retrieve` k=8) and admin-intent detection. Tool selection is on the critical path to first token; warmup (P2.5) mitigates cold cost but every turn still pays the retrieval.
- **Target:** Lower TTFT by overlapping or skipping retrieval where safe.
- **Files:** `src/agent_loop.py:1382-1394` (start streaming a lightweight ack/typing event before tool retrieval completes; cache tool-retrieval results per recent-context hash); `routes/chat_routes.py` (the SSE handler — ensure no synchronous prep blocks the first `yield`); `src/tool_index.py:431-437` (`get_tools_for_query` — memoize per query).
- **Effort:** Medium.

### [ ] P2.7 — Concurrent request handling
- **Current:** Single uvicorn process, **no `--workers`** (`start-macos.sh:208`, `Dockerfile:47`, `odysseus-ui.service:12`). Heavy work is offloaded with `asyncio.to_thread` (token-cache bcrypt in `app.py`, DB touch), and `_RequestTimeoutMiddleware` (`app.py:135-149`) bounds non-streaming requests at 45s. Blocking risks: synchronous SQLite calls on the event loop in some routes, bcrypt on login.
- **Target:** Handle concurrent users/agents without event-loop stalls (single-user is fine today; matters if companion/mobile + scheduled tasks run concurrently).
- **Files:** launch scripts (`start-macos.sh:208`, `Dockerfile:47`) — consider `--workers N` (note: in-process schedulers/pollers and the bg-job monitor assume one process; gate them to worker 0 or keep single-worker + rely on async); audit `routes/*` for synchronous `SessionLocal()` queries that should be `asyncio.to_thread`. Pairs with P2.3 (WAL) for multi-worker SQLite.
- **Effort:** Medium–High (multi-worker needs the single-process assumptions in `app.py` startup resolved first).

---

## PHASE 3 — INTELLIGENCE

> Begins only after Phase 2. Each item: current limitation → proposed improvement → files → effort.

### [ ] P3.1 — System prompt & memory injection quality
- **Current limitation:** Two parallel memory-relevance systems: lexical Jaccard/keyword (`src/memory.py:277` `get_relevant_memories`, `threshold=0.05`, `max_items=8`) and vector cosine (`src/memory_vector.py:90` `search`, `k=8`). Injection happens in `src/chat_processor.py:194-229` (pinned + recalled). `threshold=0.05` is very low → near-everything passes the lexical filter; no cross-encoder relevance ranking; fixed `max_items=8` regardless of token budget; no recency/decay weighting blended with similarity.
- **Proposed:** Unify on vector retrieval with a relevance floor, blend a recency/usage signal, and size the injected set to the (now larger, P2.1) token budget instead of a flat 8. Raise/justify the `0.05` floor.
- **Files:** `src/chat_processor.py:55-160` (retrieval + selection), `src/memory.py:277` (threshold/max_items), `src/memory_vector.py:90-130` (similarity floor).
- **Effort:** Medium.

### [ ] P3.2 — Skill auto-extraction & retrieval tuning
- **Current limitation:** Skills retrieved via ChromaDB top-k in `src/tool_index.py:260` (`retrieve`, `k=8`) and `:431-437` (`get_tools_for_query`); nightly audit at `app.py:1022-1045`; a retrieval-precision judge exists (`routes/skills_routes.py:304-331`) but is advisory. Fixed k, no score threshold on retrieval (over-selection risk the judge flags), extraction quality depends on the teacher loop.
- **Proposed:** Add a similarity threshold (not just top-k) to skill/tool retrieval; dedup near-identical skills at add-time; feed the retrieval-precision judge's output back into ranking. Tune k by query complexity.
- **Files:** `src/tool_index.py:260-280,431-437`; `routes/skills_routes.py:304-331` (promote the precision judge from advisory to a ranking input); `src/teacher_escalation.py` (extraction quality gates).
- **Effort:** Medium.

### [ ] P3.3 — Deep Research pipeline accuracy & speed
- **Current limitation:** `src/deep_research.py` is an iterative IterResearch loop (plan → queries → SearXNG search → extract → synthesize → continue/stop, `synthesis_window=10`). Single search provider (SearXNG); rounds appear sequential; no adversarial claim verification; dedup/quality filtering is light (`src/research_utils.py` `is_low_quality`, `strip_thinking`).
- **Proposed:** Parallelize per-round query fetches (`asyncio.gather`); add a verification pass that cross-checks key claims against ≥2 independent sources before they enter the report; multi-provider search fan-out; source dedup by URL+content hash.
- **Files:** `src/deep_research.py:180-260` (the round loop — parallelize fetch/extract), claim-synthesis section (`:84-150` prompts — add a verify stage); `src/research_handler.py` (orchestration); `src/research_utils.py` (dedup/quality).
- **Effort:** High.

### [ ] P3.4 — RAG chunking strategy & retrieval relevance
- **Current limitation:** Chunking is sentence-aware but fixed-size: `src/rag_vector.py:444-453` `_split_into_chunks(chunk_size=1000 chars, overlap=200)`. Hybrid search already exists (`:181-234`, `VECTOR_WEIGHT`/`KEYWORD_WEIGHT`) but the keyword score is naive word-overlap (`:222-225`), not BM25. **No cross-encoder reranker.**
- **Proposed:** Add a reranking stage (cross-encoder or LLM rerank of top-N) before returning; replace naive keyword overlap with BM25; make chunk size/overlap configurable and tune for the embedding model; add metadata filtering.
- **Files:** `src/rag_vector.py:181-234` (hybrid scoring → BM25 + rerank), `:441-453` (chunking params), `src/document_processor.py` (chunk creation), `src/embeddings.py` (optional reranker model).
- **Effort:** Medium–High.

### [ ] P3.5 — Agent tool loop reliability & error recovery
- **Current limitation:** `MAX_AGENT_ROUNDS = 20` (`src/agent_tools.py:22`). Error recovery is driven by **prompt instructions** (`src/agent_loop.py:75,122` — "after a tool fails, don't go silent"), not code: no programmatic loop/duplicate-call detection, no automatic retry-with-backoff for transient tool errors, no structured "you've repeated this failing call N times" feedback.
- **Proposed:** Add code-level detection of repeated identical tool calls (hash of tool+args) and inject explicit feedback / force a strategy change; auto-retry transient failures (timeouts, 5xx) with backoff; graceful summary at max-round exhaustion instead of a hard stop.
- **Files:** `src/agent_loop.py` (the round loop — track recent tool-call signatures, inject loop-break feedback, handle max-round exhaustion); `src/tool_execution.py:682-765` (classify transient vs permanent errors for retry).
- **Effort:** Medium.

### [ ] P3.6 — Model upgrade path (adopt better models via Cookbook)
- **Current limitation:** Models discovered/served via `src/model_discovery.py`, `routes/cookbook_routes.py`, `routes/model_routes.py`; per-role model settings exist (default/teacher/task/vision/image/research — see `src/tool_index.py:87`, `manage_settings`). Adopting a newly released model is manual (download + serve + point the role setting). No capability/context auto-detection feeding role suggestions.
- **Proposed:** A "recommended model" surface that flags when a newer/stronger model is available for a role; auto-detect served model context/capabilities (P2.1 discovery) and suggest role assignment; one-click "make this the default/teacher model" after serve.
- **Files:** `src/model_discovery.py` (capability detection + recommendation), `routes/cookbook_routes.py` (post-serve "set as role" hook), `routes/model_routes.py` (role assignment), `src/endpoint_resolver.py`.
- **Effort:** Medium.

### [ ] P3.7 — Multi-model / chain-of-thought in current arch
- **Current limitation:** Multi-model primitives already exist: `do_chat_with_model`, `do_ask_teacher`, `do_pipeline` (sequential model chain, `src/ai_interaction.py:587-692`), `do_create_session`/`do_send_to_session`. No built-in self-consistency (sample-N-and-vote), no verifier-model pass, no parallel ensemble — `pipeline` is sequential only.
- **Proposed:** Add a self-consistency/voting helper (run N samples, majority/judge select) and a verifier-model pass (second model checks the first's answer) built on the existing `chat_with_model` plumbing — cleanest insertion is a new tool alongside `do_pipeline`. Parallel fan-out via `asyncio.gather` in `do_pipeline` for independent steps.
- **Files:** `src/ai_interaction.py:587-692` (extend `do_pipeline` with parallel + voting modes, or add `do_consensus`/`do_verify`), `src/tool_index.py` / `src/agent_tools.py` (register the new tool), `src/agent_loop.py` (optional: a "verify before final answer" mode for high-stakes turns).
- **Effort:** Medium.

---

## Status summary

| Phase | Scope | Items | Done |
|---|---|---|---|
| 1 — Security | C1, C2, H1–H4, M1–M10, L1–L8 | 20 | 5 / 20 |
| 2 — Performance | P2.1–P2.7 | 7 | 0 / 7 |
| 3 — Intelligence | P3.1–P3.7 | 7 | 0 / 7 |

Phase 1 must read 20/20 before Phase 2 starts.
