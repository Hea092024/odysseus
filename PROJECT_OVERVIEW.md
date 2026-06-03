# Odysseus — Project Overview

Odysseus is a **self-hosted AI workspace with privileged local access**. It is a
FastAPI application that pairs an LLM agent with a large set of tools (shell,
file I/O, email, calendar, web research, image generation, memory, RAG, MCP, …)
and a single-page web UI. Its security posture is deliberately "treat it like an
admin console": it is built for trusted users on a private network, and a
logged-in admin can run shell commands, read/write files, send email, and manage
model serving by design. See `THREAT_MODEL.md` for the authoritative trust
boundary.

> This document is a read-only orientation guide. Nothing in the repo was
> modified to produce it.

---

## Top-level folders

### `core/` — framework foundations (cross-cutting infrastructure)
The low-level, app-wide primitives every other layer depends on:
- `auth.py` — `AuthManager`: bcrypt passwords, 7-day session tokens, 2FA (TOTP),
  reserved usernames, admin checks, `DEFAULT_PRIVILEGES`.
- `database.py` — SQLAlchemy models + session factory (`SessionLocal`),
  `ApiToken`, `Session`, `ChatMessage`, `GalleryImage`, `ScheduledTask`, legacy-
  owner migrations. (Largest file in the layer.)
- `middleware.py` — `SecurityHeadersMiddleware` (CSP nonce, X-Frame-Options,
  etc.) and the `INTERNAL_TOOL_TOKEN` / `require_admin` loopback machinery.
- `session_manager.py` — chat session lifecycle and persistence.
- `constants.py`, `models.py`, `exceptions.py`, `atomic_io.py` (atomic JSON
  writes), `platform_compat.py` (Windows/POSIX shims).

### `src/` — application logic (the agent + all capabilities)
The bulk of the codebase. Notable modules:
- **Agent core:** `agent_loop.py` (the multi-round tool-calling loop),
  `ai_interaction.py`, `chat_handler.py` / `chat_processor.py`, `llm_core.py`
  (LLM client + provider plumbing).
- **Tool system:** `agent_tools.py` (facade re-exporting the four sub-modules),
  `tool_parsing.py`, `tool_schemas.py`, `tool_execution.py` (dispatch + gating),
  `tool_implementations.py` (the `do_*` functions), `tool_index.py` (RAG-based
  tool retrieval), `tool_security.py` (**the permission policy**).
- **Capabilities:** `memory*.py`, `rag_*.py` / `embeddings.py` / `chroma_client.py`,
  `deep_research.py` / `research_handler.py`, `document_processor.py` /
  `pdf_*.py`, `task_scheduler.py` (scheduled/automation tasks), `email_*` helpers,
  `caldav_*`, `mcp_manager.py` / `builtin_mcp.py`, `webhook_manager.py`,
  `visual_report.py`.
- **Security helpers:** `prompt_security.py` (prompt-injection hardening),
  `tool_security.py`, `url_safety.py`, `secret_storage.py`, `settings_scrub.py`,
  `rate_limiter.py`.
- **Init/glue:** `app_initializer.py` (`initialize_managers`), `config.py`,
  `constants.py`, `event_bus.py`.

### `routes/` — HTTP API layer (FastAPI routers)
One module per feature area, each exposing a `setup_*_routes(...)` factory that
`app.py` includes. Examples: `auth_routes.py`, `chat_routes.py`,
`session_routes.py`, `email_routes.py`, `calendar_routes.py`, `shell_routes.py`
(**user-facing** terminal/PTY endpoint — distinct from the agent's `bash` tool),
`cookbook_routes.py` (model download/serve), `gallery_routes.py`,
`document_routes.py`, `task_routes.py`, `mcp_routes.py`, `api_token_routes.py`,
`webhook_routes.py`, etc. Admin-only endpoints are gated by
`core/middleware.py:require_admin`.

### `services/` — pluggable capability layer
Self-contained service packages, each "doing one thing well" with a clean async
interface that can run in-process or as a standalone HTTP service
(`services/__init__.py`). Subpackages: `search/`, `docs/`, `research/`,
`memory/`, `shell/`, `stt/`, `tts/`, `youtube/`, `hwfit/` (hardware "what fits?"
sizing), `faces/`, `cache/`. `src/` modules and `routes/` consume these.

### `static/` — the front-end SPA
Vanilla ES-module front end served at `/static` (no build step): `index.html`,
`app.js`, `js/`, `lib/`, `style.css`, `login.html`, `landing.html`,
`manifest.json` + `sw.js` (PWA service worker), `fonts/`. `app.py` injects a CSP
nonce into inline `<script>` tags at serve time, and serves these with
`Cache-Control: no-cache` so code changes appear without a hard refresh.

Other notable top-level dirs: `mcp_servers/` (stdio MCP server scripts for the
built-in image-gen/memory/rag/email servers), `companion/` (companion/mobile
routes), `config/`, `data/` (runtime SQLite/JSON state, generated images),
`docs/`, `scripts/`, `tests/`, `docker/`.

---

## Entry point — `app.py`

`app.py` is a **slim orchestrator** (~1070 lines, mostly wiring). Startup
sequence:

1. **MIME + env bootstrap** — register stable JS module MIME types; Windows
   HuggingFace symlink workaround; `load_dotenv(encoding="utf-8-sig")` (BOM-
   tolerant `.env` parsing).
2. **Create `FastAPI` app** and add middleware (executed in reverse order):
   - `CORSMiddleware` (origins from `ALLOWED_ORIGINS`).
   - `SecurityHeadersMiddleware` (from `core/middleware.py`).
   - `_RequestTimeoutMiddleware` — aborts hung requests after
     `REQUEST_HARD_TIMEOUT` (45s) with a 504, except whitelisted streaming/long-
     running paths (`/api/chat`, `/api/shell/stream`, `/api/research`, …).
   - `AuthMiddleware` (when `AUTH_ENABLED`, the default) — see below.
3. **Static mounts + a few inline routes** (`/`, deep-link SPA routes like
   `/email` `/calendar` `/gallery`, `/login`, `/api/version`, `/api/health`,
   `/api/ready`, `/api/runtime`, and the ownership-checked
   `/api/generated-image/{filename}`).
4. **Component init** — `initialize_managers(BASE_DIR, rag_manager)` builds the
   session/memory/upload/preset/chat/research/model-discovery/skills managers;
   plus RAG singleton, TTS/STT services, `WebhookManager`, `TaskScheduler`,
   `McpManager`.
5. **Router registration** — ~50 `app.include_router(setup_*_routes(...))` calls.
6. **Lifespan** (`_lifespan` → `_startup_event` / `_shutdown_event`) — purges
   incognito sessions, starts the background-job monitor, connects built-in +
   user MCP servers, pre-warms the tool index and LLM endpoints, reconciles
   default scheduled tasks, starts the task runner and periodic sweeps (null-
   owner reclaim, nightly skill audit).

### Authentication middleware (in `app.py`)
`AuthMiddleware.dispatch` resolves identity in this order:
1. **Exempt paths** (`/api/auth/*`, `/api/health`, `/static`, the per-task
   `…/webhook/{token}` pattern where the path *is* the credential).
2. **Internal-tool loopback** — `X-Odysseus-Internal-Token` matching the in-
   process `INTERNAL_TOOL_TOKEN` from a *trusted direct-loopback* client
   (`_is_trusted_loopback` rejects anything with proxy/tunnel forwarding
   headers). Optional `X-Odysseus-Owner` impersonation for owner attribution.
3. **`LOCALHOST_BYPASS`** for direct loopback (off by default).
4. **Bearer API tokens** (`Authorization: Bearer ody_…`) — bcrypt-checked
   against an in-memory prefix→hash cache, carries `chat`/`admin` scopes.
5. **Session cookie** — validated by `AuthManager`.

---

## The agent's shell / file / email tools and how they're gated

### Where the tools live
- **Tool registry:** `src/agent_tools.py:TOOL_TAGS` lists every callable tool
  name (`bash`, `python`, `read_file`, `write_file`, `send_email`,
  `read_email`, `list_emails`, `reply_to_email`, etc.).
- **Dispatch + execution:** `src/tool_execution.py:execute_tool_block()` is the
  single chokepoint that runs a parsed tool block.
- **shell / file / python implementations:** `bash`, `python`, `read_file`,
  `write_file` map through `_MCP_TOOL_MAP` to the MCP manager, but those four
  were folded into **native in-process execution** in
  `src/tool_execution.py:_direct_fallback()` (the old `mcp_servers/` stdio
  wrappers were removed). `bash`/`python` run via
  `asyncio.create_subprocess_shell` with a forced sane `TERM`/`COLUMNS`/`LINES`
  env and streaming progress callbacks; a `#!bg` first line runs the command
  detached as a background job (`src/bg_jobs.py`, monitored by
  `src/bg_monitor.py`).
- **email / contacts tools:** these are **built-in MCP servers**, not native.
  `src/builtin_mcp.py:_BUILTIN_SERVERS` registers `mcp_servers/email_server.py`
  (and `image_gen`, `memory`, `rag`) as stdio subprocesses at startup, so the
  agent calls them as `mcp__email__send_email`, `mcp__email__read_email`, etc.
  (The user-facing email REST API lives separately in `routes/email_routes.py`.)
- **user-facing shell** (the in-browser terminal) is a different surface:
  `routes/shell_routes.py` (PTY on POSIX, pipe/detached-job fallback on
  Windows) — not the same code path as the agent's `bash` tool.

### How they're permission-gated
The policy is **fail-closed** and lives in `src/tool_security.py`, enforced at
dispatch time in `src/tool_execution.py:execute_tool_block()`:

1. **User-disabled tools** — `disabled_tools` set for the request → blocked.
2. **Admin-only tools** — `_ADMIN_TOOLS` (e.g. `app_api`, `manage_*`,
   model-serving) blocked unless `_owner_is_admin(owner)`.
3. **Public-user blocklist** — `is_public_blocked_tool(tool)` returns True for
   any name in `NON_ADMIN_BLOCKED_TOOLS` (which includes `bash`, `python`,
   `read_file`, `write_file`, `send_email`, `read_email`, `list_emails`,
   `reply_to_email`, `manage_*`, vault, model serving, …) **or** any
   `mcp__*` tool. These are blocked unless the owner is an admin.
   - Fail-closed detail: a non-string/malformed tool name is treated as
     *blocked*; `None`/empty means "no tool to gate".
4. **Admin determination** — `owner_is_admin_or_single_user(owner)` returns True
   for admins, or when auth is not yet configured (single-user/first-run).
5. **Pre-filtering in the loop** — `src/agent_loop.py` calls
   `blocked_tools_for_owner(owner)` and, for non-admins, adds the whole
   blocklist to `disabled_tools` **and drops the MCP manager entirely** so MCP
   tool schemas are never even offered to the model.

This mirrors the role matrix in `THREAT_MODEL.md`: shell/python, file r/w,
email, MCP, calendar, token/webhook management, model serving, vault, and
settings are **admin-only**; chat, browser, documents, research, image gen, and
memory are available to non-admins.

### Path confinement for file tools
`read_file` / `write_file` paths are model-controlled, so
`src/tool_execution.py` adds a path policy on top of the admin gate:
- **Sensitive deny list (checked first):** `_SENSITIVE_BASENAMES` (`.ssh`,
  `.gnupg`, shell rc files, `.env`, `.netrc`, …) and `_SENSITIVE_FILE_PATTERNS`
  (`authorized_keys`, `id_rsa`, `known_hosts`, …) — blocked even under an allowed
  root.
- **Allowlist:** `_tool_path_roots()` defaults to the project `DATA_DIR` + system
  temp; `$HOME` is **not** included by default. Admins can widen it via the
  `tool_path_extra_roots` setting.

### Prompt-injection hardening
`src/prompt_security.py` wraps all untrusted content (web results, fetched URLs,
emails, memories, skill text, tool output) via `untrusted_context_message()`
into a `user`-role block with an `UNTRUSTED_CONTEXT_HEADER` telling the model not
to follow embedded instructions, plus an `UNTRUSTED_CONTEXT_POLICY` system
preamble. Injecting untrusted content into the system role is treated as a
security bug.

### Known gaps (from `THREAT_MODEL.md`)
No shell/filesystem sandbox (agent `bash`/file tools run as the app user with no
egress filtering), an SSRF vector via the `/api/v1/chat` `base_url` parameter, a
partially-consolidated `src/search/`, and coarse token scopes (`chat` vs
`admin`).

---

## Request flow (typical agent chat turn)

```
Browser (static/ SPA)
  → POST /api/chat            (routes/chat_routes.py)
  → AuthMiddleware            (identity: cookie / bearer / loopback)
  → chat_handler / chat_processor
  → src/agent_loop.py         (multi-round loop; RAG tool selection)
      ├─ blocked_tools_for_owner(owner)  ← gate non-admins up front
      └─ execute_tool_block(...)         (src/tool_execution.py)
            ├─ admin / public-blocklist gate (src/tool_security.py)
            ├─ native: bash/python/read_file/write_file (_direct_fallback)
            ├─ MCP: mcp__email__*, mcp__image_gen__*, user MCP servers
            └─ do_* implementations (src/tool_implementations.py)
                 └─ admin-gated routes via in-process loopback
                    (X-Odysseus-Internal-Token → require_admin)
  → SSE stream back to the UI
```
