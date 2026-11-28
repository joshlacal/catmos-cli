# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in the `catmos-cli/` project.

## Overview

`catmos-cli` is a Rust CLI + TUI MLS group-chat client for the Catbird/Bluesky messaging stack. It consumes the `catbird-mls` Rust orchestrator **directly** (no UniFFI/WASM layer — unlike iOS, desktop, or web), via a Cargo path dependency. It talks to the same backends as the other clients: `nest` (OAuth BFF) for auth and `chat.catbird.blue` (mls-ds) for the MLS delivery service.

> **Name collision warning:** the binary crate here is named `catmos` and lives in `catmos-cli/catmos/`. This is **not** the same as the top-level `catmos/` Tauri desktop app (Svelte). When in this workspace, `catmos` = the CLI/TUI binary.

## Workspace Layout

A Cargo workspace (`resolver = "2"`) with three members:

| Crate | Dir | Kind | Owns |
|-------|-----|------|------|
| `catmos` | `catmos/` | bin (`[[bin]] name = "catmos"`) | Entrypoint, `clap` arg parsing, subcommand dispatch, `tracing` setup, interactive prompts (`rpassword`). Delegates to `catmos-core` + `catmos-tui`. |
| `catmos-core` | `catmos-core/` | lib | Shared logic: MLS wiring (`MlsManager` over `catbird-mls`), `ChatService`, auth (OAuth loopback + app-password), encrypted SQLite/SQLCipher storage, config, key packages, device onboarding, recovery, WebSocket sync, blocks/aliases. |
| `catmos-tui` | `catmos-tui/` | lib | `ratatui` + `crossterm` terminal UI: app/event loop, keybinds, sidebar/messages/members/input/status-bar/avatar widgets. Entered via `catmos_tui::run()`. |

Path deps to sibling repos (declared in workspace `Cargo.toml`):
- `catbird-mls = { path = "../catbird-mls", package = "catbird_mls", features = ["legacy-orchestrator"] }`
- `../Petrel/rust` provides the SDK, identity and core AT Protocol Lexicons.
- `../PetrelCatbird/rust/petrel-catbird` provides the generated Catbird routes and subscription events.

`catmos-core` module roots: `auth/`, `chat/`, `mls/`, `recovery/`, `storage/`, `types`, `error`.

## Build & Run

### CMake workaround (REQUIRED)

This workspace transitively depends on `audiopus_sys` (via `catbird-mls`), which hits a CMake 4.x policy regression (`CMP0114/0115/0116`). There is **no `.cargo/config.toml`** setting this — you must export it yourself before any cargo invocation:

```bash
export CMAKE_POLICY_VERSION_MINIMUM=3.5    # set once per shell; workspace backlog item N2
```

Without it, the build fails in the native `audiopus_sys` step. With it, the C build succeeds (this is necessary **and** sufficient for the audiopus layer — it is not the same as a green workspace build; see Known Issues).

### Commands

```bash
cd catmos-cli
export CMAKE_POLICY_VERSION_MINIMUM=3.5

cargo build --workspace                       # debug build
cargo build --workspace --release             # release
cargo check -p catmos-core                    # single-crate check
cargo test --workspace                        # tests
cargo fmt --check && cargo clippy --all-targets   # lint

# Run the binary (CLI or TUI):
cargo run -p catmos -- login <handle>         # OAuth loopback flow (default)
cargo run -p catmos -- login <handle> --app-password   # app-password flow
cargo run -p catmos -- convos                 # list conversations
cargo run -p catmos -- send <convo> "<msg>"
cargo run -p catmos                           # launch TUI (no subcommand == `chat`)
cargo run -p catmos -- chat                   # launch TUI explicitly
```

Optional TUI feature: `--features catmos-tui/terminal-images` enables inline kitty/sixel avatar rendering (off by default; avatar bytes are persisted regardless).

### Subcommands (verify before scripting)

Per the workspace smoke-test discipline, confirm a flag/subcommand exists before scripting a sweep against it. Current top-level subcommands (see `catmos/src/main.rs`): `chat`, `send`, `convos`, `members`, `messages`, `login`, `logout`, `accounts`, `switch`, `convo {create,join,leave,info,update,add-member,remove-member,promote}`, `react`/`unreact`, `key-package {status,replenish}`, `device {list,register,remove}`, `reset-group`, `debug {epoch,group-state,tree-hash}`, `blob {upload,download,usage}`, `alias {set,list,remove}`, `block {add,remove,list}`.

## Architecture

```
catmos (bin: clap dispatch, tracing)
  ├─ catmos-tui  (ratatui TUI: catmos_tui::run())
  └─ catmos-core (ChatService, MlsManager, auth, storage)
        └─ catbird-mls  (OpenMLS orchestrator — used DIRECTLY, no FFI)
        └─ Petrel / PetrelCatbird  (ATProto types + identity)
              ↓ XRPC
        nest (OAuth BFF)  +  mls-ds (chat.catbird.blue)
```

Startup path (`init_service()` in `main.rs`; mirrored in `catmos_tui::run()`):
1. `Config::load()` → resolve `default_account` DID (errors if none — run `catmos login`).
2. Open per-account encrypted SQLite (`catmos.db`) with a per-DID key from `mls::context::get_or_create_db_key(did)`.
3. `restore_saved_auth(&db, did)` → restore + validate the saved session.
4. `MlsManager::new(mls_dir, did)` → install per-DID content-root key, wire OpenMLS.
5. Build `ChatService` (sync loop, WebSocket).

Auth (`catmos-core/src/auth/`):
- **OAuth (default):** loopback flow through `nest` — opens a browser to `{nest_url}/auth/login`, captures the callback on `127.0.0.1:{port}`, then `GET {nest_url}/auth/session`. Persists `nest_url` + session cookie in the DB.
- **App-password (`--app-password`):** direct ATProto session via handle + app password (read with `rpassword`).

Default endpoints (`storage/config.rs`, overridable via `config.toml`):
- `nest_url = "https://api.catbird.blue"`
- `mls_url  = "https://chat.catbird.blue"`

## Relationship to catbird-mls

- This is the only client that uses `mls-orchestrator` as a **native Rust path dependency** — no UniFFI (iOS), no WASM (web), no Tauri command bridge (desktop). Calls go straight into `catbird_mls`.
- Changes to the shared MLS API and generated Petrel types affect the CLI. Check the pinned sibling revisions with `scripts/check-canonical-sibling-provenance.sh`.
- OpenMLS crypto / recovery policy / sync logic live in `catbird-mls`; this workspace owns CLI/TUI UX, storage coordination, auth, and config.

## Storage & Logs

On **macOS**, `dirs::config_dir()` and `dirs::data_dir()` both resolve to `~/Library/Application Support/`, so everything lives under one tree (the in-code comments saying `~/.config` / `~/.local/share` are the Linux/XDG case — accurate only on Linux):

```
~/Library/Application Support/catmos-cli/        (macOS)   |  ~/.config/catmos-cli + ~/.local/share/catmos-cli (Linux/XDG)
  ├─ config.toml                  # server URLs, UI prefs, default_account DID
  ├─ catmos.log                   # TUI log file (CLI logs to stderr instead)
  ├─ aliases.json
  ├─ mls/                         # OpenMLS storage + per-DID content-root keys
  └─ accounts/<sha256(did)[..16]>/catmos.db   # per-account SQLCipher DB
```

- Per-account isolation: DB dir name is the first 16 hex chars of `sha256(did)`. The DB is SQLCipher-encrypted (`libsqlite3-sys` with `bundled-sqlcipher`); the key is derived/stored per DID and the OS keyring is used (`keyring` crate, apple-native / linux-native).
- **Logging:** default filter is `warn,catmos=info,catmos_core=info,catmos_core::chat=debug,catmos_tui=info,openmls=off,...`. Override with `RUST_LOG`. In **TUI mode** logs go to `catmos.log` (terminal is owned by ratatui); in **CLI mode** logs go to **stderr**. The `log` crate (openmls internals) is bridged into `tracing` via `tracing_log`.

## Known Issues / Gotchas

- **MLS group-joining blocker (Apr 2026, runtime-unverified).** Session memory `project_catmos_cli_status.md` records a "cannot join group" history. The join path is in `catmos-core/src/mls/onboarding.rs` (base64 Welcome processing + external-commit join + auto-join on device registration). Do **not** assert it's fixed or still broken without running it; pull that memory rather than re-diagnosing from scratch.
- **`catmos` vs top-level `catmos/`** — don't confuse the bin crate (`catmos-cli/catmos/`) with the desktop Tauri app (`../catmos/`).
- **No `Cargo.lock` / no `.env` committed** (`.gitignore` excludes `Cargo.lock`); config is `config.toml`, not env vars (except `RUST_LOG` and the CMake var).
- **Blocking a user leaves shared MLS groups** (`block add` prompts first); **unblocking does not rejoin** — MLS requires a fresh invite.
- Strip ANSI from captured TUI output before analysis: `sed 's/\x1b\[[0-9;]*[mGKH]//g'`.

## Coding Style

- Standard Rust: run `cargo fmt` + `cargo clippy --all-targets` before committing.
- Commit prefix convention (workspace-wide): scoped imperative, e.g. `catmos-cli: Fix convo create after CreateConvo regen`.
- Don't hand-edit generated ATProto types — fix the canonical Petrel or PetrelCatbird lexicon source and regenerate, then reconcile consumers here.
- This is a jj-colocated git repo (`cd catmos-cli` before any VCS op); prefer `jj` for routine work, `git` for hooks/signing.
