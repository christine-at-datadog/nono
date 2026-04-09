<div align="center">

<img src="assets/nono-logo.png" alt="nono logo" width="600"/>

<p>
  From the creator of
  <a href="https://sigstore.dev"><strong>Sigstore</strong></a>
  <br/>
  <sub>The standard for secure software attestation, used by PyPI, npm, brew, and Maven Central</sub>
</p>
<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://github.com/always-further/nono/actions/workflows/ci.yml"><img src="https://github.com/always-further/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/></a>
  <a href="https://docs.nono.sh"><img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/></a>
</p>
<p>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
  </a>
  <a href="https://github.com/marketplace/actions/agent-sign">
    <img src="https://img.shields.io/badge/Secure_Action-agent--sign-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="agent-sign GitHub Action"/>
  </a>
</p>

</div>

> [!WARNING]
> Early alpha -- not yet audited for production use. Active development may cause breakage. Please don't point a coding agent at the repo and raise large LLM-generated security issues, we likely already know about them; instead ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

---

nono wraps any AI agent or process in a kernel-isolated sandbox in seconds. No hypervisor. No infrastructure required. A single binary, zero added latency, and flexible enough to fit a solo developer's workflow or a fleet of agents running at scale in production.

**Platform support:** macOS, Linux, and [WSL2](https://nono.sh/docs/cli/internals/wsl2). Native Windows coming soon.

**Install:**
```bash
brew install nono
```

Other options in the [Installation Guide](https://docs.nono.sh/cli/getting_started/installation).

---

## Latest News

**Detach and reattach to sandboxed agents** -- Run agents in the background with `nono run --detach`, reconnect with `nono attach`. Includes `nono ps`, `nono stop`, and `nono inspect`. ([#526](https://github.com/always-further/nono/pull/526))

**WSL2 support** -- Auto-detection with ~84% feature coverage out of the box. Run `nono setup --check-only` to see what's available. ([#522](https://github.com/always-further/nono/pull/522))

**Portable capability manifests** -- Export fully-resolved sandbox configs with `nono policy show <profile> --format manifest` for CI/Kubernetes deployment. ([#534](https://github.com/always-further/nono/pull/534))

**API endpoint filtering** -- Control which endpoints agents can reach with L7 filtering: `--allow-endpoint 'github:GET:/repos/*/issues/**'`. ([#513](https://github.com/always-further/nono/pull/513))

**Custom CAs and file-based credentials for k8s** -- `tls_ca` for self-signed endpoints ([#548](https://github.com/always-further/nono/pull/548)), `file://` URIs for mounted secrets ([#552](https://github.com/always-further/nono/pull/552)).

[All updates](https://github.com/always-further/nono/discussions/categories/announcements)

---

## Quick Start

```bash
# Any CLI agent -- just put your command after --
$ nono run --profile claude-code -- claude

# or with tmux style multiplexer and atomic snapshots
$ nono run --detached --profile claude-code --rollback -- claude
Started detached session 7a6a652f7273fe60.
Attach with: nono attach 7a6a652f7273fe60

# Any given command
nono run -- python3 my_agent.py
nono run --read /data -- npx @modelcontextprotocol/server-filesystem /data
nono run --profile codex -- codex
```

Built-in profiles for [Claude Code](https://docs.nono.sh/cli/clients/claude-code), [Codex](https://docs.nono.sh/cli/clients/codex), [OpenCode](https://docs.nono.sh/cli/clients/opencode), [OpenClaw](https://docs.nono.sh/cli/clients/openclaw), and [Swival](https://docs.nono.sh/cli/clients/swival) -- or [define your own](https://docs.nono.sh/cli/features/profiles-groups).

## Library

The core is a Rust library that can be embedded into any application. Policy-free -- it applies only what clients explicitly request.

```rust
use nono::{CapabilitySet, Sandbox};

let mut caps = CapabilitySet::new();
caps.allow_read("/data/models")?;
caps.allow_write("/tmp/workspace")?;

Sandbox::apply(&caps)?;  // Irreversible -- kernel-enforced from here on
```

#### <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg" width="18" height="18" alt="Python"/> Python — [nono-py](https://github.com/always-further/nono-py)

```python
from nono_py import CapabilitySet, AccessMode, apply

caps = CapabilitySet()
caps.allow_path("/data/models", AccessMode.READ)
caps.allow_path("/tmp/workspace", AccessMode.READ_WRITE)

apply(caps)  # Apply CapabilitySet
```

#### <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/typescript/typescript-original.svg" width="18" height="18" alt="TypeScript"/> TypeScript — [nono-ts](https://github.com/always-further/nono-ts)

```typescript
import { CapabilitySet, AccessMode, apply } from "nono-ts";

const caps = new CapabilitySet();
caps.allowPath("/data/models", AccessMode.Read);
caps.allowPath("/tmp/workspace", AccessMode.ReadWrite);

apply(caps);  // Irreversible — kernel-enforced from here on
```

---

## Features

### Kernel-Enforced Sandbox

nono applies OS-level restrictions that cannot be bypassed or escalated from within the sandboxed process. Permissions are defined as capabilities granted before execution -- once the sandbox is applied, it is irreversible. All child processes inherit the same restrictions.

| Platform | Mechanism | Minimum Kernel |
|----------|-----------|----------------|
| macOS | Seatbelt | 10.5+ |
| Linux | Landlock | 5.13+ |

```bash
# Grant read to src, write to output — everything else is denied by the kernel
nono run --read ./src --write ./output -- cargo build
```

### Credential Injection

Two modes: **proxy injection** keeps credentials entirely outside the sandbox — the agent connects to `localhost` and the proxy injects real API keys into upstream requests. **Env injection** loads secrets from the OS keystore, 1Password, or Apple Passwords and injects them as environment variables before the sandbox locks.

```bash
# Proxy mode — agent never sees the API key, even in its own memory
nono run --network-profile claude-code --proxy-credential openai -- my-agent

# Env mode — simpler, but secret is in the process environment
nono run --env-credential openai_api_key --allow-cwd -- my-agent

# 1Password — map URI reference to destination env var
nono run --env-credential-map 'op://Development/OpenAI/credential' OPENAI_API_KEY --allow-cwd -- my-agent

# Apple Passwords (macOS) — map URI reference to destination env var
nono run --env-credential-map 'apple-password://github.com/alice@example.com' GITHUB_PASSWORD --allow-cwd -- my-agent
```

### Agent SKILL Provenance and Supply Chain Security

Instruction files (SKILLS.md, CLAUDE.md, AGENTS.md, AGENT.MD) and associated artifacts such as scripts are a supply chain attack vector. nono cryptographically signs and verifies them using Sigstore attestation with DSSE envelopes and in-toto / SLSA style statements. It supports keyed signing (system keystore) and keyless signing (OIDC via GitHub Actions + Fulcio + Rekor). Upon execution, nono verifies the signature, checks the signing certificate against trusted roots, and validates the statement predicates (e.g. signed within the last 30 days, signed by a trusted maintainer).

<p align="center">
  <a href="https://github.com/marketplace/actions/nono-attest">
    <img src="https://img.shields.io/badge/GitHub_Action-nono--attest-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="nono-attest GitHub Action"/>
  </a>
</p>

Sign instruction files directly within GitHub Actions workflows. Users can then verify that files originate from the expected repository and branch, signed by a trusted maintainer.

#### Marketplace Skill Verification

Marketplace plugins installed to `~/.claude/plugins/` (prompt files, hook scripts, config) are verified as signed units before the agent can read or execute them. Each plugin directory contains a `skill-manifest.json` declaring all files, entry points, and hooks. The entire directory is signed as a multi-subject in-toto attestation with a skill-specific predicate type.

```bash
# Sign a plugin directory
nono trust sign-skill ~/.claude/plugins/my-plugin

# Verify against a trust policy
nono trust verify-skill ~/.claude/plugins/my-plugin --policy trust-policy.json
```

**Pre-exec scanning:** before the agent starts, nono discovers all plugin directories and verifies each one. Verified plugins get read-only sandbox access. Unverified or tampered plugins are denied — on macOS via Seatbelt deny rules, on Linux by exclusion from the Landlock allow-list.

**Runtime gating:** in supervised mode, the skill interceptor checks every file access against the verification cache. Files within verified skill directories are auto-granted read access. Files within unverified directories are auto-denied without prompting.

**Security properties:**

- **No TOFU** — plugins must have valid signatures from trusted publishers on first encounter
- **Predicate isolation** — skill bundles use a distinct predicate type, preventing cross-use with instruction file bundles
- **Directory completeness** — extra files on disk not in the manifest are rejected as tampering
- **Digest integrity** — every file is SHA-256 checked against the signed manifest; post-signing modifications are detected
- **Entry point containment** — manifest paths must resolve within the skill directory; symlinks pointing outside are rejected

### Network Filtering

Allowlist-based host filtering via a local proxy. The sandbox blocks all direct outbound connections — the agent can only reach explicitly allowed hosts. Cloud metadata endpoints are hardcoded as denied.

```bash
nono run --allow-proxy api.openai.com --allow-proxy api.anthropic.com -- my-agent

# Keep the claude-code profile, but allow unrestricted network for this session
nono run --profile claude-code --allow-net -- claude
```

### Supervisor and Capability Expansion

On Linux, seccomp user notification intercepts syscalls when the agent needs access outside its sandbox. The supervisor prompts the user, then injects the file descriptor directly — the agent never executes its own `open()`. Sensitive paths are never-grantable regardless of approval.

```bash
nono run --rollback --supervised --profile claude-code --allow-cwd -- claude
```

### Undo and Snapshots

Content-addressable snapshots of your working directory taken before and during sandboxed execution. SHA-256 deduplication and Merkle tree commitments for integrity verification. Interactively review and restore individual files or the entire directory. Known regenerable directories (`.git`, `target`, `node_modules`, etc.) and directories with more than 10,000 files are auto-excluded from snapshots to prevent hangs on large projects.

```bash
# Zero-flag usage — auto-excludes large/regenerable directories
nono run --rollback --allow . -- npm test

# Force-include an auto-excluded directory
nono run --rollback --rollback-include target -- cargo build

# Exclude a custom directory from rollback
nono run --rollback --rollback-exclude vendor -- go test ./...

# Disable rollback entirely
nono run --no-rollback --allow . -- npm test

nono rollback list
nono rollback restore
```

### Composable Policy Groups

Security policy defined as named groups in a single JSON file. Profiles reference groups by name — compose fine-grained policies from reusable building blocks.

```json
{
  "deny_credentials": {
    "deny": { "access": ["~/.ssh", "~/.gnupg", "~/.aws", "~/.kube"] }
  },
  "node_runtime": {
    "allow": { "read": ["~/.nvm", "~/.fnm", "~/.npm"] }
  }
}
```

### Destructive Command Blocking

Dangerous commands (`rm`, `dd`, `chmod`, `sudo`, `scp`) are blocked before execution. Override per invocation with `--allow-command` or permanently via `allowed_commands` in a profile. Block additional commands with `add_deny_commands`.

```bash
$ nono run --allow-cwd -- rm -rf /
nono: blocked command: rm

# Override per invocation
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt

# Override via profile
# { "security": { "allowed_commands": ["rm"] } }
nono run --profile my-profile -- rm /tmp/old-file.txt

# Block specific commands in a profile (add_deny_commands) — pairs with add_deny_access for sockets
# { "policy": { "add_deny_access": ["/var/run/docker.sock"], "add_deny_commands": ["docker", "kubectl"] } }
nono run --profile no-docker -- claude
```

> [!WARNING]
> Command blocking is defense-in-depth layered on top of the kernel sandbox. Commands can bypass this via `sh -c '...'` or wrapper scripts — the sandbox filesystem restrictions are the real security boundary.

### Themes

nono ships with multiple color themes inspired by popular terminal palettes. The default is **Catppuccin Mocha**.

| Theme | Description |
|-------|-------------|
| `mocha` | Catppuccin Mocha -- warm dark (default) |
| `latte` | Catppuccin Latte -- clean light |
| `frappe` | Catppuccin Frappe -- muted dark |
| `macchiato` | Catppuccin Macchiato -- deep vivid dark |
| `tokyo-night` | Tokyo Night -- cool blues and purples |
| `minimal` | Grayscale with orange accent |

```bash
# Per invocation
nono --theme tokyo-night run --allow-cwd -- my-agent

# Via environment variable
export NONO_THEME=latte

# Via config file (~/.config/nono/config.toml)
# [ui]
# theme = "frappe"
```

### Command Mediation

Intercept specific CLI commands inside the sandbox and apply policy before they execute. A minimal shim binary (`nono-shim`) is placed in the sandbox's `PATH` for each mediated command. When the agent invokes the command, the shim forwards the call over a Unix socket to the unsandboxed parent process, which applies policy and responds — the sandboxed process never touches the real binary or its credentials.

**Intercept actions:**

- **`respond`** — return a static response immediately, without running the real binary.
- **`capture`** — run the real binary (or a `script` via `sh -c`) and return a nonce (phantom token) to the sandbox. The real value is substituted at passthrough time, so the agent can use the token in subsequent calls without ever seeing the real secret.
- **`approve`** — run the real binary (or a `script` via `sh -c`) and return the actual output to the sandbox. Typically paired with `"admin": true` to gate sensitive-but-non-secret commands behind biometric/password approval.

**Env var blocking:** named environment variables are stripped from the child process at session start, preventing the sandbox from reading raw credentials.

**Per-command sandboxing:** each mediated command can optionally restrict the filesystem paths and network access it is allowed when the parent execs it in passthrough. This is an opt-in, per-command setting.

**Allowed commands (`allow_commands`):** when a mediated command (e.g. `gh`) runs inside its per-command sandbox, subprocesses normally route through shims. `allow_commands` lets specific commands (e.g. `ddtool`) execute directly as real binaries inside that sandbox. A filtered shim directory is created containing shims only for commands _not_ in the allow list. The allowed commands' binary directories are added to PATH and granted read access in the Seatbelt profile. Their output stays within the per-command sandbox — network restrictions prevent credential leakage.

**Socket security:** the mediation socket is protected by two layers. The session directory is created `0700` and the socket itself `0600`, so other local users cannot connect. Within the same user, a 256-bit random session token is injected into the sandboxed child as `NONO_SESSION_TOKEN`; every shim request must include it. Requests exceeding 1 MiB are dropped before allocation; requests with a missing or incorrect token are dropped after reading.

**Per-rule admin gate:** set `"admin": true` on any intercept rule to require native macOS biometric or password authentication before the action executes. Requires `nono-approve` installed alongside nono.

**YOLO mode (macOS):** the `nono-privileges` menu bar app lets you temporarily suspend all mediation for a session — authenticated via Touch ID and active for a configurable window (default 10 minutes). During this window all shim requests are forwarded as raw passthroughs. An audit log is written to the session directory.

```mermaid
%%{init: {'flowchart': {'curve': 'basis'}}}%%
flowchart TD
    User(["👤 User"])

    subgraph host["Host Process (unsandboxed)"]
        direction TB
        HostProc["Process Manager"]
        Seatbelt["Seatbelt Policy"]
        MedServer["Mediation Server"]
        Broker["Token Broker"]
        MediatedBinHost["Mediated Binary (host)"]
    end

    subgraph sb["Agent Sandbox"]
        direction TB
        Agent["Agent Process"]
        BlockedBin["🚫 Original Binary (denied)"]
        Shim["nono-shim (intercepts)"]
        FreeBin["Allowed Binaries"]
    end

    subgraph sb2["Binary Sandbox (optional)"]
        MediatedBinSB["Mediated Binary"]
        AllowedBin["Allowed Binary (direct)"]
    end

    User -->|"nono run"| HostProc
    HostProc -->|"applies policy"| Seatbelt
    HostProc -->|"starts"| MedServer
    HostProc -->|"forks into"| Agent
    Seatbelt -.->|"enforces"| sb

    Agent -->|"execve original binary"| BlockedBin
    Agent -->|"execve via PATH"| Shim
    Agent -->|"execve allowed cmd"| FreeBin
    Shim -->|"request"| MedServer
    MedServer -->|"capture / respond / approve"| Broker
    MedServer -->|"passthrough"| MediatedBinHost
    MedServer -->|"passthrough"| MediatedBinSB
    MediatedBinSB -->|"allow_commands"| AllowedBin
    Broker -.->|"nonce lookup"| MedServer
    MediatedBinHost -->|"output"| MedServer
    MediatedBinSB -->|"output"| MedServer
    AllowedBin -->|"output"| MediatedBinSB
    MedServer -->|"stdout + exit code"| Shim
    Shim -->|"stdout"| Agent

    style host fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style sb fill:#fef3c7,stroke:#f59e0b,color:#78350f
    style sb2 fill:#fef9c3,stroke:#ca8a04,color:#713f12
    style User fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style Seatbelt fill:#ede9fe,stroke:#7c3aed,color:#3b0764
    style Broker fill:#fce7f3,stroke:#ec4899,color:#831843
    style MedServer fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e
    style MediatedBinHost fill:#f1f5f9,stroke:#64748b,color:#1e293b
    style MediatedBinSB fill:#f1f5f9,stroke:#64748b,color:#1e293b
    style AllowedBin fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style FreeBin fill:#f0fdf4,stroke:#22c55e,color:#14532d
    style BlockedBin fill:#fee2e2,stroke:#dc2626,color:#7f1d1d
    style Shim fill:#fff7ed,stroke:#ea580c,color:#431407
    style Agent fill:#fefce8,stroke:#ca8a04,color:#422006
    style HostProc fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f

    linkStyle 5 stroke:#dc2626,stroke-width:2px,stroke-dasharray:5
```

#### Example: Credential Capture with Nonce Tokens

The agent calls `gh auth token` — the shim intercepts it, the real binary runs in the unsandboxed parent, and the sandbox receives a nonce (`nono_abc123...`) instead of the real token. When the agent later calls `gh api user`, the nonce is promoted to the real value at passthrough time.

```json
{
  "mediation": {
    "env": { "block": ["GH_TOKEN", "GITHUB_TOKEN"] },
    "commands": [
      {
        "name": "gh",
        "intercept": [
          {
            "args_prefix": ["auth", "token"],
            "action": { "type": "capture" }
          }
        ]
      }
    ]
  }
}
```

#### Example: Static Responses

Return a canned response without running the real binary. The agent sees a realistic output but no real operation occurs.

```json
{
  "args_prefix": ["auth", "status"],
  "action": {
    "type": "respond",
    "stdout": "github.com\n  Logged in to github.com account kipz\n"
  }
}
```

#### Example: Admin-Gated Approval

Gate sensitive commands behind Touch ID / password via `nono-approve`. The `approve` action runs the real command and returns the actual output — unlike `capture`, no nonce wrapping occurs.

```json
{
  "args_prefix": ["ssh-key", "list"],
  "admin": true,
  "action": { "type": "approve" }
}
```

If the user denies the prompt, the shim returns exit code 126 and a "was not approved" message. If approved, the real output is returned to the sandbox.

#### Example: Per-Command Sandbox with `allow_commands`

Restrict `gh` to GitHub hosts only, but let it call `ddtool` directly inside its sandbox to fetch a token from the macOS Keychain. The `ddtool` binary runs as a real process (not through the shim) inside `gh`'s network-restricted sandbox — the token is used internally and never leaks to the primary sandbox.

```json
{
  "mediation": {
    "env": { "block": ["GH_TOKEN", "GITHUB_TOKEN"] },
    "commands": [
      {
        "name": "gh",
        "intercept": [
          { "args_prefix": ["auth", "token"], "action": { "type": "capture" } }
        ],
        "sandbox": {
          "network": {
            "allowed_hosts": ["github.com", "*.github.com", "api.github.com"]
          },
          "fs_read": ["~/.config/gh", "~/Library/Keychains/login.keychain-db"],
          "allow_commands": ["ddtool"]
        }
      },
      {
        "name": "ddtool",
        "intercept": [
          { "args_prefix": ["auth", "github", "token"], "action": { "type": "capture" } }
        ]
      }
    ]
  }
}
```

How this works:

1. Agent calls `gh api user` — the shim forwards it to the mediation server.
2. The server execs the real `gh` binary inside a per-command Seatbelt sandbox (network restricted to `github.com`).
3. The `gh` wrapper internally calls `ddtool auth github token` — because `ddtool` is in `allow_commands`, it resolves to the real binary (no shim), reads the Keychain, and returns the token.
4. The wrapper sets `GH_TOKEN` and calls the real `gh` binary, which hits the GitHub API through the allowlisted proxy.
5. At the top level, `ddtool auth github token` called directly by the agent still routes through the shim and returns a nonce — credentials are never exposed to the sandbox.

#### Example: Full Profile

Combining all capabilities — credential capture, static responses, admin-gated approval, per-command sandboxing, and allowed commands:

```json
{
  "mediation": {
    "env": { "block": ["GH_TOKEN", "GITHUB_TOKEN"] },
    "commands": [
      {
        "name": "gh",
        "intercept": [
          {
            "args_prefix": ["auth", "token"],
            "action": { "type": "capture" }
          },
          {
            "args_prefix": ["auth", "status"],
            "action": {
              "type": "respond",
              "stdout": "github.com\n  Logged in to github.com account kipz\n"
            }
          },
          {
            "args_prefix": ["ssh-key", "list"],
            "admin": true,
            "action": { "type": "approve" }
          }
        ],
        "sandbox": {
          "network": {
            "allowed_hosts": ["github.com", "*.github.com", "api.github.com"]
          },
          "fs_read": ["~/.config/gh", "~/Library/Keychains/login.keychain-db"],
          "allow_commands": ["ddtool"]
        }
      },
      {
        "name": "ddtool",
        "intercept": [
          {
            "args_prefix": ["auth", "github", "token"],
            "action": { "type": "capture" }
          }
        ]
      }
    ]
  }
}
```

### Audit Trail

Every supervised session automatically records command, timing, exit code, network events, and cryptographic snapshot commitments as structured JSON. Opt out with `--no-audit`.

```bash
nono audit list
nono audit show 20260216-193311-20751 --json
```

## Quick Start

### Homebrew (macOS/Linux)

```bash
brew install nono
```

### Other Linux Install Options

See the [Installation Guide](https://docs.nono.sh/cli/getting_started/installation) for prebuilt binaries and package manager instructions.

### From Source

See the [Development Guide](https://docs.nono.sh/cli/development/index) for building from source.

## Supported Clients

nono ships with built-in profiles for popular AI coding agents. Each profile defines audited, minimal permissions.

| Client | Profile | Docs |
|--------|---------|------|
| **Claude Code** | `claude-code` | [Guide](https://docs.nono.sh/cli/clients/claude-code) |
| **Codex** | `codex` | [Guide](https://docs.nono.sh/cli/clients/codex) |
| **OpenCode** | `opencode` | [Guide](https://docs.nono.sh/cli/clients/opencode) |
| **OpenClaw** | `openclaw` | [Guide](https://docs.nono.sh/cli/clients/openclaw) |
| **Swival** | `swival` | [Guide](https://docs.nono.sh/cli/clients/swival) |

Custom profiles can [extend built-in ones](https://docs.nono.sh/cli/features/profiles-groups) with `"extends": "claude-code"` (or multiple: `"extends": ["claude-code", "node-dev"]`) to inherit all settings and add overrides. nono is agent-agnostic and works with any CLI command. See the [full documentation](https://docs.nono.sh) for usage details, configuration, and integration guides.

## Projects using nono

| Project | Repository |
|---------|------------|
| **claw-wrap** | [GitHub](https://github.com/dedene/claw-wrap) |

## Architecture

nono is structured as a Cargo workspace:

- **nono** (`crates/nono/`) -- Core library. A policy-free sandbox primitive that applies only what clients explicitly request.
- **nono-cli** (`crates/nono-cli/`) -- CLI binary. Owns all security policy, profiles, hooks, and UX.
- **nono-shim** (`crates/nono-shim/`) -- Minimal shim binary used by command mediation. Placed in the sandbox PATH for each mediated command; forwards invocations to the parent mediation server over a Unix socket.
- **nono-approve** (`crates/nono-approve/`) -- Native macOS authentication binary. Invoked by the mediation server when an intercept rule sets `admin: true`; shows a biometric/password dialog via LocalAuthentication and returns exit code 0 (allow) or 1 (deny).
- **nono-privileges** (`apps/nono-privileges/`) -- macOS menu bar app for YOLO mode. Authenticates via Touch ID and sends enable/disable commands to the session's control socket.
- **nono-ffi** (`bindings/c/`) -- C FFI bindings with auto-generated header.

Language-specific bindings are maintained separately:

| Language | Repository | Package |
|----------|------------|---------|
| Python | [nono-py](https://github.com/always-further/nono-py) | PyPI |
| TypeScript | [nono-ts](https://github.com/always-further/nono-ts) | npm |

## Contributing

We encourage using AI tools to contribute. However, you must understand and carefully review any AI-generated code before submitting. Security is paramount. If you don't understand how a change works, ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Follow the process in our [Security Policy](https://github.com/always-further/nono/security).

## License

Apache-2.0
