# Experimental agent sandbox runner

`ff run` is an experimental Linux wrapper for running multiple untrusted agents
on one VM without placing Forcefield or Hive credentials in their processes. It
combines an operator-owned profile, a host-side capability broker, a transient
systemd user service, and a bubblewrap sandbox. The Forcefield credential
gateway may remain on a separate trusted macOS host: the Linux runner consumes
a protected, workload-bound capability file and fetches its live service
manifest from that gateway. This is useful process isolation and authority
separation; it is not yet a VM-grade or multi-tenant boundary.

Use it to give each agent a different Forcefield role and Hive messaging ACL.
Keep deterministic external-system writers, such as a Linear bridge, outside
the worker sandboxes. A worker should return a proposal or artifact to the lead;
it should not receive the bridge's Linear credential.

## Status and trust boundary

The runner is an experimental Linux MVP and has not had an independent security
review. Its unit tests run on supported build hosts, and the Linux code is
cross-compiled for amd64 and arm64. A real Debian end-to-end exercise with Hive
tmux sessions, Claude and Codex CLIs, systemd, bubblewrap, seccomp, streaming,
cancellation, and crash recovery is still required before production use.

The trusted computing base includes:

- the host kernel, systemd user manager, bubblewrap, host `ff` binary, and
  Forcefield service;
- the runner-host operator and processes outside the sandbox that can read its
  capability and TLS files;
- the runner profile, prepared root filesystem, host TLS material, and any
  explicitly mounted host files;
- the configured Forcefield and optional Hive origins.

The agent command, its model output, dependencies it invokes, and writable
workspace contents are untrusted. The sandbox does not receive the minted
`ff_` bearer, mTLS private key, upstream provider credentials, or real Hive
bearer. The mounted Unix socket is its capability to reach a narrow broker.

```text
trusted host
----------------------------------------------------------------------------
Hive manager environment                 protected capability file
personal MSG token, never CONTROL                    |
             |                                        | short-lived ff_ token
             v                                        v
        ff run supervisor ----------------> host-side runner broker
        profile + state                    manifest-derived route/token injection
        systemd lifecycle                  optional Hive message ACL/token
             |                                        |
             | systemd --user service                 | pinned origins
             v                                        +--> macOS Forcefield --> APIs
        bubblewrap + cgroup + seccomp                  +--> Hive
        read-only rootfs
        private namespaces
        one workspace
             |
             v
untrusted agent --> sandbox loopback relay --> mounted 0600 Unix socket
----------------------------------------------------------------------------
```

All sandboxes currently map back to the same host UID. Mount namespaces keep
one sandbox from seeing another sandbox's broker socket or workspace unless an
operator exposes them, but a process that escapes to the host UID crosses the
entire boundary. There is not yet a unique host UID or `SO_PEERCRED` identity
per sandbox. Do not treat this as hostile-tenant isolation.

## Prerequisites

The host must provide all of the following:

1. Linux on amd64 or arm64. Other architectures fail closed because they do not
   have an audited runner seccomp policy.
2. A reachable systemd user manager. Both `systemd-run --user` and
   `systemctl --user` must work in the environment used to launch `ff run`.
3. Bubblewrap and kernel support for unprivileged user namespaces and seccomp
   filter synchronization. The runner does not fall back to a weaker backend.
   Host launch helpers are resolved only from trusted `/usr/bin` or `/bin`
   locations, not an agent-controlled `PATH`.
4. A reachable Forcefield gateway. For the recommended split-host deployment,
   provision a private `0600` token file on the runner host. Mint it on the
   trusted Forcefield host for the runner's IP or mTLS workload and keep its TTL
   no longer than the intended sandbox lifetime. The runner authenticates the
   live capability manifest before launch and retains the bearer outside the
   sandbox. Same-host deployments may omit `token_file` and continue to use
   `role`, `workload`, and `token_ttl` with the private admin socket.
5. A prepared, non-root root filesystem. It must be an absolute directory that
   is not group- or world-writable and must contain the agent runtime plus the
   operator-trusted sandbox init at the fixed path `/usr/local/bin/ff`. The
   runner does not accept a worker-selectable replacement, and rejects a
   workspace or read-only mount that could shadow it. Dynamic libraries, CA
   data, shells, and tools required by the agent must already be present. Each
   profile rootfs must be a strict child of the configured
   `rootfs_directory`.
6. A separate existing workspace directory for every concurrently running
   agent. Workspaces are read-only by default. A profile may set
   `workspace_read_only: false` only for a dedicated, disposable worktree or
   checkout; never mount a shared writable parent containing another agent's
   workspace. The selected runtime workspace must be a strict child of
   `workspace_directory`.
7. For an `mtls-spki:` workload, a host-side client certificate and key whose
   leaf SPKI matches the configured workload. Generate the canonical identity
   with `ff identity --cert CLIENT_CERT`.

Both `--config` and `--profiles` must name clean absolute files outside the
workspace. Their complete path ancestry must be symlink-free, owned by root or
the effective user, and not group- or world-writable, apart from an ordinary
root-owned sticky directory. The final files must be regular and not
group- or world-writable. The defaults are
`/etc/forcefield/forcefield.yaml` and
`/etc/forcefield/forcefield-runner.yaml`; do not copy either into an agent
checkout.

The profile YAML decoder is strict: unknown fields, multiple documents, invalid
paths, and unsafe environment entries are rejected. Provision the global
runner directory roots before launch. At runtime, their complete ancestry and
the selected rootfs, workspace, and read-only sources must resolve without
symlinks through root- or runner-owned directories that are not group- or
world-writable, apart from an ordinary root-owned sticky ancestor.

## Configure profiles

Start with [the runner profile template](../examples/forcefield-runner.yaml).
The Forcefield `role` named by a profile is the agent's service authority. This
is how two agents on the same VM can have different API permissions: launch
each with an operator-selected profile backed by a different narrow role. Do
not let an untrusted agent edit the profile file or the host-side launch
wrapper.

The global filesystem fields establish where any profile may source host
content:

| Field | Purpose |
|---|---|
| `state_directory` | Private per-run records and broker sockets. |
| `rootfs_directory` | Trusted parent whose strict descendants may be selected as profile root filesystems. |
| `workspace_directory` | Trusted parent whose strict descendants may be selected with `--workspace`. |
| `read_only_source_directories` | Optional list of up to 32 operator-curated roots from which a profile may expose a read-only file or directory. |

These four directory classes must be clean, non-root, non-system absolute paths.
Every configured root must be unique and non-overlapping with every other root:
none may equal, contain, or sit inside another. Sibling roots beneath a common
trusted parent are valid. In particular, host homes, `/run/user`, `/etc`,
`/usr`, device and process filesystems, and other protected system trees cannot
be used as runner roots. This prevents a profile from selecting an arbitrary
host home or socket-bearing runtime directory merely by marking it read-only.
Keep approved read-only roots deliberately small, immutable where practical,
and free of sockets or credential caches.

The important per-profile fields are:

| Field | Purpose |
|---|---|
| `token_file` | Recommended split-host mode: protected short-lived bearer minted by the trusted Forcefield host and never mounted into the sandbox. |
| `role`, `workload`, `token_ttl` | Alternative same-host mode: mint through the local Forcefield admin socket. Mutually exclusive with `token_file`. |
| `forcefield_url` | Exact Forcefield origin. It must match `server.advertised_base_url`, or the derived local listener when no advertised URL is set. |
| `ca_cert`, `client_cert`, `client_key` | Host paths used only by the broker. Client material is required for an mTLS workload and forbidden for an IP workload. |
| `rootfs` | Host root filesystem mounted read-only as `/`; it must be strictly below `rootfs_directory`. |
| `workspace_target` | Absolute location of the one workspace inside the sandbox; defaults to `/workspace`. |
| `workspace_read_only` | Mount the workspace read-only; defaults to `true`. Set `false` only for a dedicated disposable worktree. |
| `read_only_mounts` | Additional explicit host file or directory exposures. Each source must be at or below an approved `read_only_source_directories` root; protected host-path exposure and target overlaps are rejected. |
| `broker_socket` | Fixed socket location inside the sandbox; defaults to `/run/forcefield/broker.sock`. |
| `broker_listen` | Sandbox-only loopback listener; defaults to `127.0.0.1:7902`. Use port `0` to allocate a collision-free port per run, especially with `share_network: true`. |
| `environment` | Secret-free inherited names and operator-set values after a complete environment clear. |
| `hive` | Optional pinned Hive origin, network, recipient, message-kind, broadcast, and discovery policy. |
| `resources` | systemd memory, process-count, CPU, and hard runtime ceilings. |

Configuration validation first checks that every profile rootfs is lexically
inside `rootfs_directory` and every read-only source is inside an approved
source root. Before minting, runtime validation resolves the actual paths,
rechecks strict rootfs and workspace containment, rechecks each read-only source
against its approved root, and verifies trusted ancestry, ownership, and modes.

The runner also verifies that the rootfs, workspace, and every read-only mount
source do not overlap the runner state directory, either operator
configuration, the Forcefield admin socket, TLS private key, token or audit
store, configured exec secret helper, or runner client key. Mount targets under
`/run` are forbidden. Under `/home`, only an individual regular file beneath
`/home/agent` may be mounted. That exception is for sanitized, read-only trust
configuration; never mount a host credential home, `.ssh` directory, provider
login state, socket, token cache, or general home directory. Read-only mount
targets also cannot overlap one another, the workspace, private system paths,
or the broker socket.

The profile's `forcefield_url` is the trusted host-side destination. Inside the
sandbox, `FORCEFIELD_URL` is always set to the loopback broker URL. The broker
accepts only service routes present in the freshly minted role grant, discards
caller-supplied credential headers, and installs the hidden Forcefield bearer
using the configured service's client-auth carrier.

Some SDKs refuse to start without a conventional API-key variable. A
secret-shaped name in `environment.set` is accepted only when its literal value
is the fixed non-secret marker `forcefield-runner-broker`. Pair that marker with
a base URL under the local broker, for example:

```yaml
environment:
  set:
    OPENAI_BASE_URL: http://127.0.0.1:7902/openai
    OPENAI_API_KEY: forcefield-runner-broker
    ANTHROPIC_BASE_URL: http://127.0.0.1:7902/anthropic
    ANTHROPIC_API_KEY: forcefield-runner-broker
```

The marker has no provider or Forcefield authority. The local broker replaces
it before calling Forcefield, and Forcefield performs its normal policy check
before injecting the real provider credential. The base path must match the
path-routed service granted to the profile's role. Never point these variables
at a provider origin. Reserved Forcefield and Hive names cannot be overridden,
and secret-shaped variables cannot be inherited from the host.

## Launch one agent

All paths following `--` are paths in the sandbox, not host executable paths.
The sandbox init is always the operator-trusted `/usr/local/bin/ff` from the
prepared rootfs. It is deliberately not configurable on the command line.

```sh
ff run \
  --profiles /etc/forcefield/forcefield-runner.yaml \
  --profile codex-worker \
  --agent codex-2 \
  --workspace /srv/agent-worktrees/codex-2 \
  -- /usr/local/bin/codex
```

`--agent` is the lowercase audit identity selected by the operator. It is a
name such as `codex-2`, not the full Hive address. For a profile without a
`hive` block, no Hive environment is required. The `--workspace` value above is
valid only because it is a strict descendant of the example's
`workspace_directory`.

For Hive, select this runner in the trusted spawn profile rather than making
the worker construct the wrapper command. The outer process must receive the personal
`HIVE_TOKEN`, canonical `HIVE_AGENT=name@host`, `HIVE_NET`, and `HIVE_ADDR`
created by Hive. `--agent` must match the name portion. Keep the command and
profile choice in trusted Hive/operator configuration rather than in a prompt
or worker-controlled script.

## Hive messaging boundary

For each Hive-enabled run, the supervisor holds one personal MSG token for the
canonical agent identity. It requires the outer `HIVE_NET` and `HIVE_ADDR` to
match the operator-owned profile. If a non-empty `HIVE_CONTROL_TOKEN` is
present, launch fails; configure Hive without CONTROL authority for sandboxed
workers.

The sandbox receives a local `HIVE_ADDR`, its fixed identity and network, and a
non-secret `HIVE_TOKEN=forcefield-runner-broker` marker. The host proxy accepts
only:

- a synthetic read-only `/hosts` response containing only the host already
  pinned by `HIVE_AGENT`;
- inbox reads and acknowledgments for the fixed actor;
- sends to an explicitly allowed recipient with an allowed `msg`, `ask`, or
  `answer` kind;
- agent discovery only when `allow_discovery: true`;
- `@all` only when `allow_broadcast: true`.

The synthetic `/hosts` response never reaches Hive and exposes no host-routing
table. It lets Hive's MCP client expand a bare local recipient consistently.
A bare name in `allow_to` is constrained to the actor's current host; use a
fully qualified address for a deliberately approved remote host.

Registration, deregistration, spawning, real host-routing or host mutation,
control operations, keys, direct delivery, process control, arbitrary Hive
routes, and caller-selected actors or networks are not proxied.

Assign work directly from the lead to one worker. Leave broadcast disabled.
Include the issue/job ID, expected source version, claim generation, acceptance
criteria, and reply address in the message, but understand that these are
protocol data: this runner does not implement atomic task claims or fencing. A
deterministic bridge must validate them before changing an external board.

## Isolation and workspace rules

The transient systemd user service applies `MemoryMax`, `MemorySwapMax=0`,
`TasksMax`, `CPUQuota`, `RuntimeMaxSec`, a five-second stop timeout with final
`SIGKILL`, `LimitNOFILE=1024`, `KillMode=control-group`,
`NoNewPrivileges` before starting bubblewrap. Bubblewrap supplies the sandbox's
private minimal `/dev` mount. The
host supervisor lowers its own soft `RLIMIT_NOFILE` to at most 256 before
opening the per-run broker. `RuntimeMaxSec` is derived from
`resources.wall_time`, so the user manager retains a hard deadline even if the
`ff run` supervisor is killed.

Bubblewrap clears the environment, drops capabilities, and by default unshares
all supported namespaces, giving the process private `/proc`, `/dev`, `/tmp`, `/run`, and
`/home`, mounts the prepared root read-only, and exposes only the selected
workspace, validated read-only mounts, and broker socket. General network
access is absent; a credentialless loopback relay can reach only the mounted
broker socket. The in-sandbox init then installs the runner seccomp denylist
before executing the agent. In addition to the privileged syscall denylist,
the filter rejects the `TIOCSTI` terminal-input injection request and permits
`socket()` only for `AF_UNIX`, `AF_INET`, and `AF_INET6`; other socket families
fail with `EPERM`. The private network namespace still prevents those Internet
families from reaching an external network—the loopback relay is the only
broker path.

An operator may set `share_network: true` on a trusted profile that must
authenticate directly to external services. This deliberately retains the host
network namespace while preserving the filesystem, cgroup, seccomp, and
Forcefield/Hive credential-broker boundaries. Do not enable it for hostile or
unknown workloads.

When launched from a terminal, `systemd-run --pty` provides a subordinate,
mediated controlling PTY and bubblewrap preserves it for agent TUIs and shell
job control. The seccomp `TIOCSTI` filter provides the terminal-injection
boundary without discarding the controlling terminal. Real Hive tmux sessions
with Claude and Codex CLIs still need the required Debian end-to-end validation.

The host broker limits simultaneous Unix connections, active requests, request
headers, request reads, idle connections, request bodies, upstream dialing,
TLS handshakes, and upstream response headers. It supports streamed model
responses: `text/event-stream` bodies are copied and flushed as chunks arrive
rather than buffered to completion.

Treat a writable workspace as authority. Agents share a host UID, so ordinary
host file ownership is not an inter-agent boundary. Isolation depends on
mounting exactly one workspace into each namespace. The safe default is
read-only. For an execution job that must edit files, explicitly set
`workspace_read_only: false` on a profile used only with a dedicated,
disposable worktree. Avoid shared writable mounts, and exchange patches or
artifacts through the lead/reviewer protocol. Swap is disabled for the sandbox
with `MemorySwapMax=0`, but the runner does not apply a workspace disk quota,
and systemd `MemoryMax` does not bound host disk growth. Put writable worktrees
on disposable bounded volumes or enforce host filesystem/project quotas before
enabling an execution profile.

Different Forcefield roles control API authority independently of filesystem
access. A normal worker role should not contain a Linear service grant. The
single deterministic Linear bridge can remain an unsandboxed trusted service,
or use a dedicated profile that no worker launch path can select.

## Lifecycle, stop, and recovery

One invocation follows this sequence:

1. Load and validate both configurations, the selected role, origin, workload
   identity, workspace, systemd tools, and optional Hive identity/ACL.
2. Mint one short-lived, non-delegable Forcefield token through the same-UID
   admin socket and immediately write a secret-free `starting` run record.
3. Start a private 0600 Unix-socket broker. The actual Forcefield and Hive
   bearers remain only in the supervisor.
4. Start a named `forcefield-agent-<sandbox-id>.service`, query its main process
   on a best-effort basis, then record `running`.
5. Wait for process exit, broker failure, the profile wall-time limit, or
   `SIGINT`, `SIGTERM`, or `SIGHUP` delivered to the supervisor.
6. Close the broker and cancel active requests, revoke the Forcefield token,
   always attempt to stop the named systemd unit and its entire control group,
   and write the final `exited` or `failed` record. The agent's real exit status
   is preserved.

For an immediate stop, signal the `ff run` supervisor, not only the worker PID.
The supervisor removes both broker paths to authority before stopping the
systemd service. A worker that ignores its own signal cannot continue using the
closed broker or revoked token, and systemd terminates the service's full
control group.

Run records are owner-only JSON files named `<sandbox-id>.json` in
`state_directory`. They contain the public token ID, profile digest, workspace,
granted service names, Hive identity, systemd unit, supervisor
(`systemd-run`) PID, best-effort systemd `MainPID`, status, timestamps, and exit
code. `MainPID` may be zero if the short-lived startup query loses a race; the
unit name is the teardown authority. Records never contain the bearer, command,
environment, or TLS key path.

There is no immediate crash-recovery daemon. If the supervisor receives
`SIGKILL`, its host-side broker dies immediately, so the sandbox loses both
Forcefield and Hive authority even though the minted Forcefield token remains
in the token store until revocation or TTL expiry. The transient unit may
continue local sandbox/workspace execution, but systemd stops it no later than
the profile's `RuntimeMaxSec`.

Inspect a stale run record, stop its recorded `unit` with
`systemctl --user stop`, and revoke its `token_id` with
`ff revoke --config ... --token-id ...`. Keep TTLs short and no longer than
operationally necessary. Tokens are not refreshed; an expired token stops API
authority but does not by itself stop a process before the systemd runtime
deadline.

## Recommended rollout

1. **Shadow mode.** Use mock or read-only Forcefield services, retain the
   default read-only workspace, disable Hive broadcast/discovery, and use direct
   messages only. Workers produce proposals; no bridge applies them.
2. **Limited autopilot.** Give each agent a separate writable worktree and a
   narrow role, with `workspace_read_only: false` only in that execution
   profile. Let a deterministic bridge apply only preapproved comments, labels,
   delegation, and started/review transitions after checking the current issue
   state and reviewer evidence.
3. **Full workflow.** Proceed only after Linux end-to-end tests, escape and stop
   drills, stale-run reconciliation, audit monitoring, rootfs update controls,
   and cross-model review are operating. Keep completion and destructive board
   changes behind the bridge's policy and any required human confirmation.

## Known limitations

- The host UID and all same-UID host processes are trusted. There is no unique
  per-sandbox host UID or peer-credential fencing yet.
- Bubblewrap shares the host kernel. This is not a microVM, hardware boundary,
  or hostile multi-tenant sandbox.
- Forcefield does not provision, sign, scan, update, or attest root filesystems
  and agent binaries.
- The recorded profile digest covers effective profile fields for correlation;
  it does not hash or attest rootfs contents, `/usr/local/bin/ff`, agent tools,
  mounted trust files, or either operator configuration. Content changes at the
  same paths do not change that digest.
- There is no persistent runner daemon, restart reconciliation, automatic
  stale-token revocation, or abandoned-systemd-service collector.
- The runner has no Linear integration, atomic task claim, fencing generation,
  deduplication ledger, reviewer gate, or workflow policy engine.
- The Hive proxy limits transport authority, recipients, and message shapes; it
  cannot prove that a message represents a current issue claim.
- Only one token is minted at start and it is never refreshed. Short TTLs
  reduce crash exposure but can end API access before a long job exits.
- Writable workspace disk quotas are not implemented. Use filesystem/project
  quotas or disposable bounded volumes; `MemoryMax` is not a host disk-growth
  limit. Sandbox swap is separately disabled with `MemorySwapMax=0`.
- Linux amd64/arm64 are the only intended targets, and a complete on-host Linux
  end-to-end and adversarial test pass is still outstanding.
- The mediated controlling PTY is designed to preserve shell job control and
  interactive TUI behavior while seccomp blocks `TIOCSTI`, but Hive tmux
  sessions and real Claude/Codex CLIs have not yet completed the required
  Debian end-to-end validation.
