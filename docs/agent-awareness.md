# Automatic agent capability awareness

An agent should not need a user to recite its grants. Forcefield provides an
authenticated, freshly generated projection of revision-current configured
grants, and the guest's agent runtime can inject that projection automatically.
This is a usability layer, not an authorization layer: Forcefield still
evaluates every request against the token, workload identity, current policy
and binding revisions, and remaining token lifetime.

The supplied Claude Code and Codex CLI integrations have three parts:

1. Administrator-managed `SessionStart` and `SubagentStart` hooks run `ff
   capabilities` in the runtime's hook format. The result is inserted into
   every new agent's context, including on resume/compaction and for spawned
   subagents.
2. A local `ff mcp` stdio server exposes one `capabilities` tool so the agent
   can refresh the configured-grant view before an external call when
   staleness would matter.
3. Automatically loaded runtime guidance explains that Forcefield exists, that
   snapshots are advisory, and how to handle the bearer and mTLS key. Claude
   uses managed `claudeMd`; Codex consumes the MCP server's initialization
   instructions directly.

Do not paste a bearer into `CLAUDE.md`, `AGENTS.md`, settings, hook commands,
MCP configuration, or a generated manifest. Every integration points to a
protected token file and the `ff` process reads it without returning its value.

## Live capability endpoint

The data plane reserves:

```text
GET /.well-known/forcefield/capabilities
Authorization: Bearer ff_...
```

The endpoint always uses the fixed `Authorization: Bearer` convention, even
when an individual service uses a different `client_auth` carrier. It validates
the bearer, its expiry/revocation state, audience, and the request's workload
identity. An invalid or misbound request gets the same generic 404 used for
other denials.

The JSON response contains a schema version, generation/token-expiry
timestamps, and a sorted, secret-free projection of revision-current concrete grants:
service name, adapter, public base URL/route, client authentication convention,
operator-authored capability summary, configured grant ceilings, and, for SSH,
the granted shell/exec/PTY modes plus maximum session duration. Grants
whose policy or credential binding revision is no longer current are omitted.
It does not contain the bearer, provider credential, secret reference, private
upstream URL, token or grant IDs, role name, policy internals, or admin-socket
information.

Adapter-specific rendering gives agents an exact client recipe without
exposing private binding details. Git entries show the scoped credential-helper
command. SSH entries show only recipes supported by the concrete grant: shell,
command execution, and PTY availability are explicit, and a no-PTY shell recipe
includes `--no-pty`. They use the public Forcefield origin, service alias, and
protected token-file path; they do not reveal the target address, Unix username,
host-key pins, or private-key reference. The same rendering is injected into
Claude and Codex sessions and returned by the MCP capability tool, so no
harness-specific SSH prompt is required.

Agent-facing text should describe SSH denials precisely. “No forwarding or
subsystems” means Forcefield rejects those SSH protocol requests; it does not
mean a granted shell/exec lacks filesystem or network authority. The policy's
`capability_summary` should state the configured account's effective scope and
any target-side restrictions the agent must understand.

Configured ceilings are not remaining quota. The endpoint deliberately does
not inspect live request/byte counters, and a listed grant may already be
exhausted when the agent reads it.

Capability lookup does not contact an upstream, retrieve a provider credential,
or consume a service request/byte budget. It is audited and returned with
`Cache-Control: no-store`. The endpoint accepts only exact GET requests without
a query or body. After authentication, a separate per-workload discovery
limiter allows 2 successful requests per second with a burst of 16; it does not
charge any service grant. Malformed and unauthenticated denial records are
globally sampled to bound audit growth without letting them starve a valid
workload's discovery bucket.

Set `server.advertised_base_url` to the origin actually reachable by the guest.
Without it, the projection can still name a path or host route, but cannot give
the agent a complete service base URL. Add a concise `capability_summary` to
each policy so the agent gets useful semantic guidance; this prose is never a
substitute for the enforced rules.

## Guest provisioning

Install the same `ff` binary in the VM, then provision only data-plane client
material:

```text
/usr/local/bin/ff                 executable, root-managed
/run/forcefield/token             scoped ff_ bearer, agent-readable, mode 0600
/run/forcefield/ca.crt            Forcefield server CA
/run/forcefield/client.crt        workload certificate, if mTLS is used
/run/forcefield/client.key        workload private key, mode 0600, if mTLS is used
```

The token must be a regular, non-symlink file owned by the `ff` process user
with no group or world permissions; `0600` is the normal choice. Deliver it over
the VM's authenticated provisioning channel after minting, and replace it
atomically when re-minting.
Do not bake it into an image or put it in a shell profile. Provision the server
CA rather than disabling TLS verification. For an IP-bound development guest,
omit the client certificate/key; plaintext is accepted by the client only with
`--allow-insecure` and only for a loopback Forcefield origin.

Never mount or copy the host's Forcefield admin socket, configuration, token
store, audit file, secret-helper state, or provider credentials into the VM.
The guest needs only the public data-plane origin and its scoped client
material.

Verify the guest path before configuring an agent runtime:

```sh
/usr/local/bin/ff capabilities \
  --url https://forcefield.internal:7902 \
  --token-file /run/forcefield/token \
  --ca-cert /run/forcefield/ca.crt \
  --client-cert /run/forcefield/client.crt \
  --client-key /run/forcefield/client.key
```

`--json` emits the full bounded manifest. Connection settings can alternatively
come from `FORCEFIELD_URL`, `FORCEFIELD_TOKEN_FILE`, `FORCEFIELD_CA_CERT`,
`FORCEFIELD_CLIENT_CERT`, and `FORCEFIELD_CLIENT_KEY`. The default token path is
`~/.config/forcefield/token`.

## Claude Code managed hook

Copy and adapt the hook-only
[`deploy/claude/managed-settings.json.example`](../deploy/claude/managed-settings.json.example)
into the Linux managed-settings location, normally as a drop-in such as:

```text
/etc/claude-code/managed-settings.d/50-forcefield.json
```

See Claude Code's current [managed settings](https://code.claude.com/docs/en/settings)
and [hooks reference](https://code.claude.com/docs/en/hooks) when adapting the
fleet configuration.

Replace the origin and guest paths. Remove the client certificate/key flags
only for an intentionally IP-bound deployment. Keep the executable and file
paths absolute. The example uses Claude's exec-form `args` so no shell parses
the values. Make the settings root-managed so a repository cannot replace the
hook. The hardened example also sets `allowManagedHooksOnly: true`, preventing
project, user, and plugin hooks from injecting a contradictory capability
story. If the guest needs other hooks, install them in managed settings too or
make an explicit decision to relax that setting.

Then merge
[`deploy/claude/claude-md.merge.txt`](../deploy/claude/claude-md.merge.txt)
into the organization's single effective managed `claudeMd` value. Do not put
that scalar in an independent drop-in without checking ordering: Claude merges
hook arrays, but a later `claudeMd` scalar replaces an earlier one. The supplied
hook drop-in therefore omits the scalar so it cannot erase existing
organization instructions.

The hook reads Claude's event JSON from stdin and returns structured
`additionalContext` for both `SessionStart` and `SubagentStart`. The rendered
context is bounded. If live lookup fails, it injects an explicit
"capabilities not confirmed" instruction instead of reusing a stale snapshot
or blocking startup. Therefore an outage must never be interpreted as an empty
but permissive grant.

The managed `claudeMd` text is deliberately static: it teaches the agent where
fresh capability information comes from and how bearer material may be used.
Do not generate a long-lived grant list into `CLAUDE.md`; revocation and
configuration rollout can make it stale.

## Codex CLI managed hook

Codex CLI supports `SessionStart` and `SubagentStart` hooks with the same
structured context wire format. Forcefield exposes that contract explicitly as
`ff capabilities --format codex-hook`; extra Codex event fields are ignored.

Adapt
[`deploy/codex/forcefield-capabilities-hook.example`](../deploy/codex/forcefield-capabilities-hook.example),
then install it root-owned, non-writable by the agent user, and mode `0755` as:

```text
/etc/codex/hooks/forcefield-capabilities
```

Merge
[`deploy/codex/requirements.toml.merge.example`](../deploy/codex/requirements.toml.merge.example)
into the guest's existing `/etc/codex/requirements.toml`. Do not replace other
administrator requirements. The example pins the stable `hooks` feature on,
declares `/etc/codex/hooks` as its managed script directory, and injects a live
snapshot for startup, resume, clear, compaction, and every subagent start.
Because the hook command is a shell string in Codex, the supplied requirements
call a fixed wrapper with no arguments; keep that wrapper and every value
embedded in it administrator-controlled.

The hardened example sets `allow_managed_hooks_only = true`. That prevents
user, repository, session, and plugin hooks from presenting a contradictory
capability story, but also disables every legitimate hook from those sources.
Install any other required hooks through managed configuration or deliberately
remove that setting after reviewing the tradeoff. Managed requirements hooks
are trusted automatically and cannot be disabled through Codex's `/hooks`
browser.

See the current Codex [hooks documentation](https://developers.openai.com/codex/hooks)
when adapting the managed lifecycle configuration.

Codex adds the hook's `additionalContext` as developer context. The format is
bounded and fails closed in the same way as the Claude integration: a live
lookup failure injects "capabilities not confirmed" instead of an empty or
cached grant list. No `AGENTS.md` entry is required for discovery. A global
`~/.codex/AGENTS.md` can reinforce the handling rules, but it is ordinary
advisory context and is not the production integrity boundary.

## MCP refresh tool

Run the guest-local stdio server with the same connection arguments:

```sh
/usr/local/bin/ff mcp \
  --url https://forcefield.internal:7902 \
  --token-file /run/forcefield/token \
  --ca-cert /run/forcefield/ca.crt \
  --client-cert /run/forcefield/client.crt \
  --client-key /run/forcefield/client.key
```

The server advertises a short initialization instruction that Codex consumes
as server-wide guidance. It tells the agent to consult `capabilities`, follow
cursor pagination, use only advertised Forcefield origins, protect the bearer
and private key, and treat snapshots as advisory. The server remains useful to
other MCP clients through the tool's own name, description, schema, and safety
annotations.

### Claude Code MCP configuration

Merge the `forcefield` entry from
[`deploy/claude/mcp-server.merge.json.example`](../deploy/claude/mcp-server.merge.json.example)
into the guest's MCP configuration, preferably the centrally managed set when
repositories are untrusted. With the server named `forcefield`, Claude exposes
its one tool as
`mcp__forcefield__capabilities`.

The example sets `alwaysLoad: true`, and the tool advertises Claude's matching
per-tool hint, so this one small discovery tool is visible without a tool-search
step. `alwaysLoad` requires Claude Code 2.1.121 or later. The supplied hook uses
exec-form `args`, added in Claude Code 2.1.139, so the complete supplied
integration requires 2.1.139 or later; do not assume this hook works on
2.1.121--2.1.138.

Do not blindly install the example as `/etc/claude-code/managed-mcp.json`.
Claude Code treats that file as the exclusive managed MCP allowlist and ignores
other MCP configuration. If an organization uses it, merge Forcefield into the
complete existing managed server set. Otherwise install the entry through the
runtime's managed/user-scope MCP mechanism. See Claude Code's [managed MCP
reference](https://code.claude.com/docs/en/managed-mcp) for current precedence
and deployment paths.

A user-scope MCP entry is useful for development but is not an integrity
boundary: a higher-precedence project configuration can shadow it. The managed
startup hook still provides the trusted initial snapshot, and Forcefield still
authorizes every request, but production guests should use administrator-owned
MCP configuration.

### Codex CLI MCP configuration

Merge
[`deploy/codex/config.toml.merge.example`](../deploy/codex/config.toml.merge.example)
into the guest's existing `/etc/codex/config.toml`. Do not replace unrelated
system configuration. Codex starts `ff mcp` directly from the command and
argument array, exposes the tool as `mcp__forcefield__capabilities`, and reads
the MCP initialization instructions automatically. The example restricts the
server to its one tool and sets `required = true`, so Codex startup fails if the
local MCP process cannot initialize. The process does not contact Forcefield
until the tool is called; remove `required = true` only if starting without the
refresh tool is an intentional availability tradeoff.

System `config.toml` is a centrally installed default, not an unoverrideable
policy layer: higher-precedence user or trusted-project configuration can
shadow it. Keep the root-managed startup hook as the trusted automatic
injection path. MCP output is advisory in every case, and the Forcefield
gateway remains the authorization boundary. See the current Codex
[MCP documentation](https://developers.openai.com/codex/mcp) and
[managed configuration documentation](https://developers.openai.com/codex/enterprise/managed-configuration)
when adapting fleet policy.

After provisioning, `codex features list` should report `hooks` as enabled and
stable, and `codex mcp list` should show the `forcefield` server. In a fresh
Codex CLI session, use `/hooks` to inspect the managed lifecycle entries and
`/mcp` to confirm the refresh tool is active.

The stdio server is intentionally local and narrow. It receives no bearer in
its arguments, exposes no proxy or arbitrary HTTP tool, and must never be
configured with the Forcefield admin socket. Tool output is bounded and cursor
paginated; when a result says more grants remain, call it again with the
returned stable service-name `cursor`. Every page is fetched live rather than
reusing a cached manifest. If configuration changes during enumeration, start
again without a cursor for a coherent view of the new ordering.

## Freshness and trust boundaries

The startup text is a point-in-time snapshot whose maximum lifetime is the
token expiry. A token can be revoked, a parent can be revoked, or a policy or
binding revision can change immediately after injection. Agents should refresh
through the MCP tool before a material external action or after a denial, but
must not probe random routes to infer authority. A generic 404 can mean either
"outside the grant" or "not found."

An agent can ignore, misunderstand, or overwrite context. That does not grant
authority: the gateway's token, workload, route, limit, and policy checks remain
the security boundary. Conversely, injected prose cannot promise that a call
will succeed. Treat it as discoverability that helps the agent form valid
requests while Forcefield remains authoritative.
