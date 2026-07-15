# Threat model and residual risks

Forcefield reduces the authority available to an untrusted or prompt-injected
agent and keeps reusable provider credentials out of its VM. It does not make
an authorized action safe merely because it passed through a proxy.

## Security objective

Given a trusted host, trusted configuration, and trusted configured upstream,
an agent should be able to exercise only the concrete grants in its valid,
workload-bound capability token. It should not be able to choose an upstream,
broaden its policy, substitute a credential, bypass canonicalization, multiply
a delegated budget, or receive the exact injected credential in an ordinary
upstream response.

## In scope

- A malicious, compromised, or prompt-injected agent controlling its HTTP
  method, target, query, headers, and body.
- An agent replaying a stolen `ff_` token from the same or another workload.
- Duplicate parameters, duplicate authentication headers, path confusion,
  duplicate/invalid representation headers, late trailers, encoded separators,
  redirect leakage, header smuggling, SSRF, and use of host proxy settings.
- Malformed Git smart-HTTP routes, pkt-line framing, object IDs, ref names,
  duplicate or mixed-authority ref updates, compressed packs, and attempts to
  smuggle an unauthorized update inside a multi-ref push.
- SSH attempts to select a different target/user, bypass a host-key pin, open
  extra session or forwarding channels, request agent/X11/environment/subsystem
  features, exceed decoded channel/request-payload limits, or continue after
  expiry/revocation.
- An agent attempting to enumerate routes, token validity, grants, or policy
  failures.
- A secret backend failure, policy evaluation error, audit failure, malformed
  upstream response, or configuration reference that no longer exists.
- Multiple descendants trying to multiply a root capability's in-process rate
  or byte budget.

## Assumptions and out-of-scope compromise

- The Forcefield host, its kernel, its operator account, the binary, config,
  state directory, CA keys, and credential helper are trusted. Host compromise
  defeats the system.
- The configured upstream and its TLS or pinned SSH endpoint are trusted. An
  HTTP/Git upstream is trusted not to intentionally transform and disclose the
  credential; Forcefield detects only exact reflection.
- Provider credentials are independently scoped as narrowly as the provider
  permits. Forcefield is an additional boundary, not a substitute for native
  scope, expiry, spend limits, or provider-side audit.
- The VM isolation and network rules prevent direct access to the provider and
  to the host's admin socket. If an agent can bypass Forcefield egress, it can
  use any other credential it obtains and can evade Forcefield auditing.
- A caller that possesses a valid capability can perform every operation the
  policy allows, including malicious uses of those operations. Forcefield does
  not infer intent, inspect prompts, or approve business semantics.
- Availability is not guaranteed against a client authorized to consume its
  request/bandwidth allowance, a large permitted Git pack, or an upstream that
  streams indefinitely.
- SSH shell or arbitrary exec permission is full authority as the configured
  target account. Target sudoers, filesystem, service, and egress policy are
  trusted to supply any finer boundary. Closing a connection cannot undo work
  or reliably kill a deliberately detached process.

## Workload authentication

### Verified mTLS SPKI identity (recommended)

When `tls_cert`, `tls_key`, and `client_ca` are configured, the server requires
and verifies a client certificate. The workload ID is:

```text
mtls-spki:<lowercase SHA-256 hex of leaf SubjectPublicKeyInfo>
```

Generate the exact value with `ff identity --cert client.crt`. Binding to the
public key survives certificate reissuance with the same key. Rotate the key to
change identity, revoke associated Forcefield tokens, and enforce certificate
revocation/short lifetime in the surrounding PKI; Forcefield does not implement
CRL or OCSP policy itself.

mTLS provides channel encryption, server authentication, and proof of the
client private key. A stolen Forcefield bearer alone cannot be replayed from a
workload with a different key. A stolen bearer plus stolen client key can.

### Source IP identity

Without a verified client certificate the workload ID is the direct TCP peer:

```text
ip:<canonical IP address>
```

Generate it with `ff identity --ip ADDRESS`. Forcefield ignores forwarding
headers, so a reverse proxy in front of it collapses identity to that proxy's
IP. IP binding is appropriate only on a demonstrably isolated point-to-point
VM network where addresses cannot be spoofed, reassigned, or shared. It is not
strong identity on a general LAN, NAT shared by multiple guests, Kubernetes
node, or multi-tenant bridge.

Non-loopback plaintext ingress is rejected unless
`allow_insecure_ingress: true`; that switch does not authenticate or encrypt
the bearer and is for isolated development networks only. Prefer mTLS instead.

## Capability theft and delegation

An `ff_` token is intentionally available to its agent. Treat it like a scoped
bearer credential: do not log it, put it in shell history, pass it on a command
line visible to unrelated host processes, or bake it into an image. Deliver it
over the VM's protected provisioning channel and use short TTLs.

The token is bound to one audience and exact workload identity. The store keeps
only its SHA-256 digest. Revocation cascades to descendants, validation checks
the entire ancestor chain, request context is bounded by token expiry, and the
gateway revalidates around secret lookup. This limits replay, but it is not
proof-of-possession: any process in the same workload identity that reads the
bearer can use it.

The control plane does not accept operator-invented workload strings. Mint and
delegate require the canonical `ip:` or lowercase 64-hex `mtls-spki:` forms
that the data plane itself derives.

Delegation is monotonic over expiry and concrete grants. The CLI currently
narrows by service subset only; it does not expose per-limit tightening. Do not
set `--allow-delegation` unless the workload genuinely needs to mint child
capabilities through a trusted host-side operator path.

## Capability discovery and agent context

The freshly generated capability manifest is authenticated with the same bearer
and workload identity. It deliberately reveals public service routes, auth conventions,
operator-authored scope summaries, configured ceilings, and expiry to that
workload, but never returns the bearer, provider credential, secret reference,
private upstream, or internal token/grant IDs. Treat the manifest as scoped
authority metadata and do not publish it outside the workload.
Configured ceilings are not remaining quota, so presence in the manifest is
not a promise that a request or byte budget still has capacity.

Startup hooks and MCP make this metadata easier for an agent to consume; they
do not make model context a security boundary. Context can be stale, ignored,
or manipulated by other instructions. A lookup failure must mean "no
capabilities confirmed," not permission to proceed, and the data plane must
still authorize every request. Keep managed hook/MCP configuration
administrator-owned, pass only a 0600 token-file path, and never expose the
admin socket to the guest integration.

## Confused-deputy and SSRF controls

The client cannot supply an upstream endpoint. An HTTP/Git route selects a
configured HTTPS authority, while an SSH route selects its configured
`ssh://host:port`. Absolute HTTP targets, CONNECT, upgrades, trailers, encoded
separators, double-encoded octets, dot segments, repeated interior slashes,
malformed or oversized queries, semicolons in path segments, raw query `+` or
semicolons, and excessive query pairs are denied.

DNS resolution validates every returned address, then dials one of those exact
addresses while retaining TLS SNI/certificate validation for the configured
hostname. Private and special-purpose ranges are denied unless explicitly
listed. Outbound proxy environment variables are ignored.

The Git adapter likewise does not turn a repository path into a destination.
Its four smart-HTTP route shapes are relative to the service's one configured
upstream. Dumb HTTP, Git LFS, and provider API paths do not match those shapes.

The SSH adapter similarly ignores every guest-supplied notion of destination.
It dials the one configured host and explicit port through the same resolve-once
CIDR guard, verifies an exact configured SSH host-key fingerprint, and uses the
configured username. It never consults host SSH config, proxy commands, or an
SSH agent.

Residual risks include compromise of DNS plus a valid certificate, an overly
broad `allowed_cidrs` exception, a bad configured hostname, a compromised
public upstream, and application-layer behavior inside an allowed endpoint.
Optional SPKI pins reduce some certificate/DNS risk but add an availability and
rotation obligation.

## Policy limits

Deny-wins composition prevents source order from turning an exception into an
allow. Any matcher evaluation error fails the entire request closed, even if a
different allow matched. Policy sees the canonical target Forcefield sends.

Policy still has semantic blind spots:

- Method/path restrictions do not understand the provider's business meaning.
- JSON matchers compare selected RFC 6901 pointers; unmentioned fields remain
  unconstrained. Bodies require UTF-8 JSON media semantics, unique keys, and
  valid paired surrogate escapes. JSON comparison is mathematically exact.
- GraphQL matching constrains operation type/name and an allowlist of expanded
  root fields. It does not validate against the upstream schema or constrain
  nested fields, arguments, directives, variable values, query complexity, or
  resolver side effects unless separate JSON/CEL conditions cover them. Carrier
  ambiguity, parser token/depth excess, expansion depth, cycles, and undefined
  fragments fail closed.
- CEL is bounded and has only method, path, query, and decoded JSON body, but a
  correct expression can still encode an incomplete policy. Dynamic type errors
  deny, which can also cause availability failures. JSON-to-CEL conversion is
  lazy: unrelated decimals are harmless, while an inspected decimal that has
  no exact binary `double` representation fails closed instead of rounding.
- Git fetch rules authorize a repository as a whole, not branch-level object
  confidentiality. Git push rules can prove the repository, full ref, and
  create/update/delete shape of each command, but not whether an update is a
  fast-forward or what the new objects mean.
- SSH policy controls only shell, arbitrary exec, and PTY protocol modes plus
  duration. It does not safely parse shell syntax or constrain commands inside
  an allowed shell/exec session.
- A provider can assign new semantics to an already allowed endpoint without a
  Forcefield configuration change.

Use purpose-built adapters for high-impact operations where it is important to
pin fields rather than merely test them.

## SSH session boundary

The guest's SSH connection is nested inside the same authenticated HTTPS data
plane used for capability calls. The bearer is therefore checked with the
existing source-IP or verified-mTLS workload identity and is not reused as an
SSH password. Forcefield terminates that inner connection and separately
authenticates upstream with a private key fetched after the audit boundary;
the target receives the configured public key and proof-of-key signatures,
never private-key bytes.

Only one `session` channel is accepted. Port and stream-local forwarding,
agent and X11 forwarding, tunnel channels, environment requests, subsystems
(including SFTP), and extra sessions are rejected independent of policy. The
process uses only Go's supported non-insecure SSH algorithms. Host-key pinning
does not rescue an incorrectly configured target or a compromised pinned host.
RSA login and target host keys must be at least 2048 bits; RSA authentication
uses RSA-SHA2-256/512 and never legacy `ssh-rsa`/SHA-1.

The hard I/O deadline is the earlier of token expiry and configured policy
duration, and the guest SSH handshake has its own 10-second ceiling. Active
sessions revalidate once per second, so revocation has a bounded polling window;
actions completed during or before that window remain completed. Decoded
guest-to-target channel input plus payload bytes for allowed session requests
actually forwarded upstream count against the delegation byte budget and
per-session ceiling. HTTP/SSH framing, encryption overhead, rejected request
payloads, and replies do not. Separately, all global/session request and channel
open attempts, including rejected attempts, have a hard 64-per-second,
burst-128, 4096-total guard. In-memory admission and byte counters reset on
process restart like the existing HTTP/Git limit state. Decoded stdout/stderr
is not scanned for the private key because the upstream never receives that
key; terminal contents are not audited.

These rejections are SSH protocol controls, not a sandbox around commands. A
permitted shell or exec can use every filesystem, service, sudo, and network
capability available to the configured Unix account. Use a unique login key,
target-side sshd/`authorized_keys` restrictions, a dedicated account, and
filesystem and egress controls as independent enforcement. A compromised or
over-privileged target account remains correspondingly powerful.

The outer transport also requires simultaneous unbuffered HTTP request and
response streaming. Direct TLS/mTLS is preferred. Any reverse proxy must
support that full-duplex behavior for HTTP/1.1 chunked or HTTP/2, preferably
HTTP/2 over TLS; a buffering proxy breaks the transport. Proxy TLS termination
or source-address rewriting also collapses the mTLS or direct-peer workload
identity unless the deployment provides an equally trusted identity boundary
outside Forcefield.

## Git smart-HTTP boundary

The Git adapter is generic: it contains no hosting-provider, repository-class,
or protected-branch name. Operator policy supplies exact or recursive
repository/ref selectors. A rule can deny `refs/heads/stable`, allow it, or
protect a completely different ref. This separation matters because a
deployment convention such as “infrastructure cannot push to main” is not a
Forcefield invariant.

Repository policy operates on URL identity, so every Git service requires an
operator-selected case model. `sensitive` preserves repository path bytes and
is safe only when the upstream distinguishes case variants.
`ascii-insensitive` lowercases ASCII for both requests and policy and rejects
non-ASCII paths; it is safe only when the upstream folds those same ASCII case
variants. Choosing `sensitive` for a case-insensitive upstream can let a case
alias evade an exact deny. Choosing `ascii-insensitive` for a case-sensitive
upstream can conflate distinct repositories and grant one the other's
authority.

Case handling does not solve arbitrary aliases. An upstream must not map an old
name, renamed path, redirect, vanity alias, or alternate normalization to the
same physical repository while Forcefield gives those URL names different
authority. Forcefield has no trusted upstream repository-ID oracle with which
to prove they are the same. Remove such aliases or apply identical repository
authorization to every accepted URL name.

Fetch authorization is repository-wide. Upload-pack clients choose object
wants, and advertised refs are not a sufficient confidentiality boundary for
reachable or otherwise obtainable objects. Forcefield therefore rejects Git
fetch rules that claim `refs` or update kinds. Put differently protected read
audiences in different repositories or enforce object visibility upstream.

For pushes, Forcefield parses and validates the receive-pack command prefix
before credential lookup. Every command is classified as `create`, `update`,
or `delete`; every update must match an allow; and a deny on any update rejects
the entire request before it reaches the upstream. Duplicate refs, malformed
object IDs/ref names, unsupported capabilities, oversized command prefixes,
and ambiguous protocol forms fail closed. This prevents an allowed update from
masking a denied update in the same request.

Authorization ends at the wire-visible command tuple. A trusted upstream
`proc-receive`, pre-receive, post-receive, or other hook must not reinterpret an
allowed command as an update or privileged effect on an unauthorized ref or
repository. A hook that does so acts with the broader upstream credential after
Forcefield's decision and defeats the intended semantic boundary. Audit and
review upstream hooks as part of the trusted configuration.

An `update` command contains only old object ID, new object ID, and ref. It does
not assert or prove ancestry, so Forcefield cannot distinguish a fast-forward
from a forced non-fast-forward without acquiring and trusting the repository
object graph. It intentionally exposes no `force` selector. Configure upstream
branch protection or receive-pack non-fast-forward controls as defense in
depth. The upstream credential itself may be broader than the Forcefield grant,
so native protections remain valuable if the gateway or host is compromised.

Receive-pack supports the command forms Forcefield parses: protocol v0/v1,
without push certificates or push options. Protocol-v2 receive-pack, signed
pushes, Git LFS, and dumb HTTP are outside the adapter. Receive-pack discovery
strips a v2 request so ordinary Git clients can fall back rather than treating
an unimplemented v2 push as authorized semantics.

Pack bodies stream after authorization instead of being retained in memory.
Both compressed and decoded sizes are bounded; gzip has a decompression-ratio
guard and rejects concatenated/trailing streams; decoded bytes are charged to
every delegation-chain byte budget as they are consumed. A mid-stream limit,
timeout, malformed pack, or transport error can leave the client with an
aborted RPC. Forcefield relies on receive-pack not applying a partial invalid
pack, while upstream atomic branch-update policy remains the provider's
responsibility.

## Response reflection and a malicious upstream

The response guard removes common credential-bearing headers, rejects
cross-origin redirects, rewrites accepted same-origin redirects through the
gateway, rejects non-identity content encoding by default, scans remaining
headers, and searches a streamed response across chunk boundaries for the exact
credential bytes. For `basic_username` injection it also scans the exact
base64-encoded `username:secret` payload. A non-final 1xx response (including
101) or invalid status above 599 is rejected rather than relayed.

This does **not** establish that the real credential can never reach the VM
regardless of upstream behavior. A malicious or compromised upstream can return
base64, hex, URL-encoded, compressed-under-a-different-label, encrypted,
character-interleaved, hashed, partially transformed, or otherwise derived
credential material. Exact scanning cannot recognize every reversible
transformation without becoming a content-aware data-loss-prevention system.

Forcefield filters a response prefix of up to 32 KiB before committing it, then
streams. Bytes preceding an exact secret found later in the body may therefore
already have reached the client, although the exact secret match itself is
withheld. Headers/status may also already be committed when a later body error
occurs.

Therefore:

- trust and pin the upstream;
- keep provider credentials narrowly scoped and rotateable;
- do not proxy arbitrary user-chosen origins;
- keep `response.require_identity: true` unless a provider-specific response
  adapter safely decodes and scans another encoding;
- use a native short-lived credential or narrow semantic adapter when the
  upstream itself is not within the trust boundary.

## Secret backend and memory

The exec backend invokes an absolute, resolved executable directly, without a
shell, stdin, or captured stderr. It supplies only a small fixed environment
rather than inheriting the host environment wholesale, bounds time/stdout, and
removes one trailing newline. A cache owns copies for its configured TTL and
zeroes byte slices on release or eviction.

Go and the operating system may retain copies in process memory, subprocess
pipes, allocator state, swap, crash dumps, or kernel buffers despite best-effort
zeroing. Host process compromise is out of scope. Disable core dumps, protect
swap as appropriate, keep cache TTLs short, and run Forcefield under the user
whose credential helper it must access—not under an agent-accessible account.

`agent-secret` itself allows same-host-user retrieval while the macOS Keychain
is unlocked. Forcefield adds agent/VM authorization at the HTTP boundary; it
does not make the host user's Keychain resistant to another compromised process
running as that same host user.

## Audit and state failure

The default audit mode writes an authorization record before credential access
and denies the request if that write fails. `audit_failure: open` permits
authority when the sink is unhealthy and currently has no external health
reporting hook; use it only after an explicit availability-over-accountability
decision.

Denial-path audit writes and the final completion write cannot retract an
already denied or forwarded request if they fail. An authorized request normally
produces a pre-authority record with status `0` and a completion/error record.
Data-plane records correlate a generated request ID with public token/root IDs
and include method, a path digest, policy reason, workload, grant, and rule
metadata. Mint, delegate, and revoke likewise write correlated `authorized`,
`completed`, or `failed` control records; if a required completion record fails
after mint/delegate, the newly issued token is revoked. Audit files contain no
bodies, raw bearers, or credential fields.

Token persistence is crash-conscious and bearer-free. A held cross-process
lock on supported platforms prevents multiple servers from sharing one token
file, and inactive records/subtrees are durably pruned on open and mutation.
The HTTP adapter buffers bodies under a finite configured ceiling; Git
smart-HTTP streams bounded RPC bodies after semantic prefix authorization; SSH
counts decoded guest channel input and allowed forwarded request payloads and
applies a finite session deadline.
Numeric budgets and rate state are not persisted and reset on restart. If those
are hard security quotas, enforce them again at the provider or an external
durable accounting layer.

## Operational checklist

- Use mTLS for every non-local or multi-tenant workload.
- Keep the admin socket and state directory inaccessible to agents.
- Start with provider-side read-only, low-spend, or narrowly scoped credentials.
- Set a short token TTL and explicit request, byte, and body ceilings.
- Keep fail-closed auditing and monitor the process and audit-file filesystem.
- Forward only the headers the API requires.
- Exercise both expected allows and adversarial denies before minting live tokens.
- For Git, test mixed multi-ref pushes and configure upstream branch protection
  for ancestry/merge constraints Forcefield cannot infer.
- Match `git.repository_case` to upstream routing, remove differently
  authorized repository aliases, and audit receive hooks for ref rewrites.
- For SSH, independently verify host-key pins, use a dedicated minimally
  privileged Unix account and unique login key, apply target-side
  sshd/`authorized_keys`, filesystem, sudo, and egress restrictions, test every
  forwarding/subsystem denial, and keep policy session durations and token TTLs
  short.
- Retain old policy revisions during a controlled migration or revoke/re-mint.
- Keep capability hooks/MCP root-managed and treat injected grant text as
  advisory, never as authorization.
- Rotate the upstream key and revoke Forcefield tokens after suspected compromise.
- Never use a permissive observe mode; Forcefield intentionally has none.
