# Architecture

Forcefield is a reverse-proxy capability gateway. It deliberately does not
accept an arbitrary destination. Every public route maps to one statically
configured upstream and every usable token carries an immutable concrete grant
for that service.

## Components and trust boundaries

```text
untrusted workload                 Forcefield host
------------------                 -----------------------------------
HTTP/Git/ff ssh client             public data plane
  ff_ bearer --------------------> route + canonicalize
  request body                     resolve workload (mTLS SPKI or IP)
                                   validate token + concrete grant
                                   charge grant limits
                                   evaluate deny-wins policy
                                   append pre-authority audit record
                                   fetch referenced host secret
                                   rebuild/inject HTTP or Git auth
                                   or terminate/pin an SSH session
                                                 |
                                                 v
                                      hardened direct transport
                                      DNS/IP policy + TLS/SSH identity pins
                                                 |
                                                 v
trusted, pinned upstream <-----------------------+
              response ----------> HTTP guard or SSH channel relay
                                   stream response to workload

trusted operator                    private control plane
ff mint/delegate/revoke ----------> 0600 Unix socket + same-UID check
                                   persistent token-digest store
```

The public data plane never exposes minting, delegation, or revocation. The
control plane listens on an absolute Unix-socket path in a private directory.
On Linux it checks the connecting process UID; on other systems it relies on
the socket and directory permissions. Any process with the same trusted host
UID can administer Forcefield, so agents should not run as that host user.

## Request lifecycle

For each request Forcefield performs these operations in order:

1. Reject CONNECT, upgrades, trailers, absolute-form targets, ambiguous paths,
   malformed queries, duplicate/invalid representation headers, and unknown
   routes.
2. Extract exactly one broker token from the service's configured inbound
   header and prefix.
3. Derive a workload identity from a verified client certificate, falling back
   to the direct peer IP when no verified certificate exists.
4. Validate the bearer digest, expiry, revocation chain, audience, and exact
   workload binding, then cap the request context at token expiry. Authentication
   failures are intentionally indistinguishable.
5. Resolve exactly one concrete grant for the routed service. Its credential,
   policy revision, and security-binding revision must still match the loaded
   service.
6. Atomically charge the matching grant at every token in the delegation chain
   and invoke the service adapter. The HTTP adapter buffers the body under the
   finite global/grant/policy ceiling and evaluates the canonical target. The
   Git adapter classifies one exact smart-HTTP route; fetch is authorized for
   the repository as a whole, while receive-pack parses and authorizes every ref
   update before opening an upstream request. Git pack data then streams under
   the global/grant body and byte ceilings. Late trailers fail closed.
   The SSH adapter admits one full-duplex stream, applies hard concurrency and
   session-duration bounds, and treats rate/request budget as tunnel admission.
7. Append an allow record before any secret is fetched. With the default
   `audit_failure: closed`, an audit error stops the request here. Revalidate
   the immutable token/grant before and after the potentially slow secret lookup.
8. Resolve the credential reference. HTTP/Git create outbound headers only from the
   configured allowlist, add operator-controlled static headers, inject the
   credential with `Set` semantics (or the configured upstream Basic-password
   transform), and send the request using the service's direct hardened
   transport. SSH parses a private key in host memory, connects only to the
   configured host/port through the same resolve-once address guard, verifies
   an exact host-key pin, and authenticates as the configured user.
9. HTTP/Git strip risky response headers, validate or rewrite redirects, scan response
   headers for the exact secret, reject any non-final status outside 200--599,
   and stream an exact-secret-filtered body.
   For SSH, terminate the inner connection, accept one session channel, relay
   only policy-enabled shell/exec/PTY requests, and reject forwarding,
   environment, and subsystems.
10. Append completion metadata correlated by request ID, public token ID, and
    root token ID. Data-plane records include method, a SHA-256 path digest,
    policy reason/rule IDs, and sizes, but the audit type cannot hold request
    bodies, raw broker tokens, or credential values.

Policy sees the exact canonical path and query subsequently forwarded. A path
route is removed before evaluation: a request to `/github/repos/o/r` under
`path_prefix: /github` is evaluated and forwarded as `/repos/o/r` (plus any
configured path already present in the upstream URL).

## Capability discovery lifecycle

The data plane reserves the exact path
`/.well-known/forcefield/capabilities` for an authenticated, freshly generated
projection of the caller's revision-current configured grants. It accepts only
GET without a query or body, and always
extracts the broker token from `Authorization: Bearer` so discovery does not
depend on any one service's client-auth convention.

Forcefield derives and validates the workload exactly as it does for a service
request, validates the token/audience/expiry/revocation chain, drops grants
whose policy or binding revision is no longer current, and renders a bounded,
sorted manifest. The projection includes public routing/auth conventions,
operator-authored summaries, configured ceilings, and generation/token-expiry
timestamps. Configured ceilings are not remaining quota, so an advertised
grant may already be exhausted. It omits bearer and provider credentials, secret references,
private upstreams, public token/grant IDs, and policy internals.

Discovery never fetches a secret, calls an upstream, or charges a service
request/byte budget. After authentication, a separate per-workload limiter
allows 2 successful lookups per second with a burst of 16. Malformed and
unauthenticated denial audits are globally sampled to bound storage without
starving valid discovery. Authorization is recorded before the response, and a
completion record carries the actual status and bytes written. Responses use
`Cache-Control: no-store`; authentication and workload failures use the generic
404. The manifest is advisory and can become stale immediately after return.
The ordinary request lifecycle remains the enforcement boundary.

## Service, credential, policy, role, and token

These are separate because each is a different security decision:

```text
service     = adapter + route + pinned upstream + transport + client token carrier
credential  = service + host secret reference + adapter-specific upstream auth
policy      = service + adapter-specific immutable matcher revision
binding     = revision of security-relevant service/credential configuration
grant       = service + credential + policy + binding revisions + ceilings
role        = named template containing one or more grants
token       = workload + audience + expiry + concrete immutable grants
```

A role is consulted only by `ff mint`. A minted token does not gain authority
when a role later changes. A policy's SHA-256 revision includes its service,
resource bounds, and rules. A separate binding revision covers the upstream,
route, transport confinement, adapter-specific protocol and response controls,
secret reference/auth interpretation, secret-backend mapping, global body
ceiling, and request-read timeout.
Changing either revision makes a token
fail closed rather than silently changing its authority. Rotating the value
behind an unchanged secret reference intentionally preserves the binding.

Delegation creates another persisted bearer with a shorter-or-equal lifetime,
a subset of services, the same concrete credential/policy/binding identities,
and limits no broader than the parent. The current CLI can select a service
subset but cannot tighten individual numeric limits. A request is atomically
charged to the corresponding grant at every ancestor in its root-to-leaf chain:
fan-out cannot evade an ancestor budget, and a narrower child cannot throttle a
parent or sibling.

## Upstream confinement

The upstream endpoint is parsed at startup and cannot contain user info, a
query, or a fragment. HTTP and Git services require HTTPS unless
`allow_insecure_upstream` is explicitly set for an HTTP URL. Production
configurations should never use that escape hatch. SSH services instead require
a canonical `ssh://host:port` endpoint with an explicit port and no path.

The HTTP/Git outbound transport:

- ignores proxy environment variables;
- resolves the configured hostname, rejects the connection if any returned
  address is neither public nor explicitly listed in `allowed_cidrs`, and dials
  an accepted resolved address directly;
- retains the configured hostname for SNI and ordinary system-root certificate
  verification;
- can additionally require a base64 SHA-256 SPKI pin;
- disables automatic compression and requests `Accept-Encoding: identity`;
- applies bounded connection, TLS, response-header, and header-size behavior.

`allowed_cidrs` is an exception list for intentionally private upstreams, not a
destination list supplied by the caller. SPKI pinning is additive: it does not
turn off normal certificate verification.

## HTTP header adapter

The v1 adapter separates the broker-token carrier from the real-credential
carrier. For example, an agent can send `Authorization: Bearer ff_...` while
Forcefield sends `x-api-key: real-value` upstream.

Outbound headers are rebuilt from `forward_headers`, then trusted values from
`static_headers` are added, and finally the configured credential is installed
with `Set`. Known credential-, key-, token-, session-, and signature-bearing
names, hop-by-hop/forwarding headers, `Content-Length`, `Accept-Encoding`, and
auth carriers cannot be forwarded or static; static headers additionally
exclude all representation/framing headers and `Host`. A header cannot be both
forwarded and static. Static values are non-secret configuration—not a place
for API keys—and only the separately injected credential is covered by the
exact-value response scan. This lets an operator pin semantic contract headers such as
`Anthropic-Version` and `X-GitHub-Api-Version` without trusting an SDK-selected
value, while credential `Set` semantics prevent duplicate-header smuggling.

This adapter is intentionally small. It handles only a static value injected in
one header. It does not sign a request, perform an auth challenge, mint native
temporary credentials, or rewrite a request body.

## Git smart-HTTP adapter

`adapter: git-smart-http` is a protocol adapter, not a provider adapter. It can
front any pinned upstream that implements Git smart HTTP and accepts a static
HTTP credential. No repository owner, branch name, or hosting product is built
into the adapter. Those choices live entirely in configuration policy.

Every Git service must declare `git.repository_case`. `sensitive` preserves the
canonical repository URL path byte-for-byte and is appropriate only when the
upstream treats case-distinct paths as distinct repository identities.
`ascii-insensitive` rejects non-ASCII repository paths and folds ASCII `A`--`Z`
to lowercase for policy, as it must when the upstream maps ASCII case variants
to one repository. Repository patterns are normalized the same way. This mode
affects repository URL identity only; ref names remain case-sensitive.

The case mode is an operator assertion about upstream routing, not an upstream
discovery mechanism. Other aliases are not collapsed. If an upstream maps an
old name, renamed path, vanity alias, or Unicode-normalized spelling to the same
physical repository, those URLs must not receive different Forcefield
authority. Remove the aliases or apply identical repository rules to every URL
name; otherwise an allowed alias can bypass a deny written for another name.

The adapter exposes only these service-relative request shapes, where
`REPOSITORY` is a canonical, possibly nested path ending in `.git`:

| Request | Meaning |
|---|---|
| `GET /REPOSITORY/info/refs?service=git-upload-pack` | Fetch discovery. |
| `POST /REPOSITORY/git-upload-pack` with `application/x-git-upload-pack-request` | Fetch RPC. |
| `GET /REPOSITORY/info/refs?service=git-receive-pack` | Push discovery. |
| `POST /REPOSITORY/git-receive-pack` with `application/x-git-receive-pack-request` | Push RPC. |

The path-route prefix is removed before classification. Methods, query spelling,
RPC content types, and successful upstream Git response types must be exact.
Consequently, dumb-HTTP paths such as `HEAD` and `objects/**`, Git LFS HTTP
paths, extra queries, and unrelated hosting APIs never reach the upstream
through this adapter.

Fetch authorization is deliberately repository-wide. Upload-pack object wants
cannot be treated as a confidentiality boundary for one advertised branch, so
a fetch rule may select repositories but may not claim ref-level restrictions.
An allowed fetch can obtain every object the upstream repository and its own
server-side policy make available.

Push authorization is semantic. Forcefield parses the bounded pkt-line command
prefix before credential access, derives `create`, `update`, or `delete` from
the old/new object IDs, validates each full `refs/...` name, and evaluates each
update independently. Any matching deny rejects the whole multi-ref request;
otherwise every update must match an allow. This is default deny, deny-wins,
and independent of rule order. Repository and ref selectors are exact strings
or recursive `prefix/**` patterns, so a deployment can protect
`refs/heads/stable`, `refs/tags/**`, or any other ref without a hardcoded
`main`-branch concept.

The receive-pack command does not say whether an ordinary update is a
fast-forward. Both a fast-forward and a forced non-fast-forward arrive as the
same old object ID, new object ID, and ref; proving ancestry would require
repository object-graph access. Forcefield therefore does not offer a fictional
`force` update kind. Use upstream branch protection or receive-pack controls to
deny non-fast-forwards, and use Forcefield to constrain repositories, refs, and
observable create/update/delete operations.

Likewise, policy covers the ref commands visible on the receive-pack wire, not
effects invented later by the upstream. A `proc-receive`, pre-receive,
post-receive, or other server hook must not translate an allowed command into an
update or privileged side effect on an unauthorized ref or repository. Such
hooks and their configuration are part of the trusted upstream boundary.

Git clients can present `ff_` tokens as HTTP Basic passwords through the bundled
path-scoped `ff git-credential` helper. That guest-side challenge flow is
separate from upstream authentication. Upstream injection can remain an
ordinary header prefix or set `basic_username`, which encodes the host-side
secret as that username's Basic password. Neither form exposes the upstream
credential to the Git client. For Basic injection, the response filter scans
both the raw secret and the exact base64-encoded `username:secret` payload.

Upload-pack request bodies and receive-pack pack data stream rather than being
buffered wholesale. Receive-pack buffers at most a bounded command prefix,
authorizes it, and replays the exact bytes into the stream. Identity, `gzip`,
and `x-gzip` RPC bodies are accepted; gzip is decoded before authorization and
forwarding, with compressed and decoded size bounds, a decompression-ratio
guard, byte-budget charging on decoded bytes, and rejection of concatenated or
trailing streams. A limit failure aborts the upstream RPC. Request trailers are
rejected.

Fetch supports protocol v0, v1, and v2. Git has no supported protocol-v2 push
flow here: a v2 advertisement header on receive-pack discovery is stripped so
ordinary clients can fall back to v0, while a v2 receive-pack RPC is denied.
Push certificates and push options are also denied. These restrictions keep the
policy input to the command form Forcefield actually parses.

## SSH session adapter

`adapter: ssh-session` carries a native SSH connection inside one authenticated
full-duplex HTTPS request. The outer layer retains Forcefield's bearer,
source-IP/mTLS workload identity, route, limits, and fail-closed audit boundary.
The inner layer is terminated by Forcefield; it never reaches the upstream as
an opaque TCP tunnel.

After authorization, Forcefield retrieves the configured private key, dials
the fixed `ssh://host:port` through the resolve-once CIDR guard, verifies one
of the configured exact host-key fingerprints, and authenticates as the fixed
upstream user. Only then does it commit HTTP 200 and perform the guest-side SSH
handshake. The inner process-local host key is pinned by a response header
authenticated by the outer TLS connection; the guest presents no second
credential. The `ff_` bearer remains an HTTPS credential and is never sent in
the SSH protocol. The guest handshake has a 10-second deadline, further bounded
by token expiry and policy duration.

One tunnel accepts exactly one `session` channel. Structurally validated
shell, exec, PTY, window-change, break, and signal requests are relayed only
when the immutable SSH policy permits them. Direct/remote forwarding,
additional channels, agent and X11 forwarding, environment requests, and
subsystems are rejected locally. Supported SSH algorithms come from Go's
non-insecure algorithm set; neither host SSH configuration nor `SSH_AUTH_SOCK`
is consulted. RSA login and host keys must be at least 2048 bits, and RSA login
authentication permits RSA-SHA2-256/512 rather than legacy `ssh-rsa`/SHA-1.
The target sees the configured login public key and signatures proving
possession, but never receives private-key bytes.

The session deadline is `min(token expiry, policy max_session_duration)` and is
installed on both SSH legs and the HTTP stream. The same bearer, workload,
token/root identity, concrete grant, revisions, and delegation limit chain are
revalidated once per second; failure closes both sides. Decoded guest-to-target
session-channel input and the raw payload of each allowed session request
actually forwarded upstream consume the delegation-wide byte budget and
per-session ceiling. HTTP/SSH framing, encryption overhead, rejected request
payloads, and replies do not. Independently, channel opens and global/session
request attempts are capped at 64 per second with burst 128 and 4096 total per
session, including rejected attempts. Audit records contain metadata and byte
counts, never command strings or terminal contents.

The outer HTTP exchange must remain full duplex. Direct TLS/mTLS is preferred;
any reverse proxy must stream request and response bodies simultaneously
without buffering. Forcefield accepts HTTP/1.1 chunked or HTTP/2 for the stream;
prefer HTTP/2 over TLS when proxying. A buffering proxy deadlocks the SSH
transport, while TLS termination or peer-address rewriting also changes the
workload identity visible to Forcefield.

Shell and arbitrary exec permission are necessarily coarse. Rejected SSH port
forwarding, agent/X11, environment, and subsystem requests do not prevent a
shell command from reading files or opening network connections. Once granted,
the configured Unix account, sshd/`authorized_keys` restrictions, sudoers,
target filesystem, services, and target egress policy define the real authority.
Disconnecting cannot undo completed actions or reliably kill a process
deliberately detached on the target.

## Response boundary

By default Forcefield removes `Set-Cookie`, `Authentication-Info`,
`Proxy-Authenticate`, `Alt-Svc`, `Refresh`, and `Link`, plus operator-configured
headers. It rejects userinfo or cross-origin redirects. A same-origin redirect
inside the configured upstream base is rewritten through the public Forcefield
path so the client's next request is authorized again.

Only final HTTP statuses from 200 through 599 may cross the upstream boundary.
All 1xx responses, including protocol switching, and invalid statuses above 599
are rejected rather than forwarded.

Because `Link` remains stripped, clients must send explicit pagination query
parameters covered by policy instead of depending on an upstream pagination
link.

The guard checks each remaining header and the streamed body for the exact
secret byte string. It pre-reads up to 32 KiB through that filter before
committing response headers, then streams the remainder. `require_identity`
defaults to true and rejects an encoded upstream response, because compressed
bytes cannot be searched for the plain secret. Forwarded responses are marked
`Cache-Control: no-store`; upstream cache expiry metadata is removed. This is
useful defense in depth, but cannot detect base64, URL-encoded, encrypted,
split-and-transformed, or otherwise derived secret material. The
[threat model](threat-model.md#response-reflection-and-a-malicious-upstream)
describes the residual risk.

## Adapter boundary and roadmap

Forcefield should keep specialized authentication outside the generic header
adapter:

- **AWS SigV4:** requires a signer that hashes and signs the exact canonical
  request, or a credential-vending endpoint that returns narrowly scoped,
  short-lived native credentials. Static header replacement is incorrect.
- **`gh` and Git extensions:** `gh` has host and credential-selection behavior
  beyond a simple arbitrary API base URL. Git LFS, dumb HTTP, signed pushes,
  push options, and protocol-v2 push are outside the smart-HTTP adapter's
  deliberately small surface and need explicit designs before support.
- **OCI/Docker registries:** the bearer challenge and token-service exchange
  create multiple pinned authorities and scope negotiation. This needs a
  registry adapter, not a permissive second destination.
- **Upstream mTLS:** requires host-side certificate/key selection and a service
  transport adapter. The current TLS settings cover inbound workload mTLS only.
- **Other SSH modes:** the terminating session adapter does not issue SSH
  certificates, proxy arbitrary destinations, expose SFTP, or provide port,
  agent, X11, or raw TCP forwarding. Those require separate threat models and
  must not broaden the existing pinned session boundary.
- **High-impact operations:** when method/path/body filtering cannot express a
  safe boundary, expose a narrow semantic operation that pins non-overridable
  fields instead of transparently proxying the provider API.

Adapters should preserve the same invariant: the configured service determines
every possible upstream authority, authorization happens before credential
access, and the representation authorized is the representation signed or sent.

## Process and persistence model

One `ff serve` process owns the data listener, admin socket, in-memory limit
state, secret cache, append-only audit writer, and token store. Token mutations
are persisted with a 0600 temporary file, fsync, atomic rename, and directory
sync. Only SHA-256 bearer digests and claims are stored; newly minted bearer
material is returned once.

There is no runtime config reload. Restart to load configuration. On Linux and
macOS the store owns a non-blocking exclusive lock file for its lifetime; a
second process targeting the same token file fails closed, and platforms
without the required lock are unsupported. Expired or revoked records and
their inactive descendant subtrees are durably pruned on open and before token
mutations. Rate and byte accounting is in memory and resets on restart; active
token records and revocation state persist until they become pruneable.
