// Package tokens issues and validates short-lived Forcefield capability tokens.
//
// A Store never persists bearer-token material. It persists only SHA-256 token
// digests and the immutable claims associated with those digests. Callers must
// therefore treat the Bearer returned by Mint or Delegate as a write-only
// secret: it cannot be recovered from the store.
package tokens

import (
	"errors"
	"io"
	"time"
)

const (
	// BearerPrefix makes Forcefield tokens easy to identify and redact. The
	// suffix is the unpadded base64url encoding of 32 random bytes.
	BearerPrefix = "ff_"
	// BearerLength is the exact encoded length of a Forcefield bearer. It is
	// exported so secret-free projections can reject embedded bearer material
	// without accepting arbitrary ff_-prefixed prose as a secret.
	BearerLength = 46

	defaultMaxDelegationDepth  = 4
	defaultMaxChildrenPerToken = 32
	defaultMaxTokensPerRoot    = 256
	defaultMaxGrantsPerToken   = 64
	defaultMaxRecords          = 16_384
	hardMaxRecords             = 65_536
)

var (
	// ErrInvalidToken intentionally covers unknown, malformed, expired,
	// revoked, and incorrectly bound tokens. Validation does not reveal which
	// check failed.
	ErrInvalidToken = errors.New("invalid token")

	ErrInvalidRequest       = errors.New("invalid token request")
	ErrDelegationNotAllowed = errors.New("token does not permit delegation")
	ErrExpiryBroadening     = errors.New("child expiry exceeds parent expiry")
	ErrGrantBroadening      = errors.New("child grants broaden parent grants")
	ErrDelegationDepth      = errors.New("maximum delegation depth exceeded")
	ErrChildLimit           = errors.New("maximum children per token exceeded")
	ErrRootTokenLimit       = errors.New("maximum tokens per root exceeded")
	ErrEntropy              = errors.New("could not generate a unique token")
	ErrInsecurePermissions  = errors.New("insecure token-store permissions")
	ErrSymlink              = errors.New("token-store path contains a symlink")
	ErrCorruptStore         = errors.New("corrupt token store")
	// ErrStoreLocked means another process or Store instance currently owns
	// the exclusive lock for this token-store path.
	ErrStoreLocked = errors.New("token store is already open")
	// ErrStoreClosed is returned by operations attempted after Close.
	ErrStoreClosed = errors.New("token store is closed")
	// ErrLockUnsupported means the current platform cannot provide the held,
	// cross-process lock required to open a Store safely.
	ErrLockUnsupported = errors.New("token-store locking is unsupported on this platform")
	// ErrRecordLimit covers both the configured global record ceiling and the
	// on-disk capacity guard that preserves room for revocation metadata.
	ErrRecordLimit = errors.New("maximum token-store records or capacity exceeded")
)

// Limits are ceilings attached to a concrete grant. Zero means unlimited for
// every field. A delegated limit may stay equal or become more restrictive,
// but it may never change from a finite parent value to zero or to a larger
// value.
type Limits struct {
	RequestsPerSecond uint64 `json:"requests_per_second,omitempty"`
	Burst             uint64 `json:"burst,omitempty"`
	RequestBudget     uint64 `json:"request_budget,omitempty"`
	ByteBudget        uint64 `json:"byte_budget,omitempty"`
	MaxRequestBytes   uint64 `json:"max_request_bytes,omitempty"`
}

// Grant is concrete authority over one configured service. CredentialRef and
// PolicyRevision are immutable identifiers resolved by other Forcefield
// components; tokens never contain credential material.
type Grant struct {
	Service         string `json:"service"`
	CredentialRef   string `json:"credential_ref"`
	PolicyRevision  string `json:"policy_revision"`
	BindingRevision string `json:"binding_revision"`
	Limits          Limits `json:"limits,omitempty"`
}

// MintRequest describes a new root token. All fields are mandatory except
// AllowDelegation. ExpiresAt must be in the future.
type MintRequest struct {
	Workload        string    `json:"workload"`
	Audience        string    `json:"audience"`
	ExpiresAt       time.Time `json:"expires_at"`
	Grants          []Grant   `json:"grants"`
	AllowDelegation bool      `json:"allow_delegation,omitempty"`
}

// DelegateRequest describes a child token. CallerWorkload and Audience bind
// use of the parent token to the caller. Workload binds the resulting child
// and may differ from CallerWorkload.
type DelegateRequest struct {
	CallerWorkload  string    `json:"caller_workload"`
	Audience        string    `json:"audience"`
	Workload        string    `json:"workload"`
	ExpiresAt       time.Time `json:"expires_at"`
	Grants          []Grant   `json:"grants"`
	AllowDelegation bool      `json:"allow_delegation,omitempty"`
}

// ValidationRequest supplies the non-secret context to which a token must be
// bound. Both fields are mandatory.
type ValidationRequest struct {
	Workload string `json:"workload"`
	Audience string `json:"audience"`
}

// Claims is a detached, immutable snapshot of a token record. Mutating Grants
// in a returned Claims value does not mutate the Store.
type Claims struct {
	TokenID         string     `json:"token_id"`
	ParentTokenID   string     `json:"parent_token_id,omitempty"`
	RootTokenID     string     `json:"root_token_id"`
	Workload        string     `json:"workload"`
	Audience        string     `json:"audience"`
	IssuedAt        time.Time  `json:"issued_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Grants          []Grant    `json:"grants"`
	AllowDelegation bool       `json:"allow_delegation"`
	Depth           int        `json:"depth"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`

	// LimitChain is the immutable root-to-leaf delegation chain used by the
	// in-process gateway to enforce every ancestor's aggregate limits. It is
	// deliberately omitted from control-plane JSON: callers only need their
	// own grants, while the broker can reconstruct the chain on validation.
	LimitChain []LimitScope `json:"-"`
}

// LimitScope identifies one token in a validated delegation chain and the
// grants whose limits bound that token and all of its descendants.
type LimitScope struct {
	TokenID   string
	ExpiresAt time.Time
	Grants    []Grant
}

// IssuedToken contains the only copy of newly generated bearer material that
// the Store will return. Claims does not contain that material.
type IssuedToken struct {
	Bearer string `json:"bearer"`
	Claims Claims `json:"claims"`
}

// Options sets resource bounds and provides deterministic hooks for tests.
// Zero-valued bounds receive conservative defaults. Rand and Now default to
// crypto/rand.Reader and time.Now.
type Options struct {
	MaxDelegationDepth  int
	MaxChildrenPerToken int
	MaxTokensPerRoot    int
	MaxGrantsPerToken   int
	MaxRecords          int

	Rand io.Reader
	Now  func() time.Time

	// storeFileSizeLimit is an internal test hook. Production callers always
	// receive the fixed 64 MiB corruption ceiling.
	storeFileSizeLimit int
}
