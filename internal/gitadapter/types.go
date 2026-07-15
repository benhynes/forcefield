package gitadapter

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidRoute    = errors.New("git adapter: invalid smart HTTP route")
	ErrInvalidProtocol = errors.New("git adapter: invalid receive-pack protocol")
	ErrInvalidRef      = errors.New("git adapter: invalid ref name")
	ErrLimitExceeded   = errors.New("git adapter: resource limit exceeded")
	ErrUnsupported     = errors.New("git adapter: unsupported protocol feature")
	ErrInvalidPolicy   = errors.New("git adapter: invalid policy")
)

type Service string

const (
	ServiceUploadPack  Service = "git-upload-pack"
	ServiceReceivePack Service = "git-receive-pack"
)

// RepositoryCaseMode declares how an upstream maps URL repository names to
// repository identities. The operator must choose because folding names for a
// case-sensitive server can conflate distinct repositories, while preserving
// case for a case-insensitive server can make an exact deny bypassable.
type RepositoryCaseMode string

const (
	RepositoryCaseSensitive        RepositoryCaseMode = "sensitive"
	RepositoryCaseASCIIInsensitive RepositoryCaseMode = "ascii-insensitive"
)

// NormalizeRepository returns the identity used by policy. ASCII-insensitive
// mode deliberately rejects non-ASCII names rather than guessing at an
// upstream's Unicode normalization and case-folding behavior.
func NormalizeRepository(value string, mode RepositoryCaseMode) (string, error) {
	switch mode {
	case RepositoryCaseSensitive:
		return value, nil
	case RepositoryCaseASCIIInsensitive:
		result := []byte(value)
		for index, current := range result {
			if current >= 0x80 {
				return "", fmt.Errorf("%w: non-ASCII repository in ASCII-insensitive mode", ErrInvalidRoute)
			}
			if current >= 'A' && current <= 'Z' {
				result[index] = current + ('a' - 'A')
			}
		}
		return string(result), nil
	default:
		return "", fmt.Errorf("%w: unknown repository case mode", ErrInvalidPolicy)
	}
}

type RoutePhase string

const (
	RouteDiscovery RoutePhase = "discovery"
	RouteRPC       RoutePhase = "rpc"
)

// Route is a classified smart-HTTP endpoint. Repository is the canonical URL
// path before the Git service suffix, without a leading or trailing slash.
type Route struct {
	Repository string
	Service    Service
	Phase      RoutePhase
	// ContentType is the required request content type for RPC routes. It is
	// empty for discovery routes, whose GET request body has no media type.
	ContentType string
}

type ObjectFormat string

const (
	ObjectFormatSHA1   ObjectFormat = "sha1"
	ObjectFormatSHA256 ObjectFormat = "sha256"
)

func (f ObjectFormat) oidHexLength() int {
	switch f {
	case ObjectFormatSHA1:
		return 40
	case ObjectFormatSHA256:
		return 64
	default:
		return 0
	}
}

type UpdateKind string

const (
	UpdateCreate UpdateKind = "create"
	UpdateModify UpdateKind = "update"
	UpdateDelete UpdateKind = "delete"
)

type Update struct {
	OldOID string
	NewOID string
	Ref    string
	Kind   UpdateKind
}

type ReceivePackKind string

const (
	ReceivePackProbe ReceivePackKind = "probe"
	ReceivePackNoop  ReceivePackKind = "noop"
	ReceivePackPush  ReceivePackKind = "push"
)

// ReceivePackRequest is the policy-relevant portion of a receive-pack RPC.
// OIDs are canonical lowercase hexadecimal strings. Capabilities retain their
// canonical wire spelling, but callers should use the explicit booleans for
// policy decisions.
type ReceivePackRequest struct {
	Kind         ReceivePackKind
	ObjectFormat ObjectFormat
	Updates      []Update
	ShallowOIDs  []string
	Capabilities []string
	PushOptions  []string
	// PushOptionsNegotiated records the wire capability even when the client
	// sends an empty option list. Policy must not infer negotiation from
	// len(PushOptions), because that would let an unsupported feature through.
	PushOptionsNegotiated bool
	Signed                bool
	Atomic                bool
	HasPack               bool
	ReportStatus          bool
	ReportStatusV2        bool
}

// ParsedReceivePack owns a one-shot reconstruction of the decoded request
// body. PrefixBytes returns the bytes consumed by the parser. Body returns the
// exact consumed prefix followed by the unread pack stream.
type ParsedReceivePack struct {
	Request   ReceivePackRequest
	prefix    []byte
	remainder io.Reader
}

func (p *ParsedReceivePack) PrefixBytes() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.prefix...)
}

func (p *ParsedReceivePack) Body() io.Reader {
	if p == nil {
		return nil
	}
	if p.remainder == nil {
		return newBytesReader(p.prefix)
	}
	return io.MultiReader(newBytesReader(p.prefix), p.remainder)
}
