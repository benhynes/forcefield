package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const tokenBytes = 32

type tokenHash [sha256.Size]byte

type record struct {
	hash            tokenHash
	parent          tokenHash
	root            tokenHash
	workload        string
	audience        string
	issuedAt        time.Time
	expiresAt       time.Time
	grants          []Grant
	allowDelegation bool
	depth           int
	revokedAt       *time.Time
}

// Store is a thread-safe persistent token store.
type Store struct {
	mu      sync.RWMutex
	path    string
	records map[tokenHash]record
	opts    Options
	lock    *storeLock
	closed  bool
}

// Open loads or creates the store at path. A newly created file is persisted
// immediately with mode 0600.
func Open(path string, opts Options) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty store path", ErrInvalidRequest)
	}

	normalized, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve token store path: %w", err)
	}
	store := &Store{
		path:    absPath,
		records: make(map[tokenHash]record),
		opts:    normalized,
	}

	if err := ensureSecureDirectory(filepath.Dir(absPath)); err != nil {
		return nil, err
	}
	lock, err := acquireStoreLock(absPath + ".lock")
	if err != nil {
		return nil, err
	}
	store.lock = lock
	success := false
	defer func() {
		if !success {
			_ = store.Close()
		}
	}()

	found, err := store.load()
	if err != nil {
		return nil, err
	}
	pruned, changed := pruneInactive(store.records, canonicalTime(store.opts.Now()))
	if changed {
		store.records = pruned
	}
	if err := validateLoadedBounds(store.records, store.opts); err != nil {
		return nil, err
	}
	if err := store.ensureRevocationCapacity(store.records); err != nil {
		return nil, fmt.Errorf("%w: loaded state has no revocation headroom: %w", ErrCorruptStore, err)
	}
	if !found || changed {
		if _, err := store.persist(store.records); err != nil {
			return nil, err
		}
	}
	success = true
	return store, nil
}

// Close releases the held cross-process lock. It is safe to call repeatedly
// and waits for any in-flight Store operation to finish.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	lock := s.lock
	s.lock = nil
	if lock == nil {
		return nil
	}
	return lock.close()
}

// Mint creates a new root token. The bearer is returned exactly once and is
// never retained by the Store.
func (s *Store) Mint(ctx context.Context, req MintRequest) (IssuedToken, error) {
	if err := contextErr(ctx); err != nil {
		return IssuedToken{}, err
	}
	if err := validateBinding(req.Workload, req.Audience); err != nil {
		return IssuedToken{}, err
	}
	if err := validateGrantSet(req.Grants, s.opts.MaxGrantsPerToken); err != nil {
		return IssuedToken{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return IssuedToken{}, ErrStoreClosed
	}
	if err := contextErr(ctx); err != nil {
		return IssuedToken{}, err
	}
	now := canonicalTime(s.opts.Now())
	if err := s.pruneLocked(now); err != nil {
		return IssuedToken{}, err
	}
	expiresAt := canonicalTime(req.ExpiresAt)
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return IssuedToken{}, fmt.Errorf("%w: expiry must be in the future", ErrInvalidRequest)
	}

	bearer, hash, err := s.generateUniqueTokenLocked()
	if err != nil {
		return IssuedToken{}, err
	}
	rec := record{
		hash:            hash,
		root:            hash,
		workload:        req.Workload,
		audience:        req.Audience,
		issuedAt:        now,
		expiresAt:       expiresAt,
		grants:          cloneGrants(req.Grants),
		allowDelegation: req.AllowDelegation,
	}

	next := cloneRecords(s.records)
	next[hash] = rec
	if err := s.ensureAppendCapacity(next); err != nil {
		return IssuedToken{}, err
	}
	committed, err := s.persist(next)
	if committed {
		s.records = next
	}
	if err != nil {
		return IssuedToken{}, err
	}

	return IssuedToken{Bearer: bearer, Claims: claimsFromRecord(rec, next)}, nil
}

// Delegate creates a child of parentBearer. The child can only narrow the
// parent's expiry and concrete grant limits.
func (s *Store) Delegate(ctx context.Context, parentBearer string, req DelegateRequest) (IssuedToken, error) {
	if err := contextErr(ctx); err != nil {
		return IssuedToken{}, err
	}
	if err := validateBinding(req.CallerWorkload, req.Audience); err != nil {
		return IssuedToken{}, err
	}
	if err := validateIdentifier("child workload", req.Workload, 512); err != nil {
		return IssuedToken{}, err
	}
	if err := validateGrantSet(req.Grants, s.opts.MaxGrantsPerToken); err != nil {
		return IssuedToken{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return IssuedToken{}, ErrStoreClosed
	}
	if err := contextErr(ctx); err != nil {
		return IssuedToken{}, err
	}
	now := canonicalTime(s.opts.Now())
	if err := s.pruneLocked(now); err != nil {
		return IssuedToken{}, err
	}
	parent, ok := s.validateLocked(parentBearer, ValidationRequest{
		Workload: req.CallerWorkload,
		Audience: req.Audience,
	}, now)
	if !ok {
		return IssuedToken{}, ErrInvalidToken
	}
	if !parent.allowDelegation {
		return IssuedToken{}, ErrDelegationNotAllowed
	}
	if parent.depth+1 > s.opts.MaxDelegationDepth {
		return IssuedToken{}, ErrDelegationDepth
	}

	expiresAt := canonicalTime(req.ExpiresAt)
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return IssuedToken{}, fmt.Errorf("%w: expiry must be in the future", ErrInvalidRequest)
	}
	if expiresAt.After(parent.expiresAt) {
		return IssuedToken{}, ErrExpiryBroadening
	}
	if !grantsAreSubset(req.Grants, parent.grants) {
		return IssuedToken{}, ErrGrantBroadening
	}
	if directChildCount(s.records, parent.hash) >= s.opts.MaxChildrenPerToken {
		return IssuedToken{}, ErrChildLimit
	}
	if rootTokenCount(s.records, parent.root) >= s.opts.MaxTokensPerRoot {
		return IssuedToken{}, ErrRootTokenLimit
	}

	bearer, hash, err := s.generateUniqueTokenLocked()
	if err != nil {
		return IssuedToken{}, err
	}
	rec := record{
		hash:            hash,
		parent:          parent.hash,
		root:            parent.root,
		workload:        req.Workload,
		audience:        parent.audience,
		issuedAt:        now,
		expiresAt:       expiresAt,
		grants:          cloneGrants(req.Grants),
		allowDelegation: req.AllowDelegation,
		depth:           parent.depth + 1,
	}

	next := cloneRecords(s.records)
	next[hash] = rec
	if err := s.ensureAppendCapacity(next); err != nil {
		return IssuedToken{}, err
	}
	committed, err := s.persist(next)
	if committed {
		s.records = next
	}
	if err != nil {
		return IssuedToken{}, err
	}

	return IssuedToken{Bearer: bearer, Claims: claimsFromRecord(rec, next)}, nil

}

// Validate authenticates a token and verifies its workload and audience
// binding. Every authentication failure is reported as ErrInvalidToken.
func (s *Store) Validate(ctx context.Context, bearer string, req ValidationRequest) (Claims, error) {
	if err := contextErr(ctx); err != nil {
		return Claims{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return Claims{}, ErrStoreClosed
	}
	if err := contextErr(ctx); err != nil {
		return Claims{}, err
	}
	rec, ok := s.validateLocked(bearer, req, canonicalTime(s.opts.Now()))
	if !ok {
		return Claims{}, ErrInvalidToken
	}
	return claimsFromRecord(rec, s.records), nil
}

// Revoke revokes the identified token and all of its descendants. Revoking an
// already revoked token is idempotent.
func (s *Store) Revoke(ctx context.Context, bearer string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !wellFormedBearer(bearer) {
		return ErrInvalidToken
	}
	return s.revokeHash(ctx, hashToken(bearer))
}

// RevokeTokenID is the control-plane form of Revoke. Token IDs are SHA-256
// digests returned in Claims and do not contain bearer material.
func (s *Store) RevokeTokenID(ctx context.Context, tokenID string) error {
	hash, err := parseTokenID(tokenID)
	if err != nil {
		return ErrInvalidToken
	}
	return s.revokeHash(ctx, hash)
}

func (s *Store) revokeHash(ctx context.Context, hash tokenHash) error {
	if err := contextErr(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	now := canonicalTime(s.opts.Now())
	before, existedBeforePrune := s.records[hash]
	wasInactive := existedBeforePrune && recordOrAncestorInactive(before, s.records, now)
	if err := s.pruneLocked(now); err != nil {
		return err
	}
	if _, ok := s.records[hash]; !ok {
		// Preserve idempotency for a record that this call just pruned. Unknown
		// token IDs remain indistinguishable and fail closed.
		if wasInactive {
			return nil
		}
		return ErrInvalidToken
	}

	next := cloneRecords(s.records)
	children := make(map[tokenHash][]tokenHash)
	for childHash, child := range next {
		if child.depth > 0 {
			children[child.parent] = append(children[child.parent], childHash)
		}
	}
	queue := []tokenHash{hash}
	changed := false
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		rec := next[current]
		if rec.revokedAt == nil {
			revokedAt := now
			rec.revokedAt = &revokedAt
			next[current] = rec
			changed = true
		}
		queue = append(queue, children[current]...)
	}
	if !changed {
		return nil
	}
	committed, err := s.persist(next)
	if committed {
		s.records = next
	}
	if err != nil {
		return err
	}
	return nil
}

// validateLocked deliberately combines every authentication failure into one
// result and uses digest comparisons for the caller-supplied bindings. Go map
// lookup and time comparisons are not strictly constant-time, but no raw token
// or failure reason is compared or returned directly.
func (s *Store) validateLocked(bearer string, req ValidationRequest, now time.Time) (record, bool) {
	formatOK := wellFormedBearer(bearer)
	hash := hashTokenForValidation(bearer, formatOK)
	rec, found := s.records[hash]
	if !found {
		rec = record{expiresAt: time.Unix(0, 0).UTC()}
	}

	valid := boolInt(formatOK) & boolInt(found)
	valid &= constantTimeStringEqual(rec.workload, req.Workload)
	valid &= constantTimeStringEqual(rec.audience, req.Audience)
	valid &= boolInt(req.Workload != "" && req.Audience != "")
	valid &= boolInt(rec.revokedAt == nil)
	valid &= boolInt(now.Before(rec.expiresAt))

	// Validate the entire ancestor chain as defense in depth. Revocation also
	// cascades eagerly, but this prevents an inconsistent persisted descendant
	// from surviving an ancestor revocation.
	current := rec
	for current.depth > 0 {
		parent, ok := s.records[current.parent]
		valid &= boolInt(ok)
		if !ok {
			break
		}
		valid &= boolInt(parent.revokedAt == nil)
		valid &= boolInt(now.Before(parent.expiresAt))
		valid &= boolInt(parent.root == rec.root)
		current = parent
	}
	valid &= boolInt(current.depth == 0 && current.root == rec.root)

	return rec, valid == 1
}

func (s *Store) generateUniqueTokenLocked() (string, tokenHash, error) {
	var random [tokenBytes]byte
	for range 8 {
		if _, err := io.ReadFull(s.opts.Rand, random[:]); err != nil {
			return "", tokenHash{}, fmt.Errorf("%w: %v", ErrEntropy, err)
		}
		bearer := BearerPrefix + base64.RawURLEncoding.EncodeToString(random[:])
		hash := hashToken(bearer)
		if _, exists := s.records[hash]; !exists {
			return bearer, hash, nil
		}
	}
	return "", tokenHash{}, ErrEntropy
}

func normalizeOptions(opts Options) (Options, error) {
	if opts.MaxDelegationDepth < 0 || opts.MaxChildrenPerToken < 0 || opts.MaxTokensPerRoot < 0 || opts.MaxGrantsPerToken < 0 || opts.MaxRecords < 0 {
		return Options{}, fmt.Errorf("%w: resource bounds cannot be negative", ErrInvalidRequest)
	}
	if opts.MaxDelegationDepth == 0 {
		opts.MaxDelegationDepth = defaultMaxDelegationDepth
	}
	if opts.MaxChildrenPerToken == 0 {
		opts.MaxChildrenPerToken = defaultMaxChildrenPerToken
	}
	if opts.MaxTokensPerRoot == 0 {
		opts.MaxTokensPerRoot = defaultMaxTokensPerRoot
	}
	if opts.MaxGrantsPerToken == 0 {
		opts.MaxGrantsPerToken = defaultMaxGrantsPerToken
	}
	if opts.MaxRecords == 0 {
		opts.MaxRecords = defaultMaxRecords
	}
	if opts.MaxDelegationDepth > 64 || opts.MaxChildrenPerToken > 1_000_000 || opts.MaxTokensPerRoot > 1_000_000 || opts.MaxGrantsPerToken > 4096 || opts.MaxRecords > hardMaxRecords {
		return Options{}, fmt.Errorf("%w: resource bound is unreasonably large", ErrInvalidRequest)
	}
	if opts.storeFileSizeLimit == 0 {
		opts.storeFileSizeLimit = maxStoreFileSize
	}
	if opts.storeFileSizeLimit < minimumStoreFileSize || opts.storeFileSizeLimit > maxStoreFileSize {
		return Options{}, fmt.Errorf("%w: invalid store file size limit", ErrInvalidRequest)
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts, nil
}

func validateBinding(workload, audience string) error {
	if err := validateIdentifier("workload", workload, 512); err != nil {
		return err
	}
	return validateIdentifier("audience", audience, 512)
}

func validateIdentifier(name, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: invalid %s", ErrInvalidRequest, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: invalid %s", ErrInvalidRequest, name)
		}
	}
	return nil
}

func validateGrantSet(grants []Grant, max int) error {
	if len(grants) == 0 || len(grants) > max {
		return fmt.Errorf("%w: grant count must be between 1 and %d", ErrInvalidRequest, max)
	}
	type identity struct {
		service, credential, policy string
	}
	seen := make(map[identity]struct{}, len(grants))
	for _, grant := range grants {
		if err := validateIdentifier("grant service", grant.Service, 256); err != nil {
			return err
		}
		if err := validateIdentifier("credential reference", grant.CredentialRef, 1024); err != nil {
			return err
		}
		if err := validateIdentifier("policy revision", grant.PolicyRevision, 256); err != nil {
			return err
		}
		if err := validateIdentifier("binding revision", grant.BindingRevision, 256); err != nil {
			return err
		}
		if grant.Limits.RequestsPerSecond == 0 && grant.Limits.Burst != 0 {
			return fmt.Errorf("%w: burst requires requests_per_second", ErrInvalidRequest)
		}
		key := identity{grant.Service, grant.CredentialRef, grant.PolicyRevision + "\x00" + grant.BindingRevision}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate concrete grant", ErrInvalidRequest)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func grantsAreSubset(child, parent []Grant) bool {
	type identity struct {
		service, credential, policy, binding string
	}
	parents := make(map[identity]Grant, len(parent))
	for _, grant := range parent {
		parents[identity{grant.Service, grant.CredentialRef, grant.PolicyRevision, grant.BindingRevision}] = grant
	}
	for _, grant := range child {
		parentGrant, ok := parents[identity{grant.Service, grant.CredentialRef, grant.PolicyRevision, grant.BindingRevision}]
		if !ok || !limitsNoBroader(grant.Limits, parentGrant.Limits) {
			return false
		}
	}
	return true
}

func limitsNoBroader(child, parent Limits) bool {
	return limitNoBroader(child.RequestsPerSecond, parent.RequestsPerSecond) &&
		burstNoBroader(child, parent) &&
		limitNoBroader(child.RequestBudget, parent.RequestBudget) &&
		limitNoBroader(child.ByteBudget, parent.ByteBudget) &&
		limitNoBroader(child.MaxRequestBytes, parent.MaxRequestBytes)
}

func burstNoBroader(child, parent Limits) bool {
	if parent.RequestsPerSecond == 0 {
		return true
	}
	parentBurst := parent.Burst
	if parentBurst == 0 {
		parentBurst = 1
	}
	childBurst := child.Burst
	if childBurst == 0 {
		childBurst = 1
	}
	return childBurst <= parentBurst
}

func limitNoBroader(child, parent uint64) bool {
	if parent == 0 {
		return true
	}
	return child != 0 && child <= parent
}

func directChildCount(records map[tokenHash]record, parent tokenHash) int {
	count := 0
	for _, rec := range records {
		if rec.parent == parent && rec.depth > 0 {
			count++
		}
	}
	return count
}

func rootTokenCount(records map[tokenHash]record, root tokenHash) int {
	count := 0
	for _, rec := range records {
		if rec.root == root {
			count++
		}
	}
	return count
}

// pruneLocked durably removes records that can never validate again. Removing
// an inactive ancestor removes its entire subtree even if a corrupt clock or a
// legacy file gave a descendant a later expiry.
func (s *Store) pruneLocked(now time.Time) error {
	next, changed := pruneInactive(s.records, now)
	if !changed {
		return nil
	}
	committed, err := s.persist(next)
	if committed {
		s.records = next
	}
	return err
}

func pruneInactive(records map[tokenHash]record, now time.Time) (map[tokenHash]record, bool) {
	remove := make(map[tokenHash]struct{})
	for hash, rec := range records {
		if rec.revokedAt != nil || !now.Before(rec.expiresAt) {
			remove[hash] = struct{}{}
		}
	}
	if len(remove) == 0 {
		return records, false
	}
	for changed := true; changed; {
		changed = false
		for hash, rec := range records {
			if _, already := remove[hash]; already || rec.depth == 0 {
				continue
			}
			if _, parentRemoved := remove[rec.parent]; parentRemoved {
				remove[hash] = struct{}{}
				changed = true
			}
		}
	}
	next := make(map[tokenHash]record, len(records)-len(remove))
	for hash, rec := range records {
		if _, removed := remove[hash]; !removed {
			rec.grants = cloneGrants(rec.grants)
			next[hash] = rec
		}
	}
	return next, true
}

func recordOrAncestorInactive(rec record, records map[tokenHash]record, now time.Time) bool {
	for {
		if rec.revokedAt != nil || !now.Before(rec.expiresAt) {
			return true
		}
		if rec.depth == 0 {
			return false
		}
		parent, ok := records[rec.parent]
		if !ok {
			return true
		}
		rec = parent
	}
}

func (s *Store) ensureAppendCapacity(records map[tokenHash]record) error {
	if len(records) > s.opts.MaxRecords {
		return ErrRecordLimit
	}
	return s.ensureRevocationCapacity(records)
}

func (s *Store) ensureRevocationCapacity(records map[tokenHash]record) error {
	contents, err := encodeDiskState(records)
	if err != nil {
		return err
	}
	// Revocation adds a timestamp to every member of a subtree. Reserve a
	// conservative per-record allowance plus fixed JSON/file overhead so a
	// store filled by successful issuance can always record that revocation.
	reserve := fixedRevocationHeadroom + len(records)*perRecordRevocationHeadroom
	if reserve >= s.opts.storeFileSizeLimit || len(contents) > s.opts.storeFileSizeLimit-reserve {
		return ErrRecordLimit
	}
	return nil
}

func claimsFromRecord(rec record, records map[tokenHash]record) Claims {
	claims := Claims{
		TokenID:         tokenID(rec.hash),
		RootTokenID:     tokenID(rec.root),
		Workload:        rec.workload,
		Audience:        rec.audience,
		IssuedAt:        rec.issuedAt,
		ExpiresAt:       rec.expiresAt,
		Grants:          cloneGrants(rec.grants),
		AllowDelegation: rec.allowDelegation,
		Depth:           rec.depth,
	}
	chain := make([]LimitScope, rec.depth+1)
	current := rec
	for index := rec.depth; index >= 0; index-- {
		chain[index] = LimitScope{
			TokenID: tokenID(current.hash), ExpiresAt: current.expiresAt,
			Grants: cloneGrants(current.grants),
		}
		if index > 0 {
			parent, ok := records[current.parent]
			if !ok {
				// Validation and persistence separately guarantee a complete
				// chain. Keep this defensive branch fail-closed for callers that
				// construct a Store incorrectly in package-level tests.
				chain = nil
				break
			}
			current = parent
		}
	}
	claims.LimitChain = chain
	if rec.depth > 0 {
		claims.ParentTokenID = tokenID(rec.parent)
	}
	if rec.revokedAt != nil {
		revokedAt := *rec.revokedAt
		claims.RevokedAt = &revokedAt
	}
	return claims
}

func cloneGrants(grants []Grant) []Grant {
	return append([]Grant(nil), grants...)
}

func cloneRecords(records map[tokenHash]record) map[tokenHash]record {
	clone := make(map[tokenHash]record, len(records)+1)
	for hash, rec := range records {
		rec.grants = cloneGrants(rec.grants)
		if rec.revokedAt != nil {
			revokedAt := *rec.revokedAt
			rec.revokedAt = &revokedAt
		}
		clone[hash] = rec
	}
	return clone
}

func wellFormedBearer(bearer string) bool {
	if len(bearer) != len(BearerPrefix)+base64.RawURLEncoding.EncodedLen(tokenBytes) || !strings.HasPrefix(bearer, BearerPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(bearer[len(BearerPrefix):])
	if err != nil || len(decoded) != tokenBytes {
		return false
	}
	canonical := BearerPrefix + base64.RawURLEncoding.EncodeToString(decoded)
	return subtle.ConstantTimeCompare([]byte(canonical), []byte(bearer)) == 1
}

func hashToken(bearer string) tokenHash {
	return sha256.Sum256([]byte(bearer))
}

func hashTokenForValidation(bearer string, wellFormed bool) tokenHash {
	if !wellFormed {
		// Avoid hashing an attacker-controlled, unbounded string while keeping
		// the remaining validation path identical.
		return sha256.Sum256([]byte(BearerPrefix + "invalid-token-placeholder"))
	}
	return hashToken(bearer)
}

func constantTimeStringEqual(left, right string) int {
	leftHash := sha256.Sum256([]byte(left))
	var rightHash [sha256.Size]byte
	if len(right) <= 512 {
		rightHash = sha256.Sum256([]byte(right))
	} else {
		// Stored bindings cannot exceed 512 bytes. Hash a fixed placeholder for
		// oversized caller input instead of allocating and hashing without bound.
		rightHash = sha256.Sum256([]byte{0}) // NUL is forbidden in stored bindings.
	}
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:])
}

func tokenID(hash tokenHash) string {
	return hex.EncodeToString(hash[:])
}

func parseTokenID(id string) (tokenHash, error) {
	var hash tokenHash
	if len(id) != hex.EncodedLen(len(hash)) {
		return hash, ErrInvalidToken
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != len(hash) {
		return hash, ErrInvalidToken
	}
	copy(hash[:], decoded)
	return hash, nil
}

func canonicalTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidRequest)
	}
	return ctx.Err()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
