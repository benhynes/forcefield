package tokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	storeFileVersion            = 1
	maxStoreFileSize            = 64 << 20
	minimumStoreFileSize        = 4 << 10
	fixedRevocationHeadroom     = 4 << 10
	perRecordRevocationHeadroom = 128
)

type diskState struct {
	Version int          `json:"version"`
	Records []diskRecord `json:"records"`
}

type diskRecord struct {
	Hash            string     `json:"hash"`
	Parent          string     `json:"parent,omitempty"`
	Root            string     `json:"root"`
	Workload        string     `json:"workload"`
	Audience        string     `json:"audience"`
	IssuedAt        time.Time  `json:"issued_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Grants          []Grant    `json:"grants"`
	AllowDelegation bool       `json:"allow_delegation,omitempty"`
	Depth           int        `json:"depth"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// load returns false when the store does not yet exist.
func (s *Store) load() (bool, error) {
	dir := filepath.Dir(s.path)
	if err := ensureSecureDirectory(dir); err != nil {
		return false, err
	}

	pathInfo, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect token store: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %s", ErrSymlink, s.path)
	}
	if !pathInfo.Mode().IsRegular() {
		return false, fmt.Errorf("%w: token store is not a regular file", ErrInsecurePermissions)
	}
	if pathInfo.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("%w: token store mode is %04o, want 0600", ErrInsecurePermissions, pathInfo.Mode().Perm())
	}
	if err := ensureCurrentOwner(pathInfo, "token store"); err != nil {
		return false, err
	}

	file, err := os.Open(s.path)
	if err != nil {
		return false, fmt.Errorf("open token store: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat open token store: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return false, fmt.Errorf("%w: token store changed while opening", ErrSymlink)
	}
	if err := ensureCurrentOwner(openedInfo, "token store"); err != nil {
		return false, err
	}
	if openedInfo.Size() > int64(s.opts.storeFileSizeLimit) {
		return false, fmt.Errorf("%w: token store exceeds %d bytes", ErrCorruptStore, s.opts.storeFileSizeLimit)
	}

	contents, err := io.ReadAll(io.LimitReader(file, int64(s.opts.storeFileSizeLimit)+1))
	if err != nil {
		return false, fmt.Errorf("read token store: %w", err)
	}
	if len(contents) > s.opts.storeFileSizeLimit {
		return false, fmt.Errorf("%w: token store exceeds %d bytes", ErrCorruptStore, s.opts.storeFileSizeLimit)
	}
	records, err := decodeDiskState(contents, s.opts)
	if err != nil {
		return false, err
	}
	s.records = records
	return true, nil
}

// persist reports whether rename reached its atomic commit point separately
// from any later directory-sync error. Callers install records in memory once
// committed even when durability confirmation fails, keeping the live view
// consistent with the path that future writes would replace.
func (s *Store) persist(records map[tokenHash]record) (bool, error) {
	dir := filepath.Dir(s.path)
	if err := ensureSecureDirectory(dir); err != nil {
		return false, err
	}
	if err := inspectDestination(s.path); err != nil {
		return false, err
	}

	contents, err := encodeDiskState(records)
	if err != nil {
		return false, err
	}
	if len(contents) > s.opts.storeFileSizeLimit {
		return false, fmt.Errorf("token store state exceeds %d bytes", s.opts.storeFileSizeLimit)
	}

	temp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create token-store temporary file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		return false, fmt.Errorf("set token-store temporary permissions: %w", err)
	}
	if err := writeAll(temp, contents); err != nil {
		return false, fmt.Errorf("write token-store temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return false, fmt.Errorf("sync token-store temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return false, fmt.Errorf("close token-store temporary file: %w", err)
	}

	// Recheck immediately before the commit. Rename replaces a symlink rather
	// than following it, but rejecting one keeps external tampering visible.
	if err := inspectDestination(s.path); err != nil {
		return false, err
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return false, fmt.Errorf("commit token store: %w", err)
	}
	committed = true

	directory, err := os.Open(dir)
	if err != nil {
		return true, fmt.Errorf("open token-store directory for sync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return true, fmt.Errorf("sync token-store directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return true, fmt.Errorf("close token-store directory: %w", err)
	}
	return true, nil
}

func ensureSecureDirectory(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve token-store directory: %w", err)
	}
	absDir = filepath.Clean(absDir)

	// Discover the nearest existing ancestor before creating anything. Unlike
	// os.MkdirAll, this lets us reject a symlink in that ancestor path before
	// it can redirect directory creation somewhere the caller did not intend.
	current := absDir
	var missing []string
	for {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s", ErrSymlink, current)
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: token-store ancestor is not a directory", ErrInsecurePermissions)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect token-store directory: %w", statErr)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("create token-store directory: no existing ancestor")
		}
		current = parent
	}
	resolvedAncestor, err := filepath.EvalSymlinks(current)
	if err != nil {
		return fmt.Errorf("resolve token-store directory symlinks: %w", err)
	}
	if filepath.Clean(resolvedAncestor) != filepath.Clean(current) {
		return fmt.Errorf("%w: %s", ErrSymlink, current)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		if err := os.Mkdir(missing[index], 0o700); err != nil {
			return fmt.Errorf("create token-store directory: %w", err)
		}
	}

	resolved, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return fmt.Errorf("resolve token-store directory symlinks: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(absDir) {
		return fmt.Errorf("%w: %s", ErrSymlink, dir)
	}
	info, err := os.Lstat(absDir)
	if err != nil {
		return fmt.Errorf("inspect token-store directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: token-store parent is not a directory", ErrInsecurePermissions)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: token-store directory mode is %04o", ErrInsecurePermissions, info.Mode().Perm())
	}
	if err := ensureCurrentOwner(info, "token-store directory"); err != nil {
		return err
	}
	return nil
}

func inspectDestination(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect token-store destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: token-store destination is not a regular file", ErrInsecurePermissions)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: token store mode is %04o, want 0600", ErrInsecurePermissions, info.Mode().Perm())
	}
	return ensureCurrentOwner(info, "token store")
}

func encodeDiskState(records map[tokenHash]record) ([]byte, error) {
	hashes := make([]tokenHash, 0, len(records))
	for hash := range records {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool {
		return tokenID(hashes[i]) < tokenID(hashes[j])
	})

	state := diskState{Version: storeFileVersion, Records: make([]diskRecord, 0, len(records))}
	for _, hash := range hashes {
		rec := records[hash]
		disk := diskRecord{
			Hash:            tokenID(rec.hash),
			Root:            tokenID(rec.root),
			Workload:        rec.workload,
			Audience:        rec.audience,
			IssuedAt:        rec.issuedAt,
			ExpiresAt:       rec.expiresAt,
			Grants:          cloneGrants(rec.grants),
			AllowDelegation: rec.allowDelegation,
			Depth:           rec.depth,
		}
		if rec.depth > 0 {
			disk.Parent = tokenID(rec.parent)
		}
		if rec.revokedAt != nil {
			revokedAt := *rec.revokedAt
			disk.RevokedAt = &revokedAt
		}
		state.Records = append(state.Records, disk)
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		return nil, fmt.Errorf("encode token store: %w", err)
	}
	return buffer.Bytes(), nil
}

func decodeDiskState(contents []byte, opts Options) (map[tokenHash]record, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var state diskState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrCorruptStore, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing JSON value", ErrCorruptStore)
		}
		return nil, fmt.Errorf("%w: trailing data: %v", ErrCorruptStore, err)
	}
	if state.Version != storeFileVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptStore, state.Version)
	}
	if len(state.Records) > hardMaxRecords {
		return nil, fmt.Errorf("%w: record count exceeds hard bound", ErrCorruptStore)
	}

	records := make(map[tokenHash]record, len(state.Records))
	for index, disk := range state.Records {
		hash, err := parseTokenID(disk.Hash)
		if err != nil {
			return nil, corruptRecord(index, "invalid token hash")
		}
		if _, duplicate := records[hash]; duplicate {
			return nil, corruptRecord(index, "duplicate token hash")
		}
		root, err := parseTokenID(disk.Root)
		if err != nil {
			return nil, corruptRecord(index, "invalid root hash")
		}
		var parent tokenHash
		if disk.Depth > 0 {
			parent, err = parseTokenID(disk.Parent)
			if err != nil {
				return nil, corruptRecord(index, "invalid parent hash")
			}
		} else if disk.Parent != "" {
			return nil, corruptRecord(index, "root token has a parent")
		}
		if disk.Depth < 0 || disk.Depth > opts.MaxDelegationDepth {
			return nil, corruptRecord(index, "invalid delegation depth")
		}
		if err := validateBinding(disk.Workload, disk.Audience); err != nil {
			return nil, corruptRecord(index, "invalid binding")
		}
		if err := validateGrantSet(disk.Grants, opts.MaxGrantsPerToken); err != nil {
			return nil, corruptRecord(index, "invalid grants")
		}
		issuedAt := canonicalTime(disk.IssuedAt)
		expiresAt := canonicalTime(disk.ExpiresAt)
		if issuedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(issuedAt) {
			return nil, corruptRecord(index, "invalid lifetime")
		}
		var revokedAt *time.Time
		if disk.RevokedAt != nil {
			canonical := canonicalTime(*disk.RevokedAt)
			if canonical.IsZero() {
				return nil, corruptRecord(index, "invalid revocation time")
			}
			revokedAt = &canonical
		}
		records[hash] = record{
			hash:            hash,
			parent:          parent,
			root:            root,
			workload:        disk.Workload,
			audience:        disk.Audience,
			issuedAt:        issuedAt,
			expiresAt:       expiresAt,
			grants:          cloneGrants(disk.Grants),
			allowDelegation: disk.AllowDelegation,
			depth:           disk.Depth,
			revokedAt:       revokedAt,
		}
	}

	if err := validateLoadedRecords(records, opts); err != nil {
		return nil, err
	}
	return records, nil
}

func validateLoadedRecords(records map[tokenHash]record, opts Options) error {
	for hash, rec := range records {
		if rec.depth == 0 {
			if rec.root != hash || rec.parent != (tokenHash{}) {
				return nilCorrupt("invalid root lineage")
			}
		} else {
			parent, ok := records[rec.parent]
			if !ok {
				return nilCorrupt("missing parent")
			}
			if parent.depth+1 != rec.depth || parent.root != rec.root {
				return nilCorrupt("invalid parent lineage")
			}
			if !parent.allowDelegation {
				return nilCorrupt("parent did not permit delegation")
			}
			if rec.audience != parent.audience {
				return nilCorrupt("delegated audience changed")
			}
			if rec.expiresAt.After(parent.expiresAt) {
				return nilCorrupt("delegated expiry broadened")
			}
			if !grantsAreSubset(rec.grants, parent.grants) {
				return nilCorrupt("delegated grants broadened")
			}
			if parent.revokedAt != nil && rec.revokedAt == nil {
				return nilCorrupt("revocation did not cascade")
			}
		}
		root, ok := records[rec.root]
		if !ok || root.depth != 0 || root.root != rec.root {
			return nilCorrupt("missing root")
		}
	}
	return nil
}

func validateLoadedBounds(records map[tokenHash]record, opts Options) error {
	if len(records) > opts.MaxRecords {
		return nilCorrupt("record count exceeds configured bound")
	}
	children := make(map[tokenHash]int)
	roots := make(map[tokenHash]int)
	for _, rec := range records {
		roots[rec.root]++
		if rec.depth > 0 {
			children[rec.parent]++
		}
	}
	for _, count := range children {
		if count > opts.MaxChildrenPerToken {
			return nilCorrupt("child count exceeds configured bound")
		}
	}
	for _, count := range roots {
		if count > opts.MaxTokensPerRoot {
			return nilCorrupt("root token count exceeds configured bound")
		}
	}
	return nil
}

func corruptRecord(index int, reason string) error {
	return fmt.Errorf("%w: record %d: %s", ErrCorruptStore, index, reason)
}

func nilCorrupt(reason string) error {
	return fmt.Errorf("%w: %s", ErrCorruptStore, reason)
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}
