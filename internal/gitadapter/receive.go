package gitadapter

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

type ParseOptions struct {
	MaxPrefixBytes        int
	MaxCommands           int
	MaxShallowOIDs        int
	MaxCapabilities       int
	MaxPushOptions        int
	MaxPushOptionBytes    int
	MaxRefBytes           int
	MaxCertificateBytes   int
	MaxCertificateLines   int
	AllowPushCertificates bool
}

const (
	defaultMaxPrefixBytes      = 1 << 20
	defaultMaxCommands         = 1024
	defaultMaxShallowOIDs      = 1024
	defaultMaxCapabilities     = 64
	defaultMaxPushOptions      = 256
	defaultMaxPushOptionBytes  = 4096
	defaultMaxRefBytes         = 1024
	defaultMaxCertificateBytes = 256 << 10
	defaultMaxCertificateLines = 4096
)

func normalizeParseOptions(opts ParseOptions) (ParseOptions, error) {
	values := []*int{
		&opts.MaxPrefixBytes, &opts.MaxCommands, &opts.MaxShallowOIDs,
		&opts.MaxCapabilities, &opts.MaxPushOptions, &opts.MaxPushOptionBytes,
		&opts.MaxRefBytes, &opts.MaxCertificateBytes, &opts.MaxCertificateLines,
	}
	defaults := [...]int{
		defaultMaxPrefixBytes, defaultMaxCommands, defaultMaxShallowOIDs,
		defaultMaxCapabilities, defaultMaxPushOptions, defaultMaxPushOptionBytes,
		defaultMaxRefBytes, defaultMaxCertificateBytes, defaultMaxCertificateLines,
	}
	for i, value := range values {
		if *value < 0 {
			return ParseOptions{}, fmt.Errorf("%w: negative parser limit", ErrLimitExceeded)
		}
		if *value == 0 {
			*value = defaults[i]
		}
	}
	if opts.MaxPrefixBytes < 4 || opts.MaxRefBytes < len("refs/x") {
		return ParseOptions{}, fmt.Errorf("%w: parser limit too small", ErrLimitExceeded)
	}
	return opts, nil
}

// ParseReceivePackPrefix reads and validates the policy-relevant prefix of a
// decoded receive-pack body. For a push containing a pack, it consumes the
// four-byte PACK signature and leaves the remainder streaming. Probe,
// shallow-only, and delete-only bodies are required to end at the parsed
// prefix. No upstream request should be opened before this function and policy
// evaluation both succeed.
func ParseReceivePackPrefix(body io.Reader, opts ParseOptions) (*ParsedReceivePack, error) {
	if body == nil {
		return nil, fmt.Errorf("%w: nil body", ErrInvalidProtocol)
	}
	var err error
	opts, err = normalizeParseOptions(opts)
	if err != nil {
		return nil, err
	}
	reader, ok := body.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(body, 4096)
	}
	prefix := &prefixBuffer{max: opts.MaxPrefixBytes}
	request := ReceivePackRequest{Kind: ReceivePackPush, ObjectFormat: ObjectFormatSHA1}
	var rawShallows []string
	seenCarrier := false
	signedCarrier := false

	for {
		pkt, readErr := readPacket(reader, prefix)
		if readErr != nil {
			return nil, readErr
		}
		switch pkt.kind {
		case packetDelimiter, packetResponseEnd:
			return nil, fmt.Errorf("%w: v2 marker in receive-pack request", ErrInvalidProtocol)
		case packetFlush:
			if !seenCarrier {
				if err := requireEOF(reader); err != nil {
					return nil, err
				}
				if len(rawShallows) == 0 {
					request.Kind = ReceivePackProbe
				} else {
					format, err := inferShallowFormat(rawShallows)
					if err != nil {
						return nil, err
					}
					request.Kind = ReceivePackNoop
					request.ObjectFormat = format
					request.ShallowOIDs = canonicalizeOIDs(rawShallows)
				}
				return &ParsedReceivePack{Request: request, prefix: prefix.Bytes(), remainder: reader}, nil
			}
			goto commandsDone
		case packetData:
			line, err := protocolLine(pkt.payload)
			if err != nil {
				return nil, err
			}
			if !seenCarrier && bytes.HasPrefix(line, []byte("shallow ")) {
				if len(rawShallows) >= opts.MaxShallowOIDs {
					return nil, ErrLimitExceeded
				}
				oid := string(line[len("shallow "):])
				if !validUnboundOID(oid) {
					return nil, fmt.Errorf("%w: invalid shallow object id", ErrInvalidProtocol)
				}
				rawShallows = append(rawShallows, oid)
				continue
			}
			if !seenCarrier {
				command, capabilities, cert, err := parseFirstCarrier(line, opts)
				if err != nil {
					return nil, err
				}
				request.Capabilities = capabilities.tokens
				request.ObjectFormat = capabilities.objectFormat
				request.Atomic = capabilities.atomic
				request.ReportStatus = capabilities.reportStatus
				request.ReportStatusV2 = capabilities.reportStatusV2
				request.Signed = cert
				seenCarrier = true
				signedCarrier = cert
				for _, oid := range rawShallows {
					canonical, err := parseOID(oid, request.ObjectFormat)
					if err != nil {
						return nil, fmt.Errorf("%w: shallow object format mismatch", ErrInvalidProtocol)
					}
					request.ShallowOIDs = append(request.ShallowOIDs, canonical)
				}
				if cert {
					if !opts.AllowPushCertificates {
						return nil, fmt.Errorf("%w: push certificates", ErrUnsupported)
					}
					updates, embeddedOptions, err := parsePushCertificate(reader, prefix, request.ObjectFormat, opts)
					if err != nil {
						return nil, err
					}
					request.Updates = updates
					request.PushOptions = embeddedOptions
					continue
				}
				update, err := parseUpdate(command, request.ObjectFormat, opts.MaxRefBytes)
				if err != nil {
					return nil, err
				}
				request.Updates = append(request.Updates, update)
				continue
			}
			if signedCarrier {
				return nil, fmt.Errorf("%w: commands after push certificate", ErrInvalidProtocol)
			}
			if bytes.IndexByte(line, 0) >= 0 || bytes.HasPrefix(line, []byte("shallow ")) {
				return nil, fmt.Errorf("%w: invalid subsequent command", ErrInvalidProtocol)
			}
			if len(request.Updates) >= opts.MaxCommands {
				return nil, ErrLimitExceeded
			}
			update, err := parseUpdate(line, request.ObjectFormat, opts.MaxRefBytes)
			if err != nil {
				return nil, err
			}
			request.Updates = append(request.Updates, update)
		}
	}

commandsDone:
	if len(request.Updates) == 0 {
		return nil, fmt.Errorf("%w: empty update list", ErrInvalidProtocol)
	}
	if err := rejectDuplicateRefs(request.Updates); err != nil {
		return nil, err
	}
	hasPushOptions := hasCapability(request.Capabilities, "push-options")
	request.PushOptionsNegotiated = hasPushOptions
	if hasPushOptions {
		wireOptions, err := parsePushOptions(reader, prefix, opts)
		if err != nil {
			return nil, err
		}
		if request.Signed {
			if !equalStrings(request.PushOptions, wireOptions) {
				return nil, fmt.Errorf("%w: inconsistent signed push options", ErrInvalidProtocol)
			}
		} else {
			request.PushOptions = wireOptions
		}
	} else if request.Signed && len(request.PushOptions) != 0 {
		return nil, fmt.Errorf("%w: certificate options without capability", ErrInvalidProtocol)
	}

	needsPack := false
	for _, update := range request.Updates {
		if update.Kind != UpdateDelete {
			needsPack = true
			break
		}
	}
	if !needsPack {
		if err := requireEOF(reader); err != nil {
			return nil, err
		}
		return &ParsedReceivePack{Request: request, prefix: prefix.Bytes(), remainder: reader}, nil
	}
	marker := make([]byte, 4)
	if _, err := io.ReadFull(reader, marker); err != nil || !bytes.Equal(marker, []byte("PACK")) {
		return nil, fmt.Errorf("%w: missing pack signature", ErrInvalidProtocol)
	}
	if err := prefix.append(marker); err != nil {
		return nil, err
	}
	request.HasPack = true
	return &ParsedReceivePack{Request: request, prefix: prefix.Bytes(), remainder: reader}, nil
}

type parsedCapabilities struct {
	tokens         []string
	objectFormat   ObjectFormat
	atomic         bool
	reportStatus   bool
	reportStatusV2 bool
}

func parseFirstCarrier(line []byte, opts ParseOptions) ([]byte, parsedCapabilities, bool, error) {
	firstNUL := bytes.IndexByte(line, 0)
	if firstNUL < 0 || firstNUL != bytes.LastIndexByte(line, 0) {
		return nil, parsedCapabilities{}, false, fmt.Errorf("%w: first command must contain one capability separator", ErrInvalidProtocol)
	}
	command := line[:firstNUL]
	capabilities, err := parseCapabilities(line[firstNUL+1:], opts.MaxCapabilities)
	if err != nil {
		return nil, parsedCapabilities{}, false, err
	}
	if bytes.Equal(command, []byte("push-cert")) {
		return nil, capabilities, true, nil
	}
	return command, capabilities, false, nil
}

func parseCapabilities(value []byte, max int) (parsedCapabilities, error) {
	result := parsedCapabilities{objectFormat: ObjectFormatSHA1}
	if len(value) == 0 {
		return result, nil
	}
	if value[0] == ' ' {
		value = value[1:]
	}
	if len(value) == 0 || value[0] == ' ' || value[len(value)-1] == ' ' || bytes.Contains(value, []byte("  ")) {
		return parsedCapabilities{}, fmt.Errorf("%w: malformed capability list", ErrInvalidProtocol)
	}
	parts := bytes.Split(value, []byte{' '})
	if len(parts) > max {
		return parsedCapabilities{}, ErrLimitExceeded
	}
	seen := make(map[string]struct{}, len(parts))
	for _, raw := range parts {
		for _, b := range raw {
			if b < 0x21 || b > 0x7e {
				return parsedCapabilities{}, fmt.Errorf("%w: invalid capability byte", ErrInvalidProtocol)
			}
		}
		token := string(raw)
		name, parameter, hasParameter := strings.Cut(token, "=")
		if _, duplicate := seen[name]; duplicate {
			return parsedCapabilities{}, fmt.Errorf("%w: duplicate capability", ErrInvalidProtocol)
		}
		seen[name] = struct{}{}
		switch name {
		case "report-status":
			if hasParameter {
				return parsedCapabilities{}, fmt.Errorf("%w: parameterized flag capability", ErrInvalidProtocol)
			}
			result.reportStatus = true
		case "report-status-v2":
			if hasParameter {
				return parsedCapabilities{}, fmt.Errorf("%w: parameterized flag capability", ErrInvalidProtocol)
			}
			result.reportStatusV2 = true
		case "delete-refs", "side-band-64k", "quiet", "atomic", "push-options", "ofs-delta":
			if hasParameter {
				return parsedCapabilities{}, fmt.Errorf("%w: parameterized flag capability", ErrInvalidProtocol)
			}
			if name == "atomic" {
				result.atomic = true
			}
		case "push-cert":
			if hasParameter && parameter == "" {
				return parsedCapabilities{}, fmt.Errorf("%w: empty push certificate capability", ErrInvalidProtocol)
			}
		case "object-format":
			if !hasParameter || (parameter != string(ObjectFormatSHA1) && parameter != string(ObjectFormatSHA256)) {
				return parsedCapabilities{}, fmt.Errorf("%w: unsupported object format", ErrInvalidProtocol)
			}
			result.objectFormat = ObjectFormat(parameter)
		case "agent", "session-id":
			if !hasParameter || parameter == "" {
				return parsedCapabilities{}, fmt.Errorf("%w: missing capability value", ErrInvalidProtocol)
			}
		default:
			return parsedCapabilities{}, fmt.Errorf("%w: unknown receive-pack capability", ErrUnsupported)
		}
		result.tokens = append(result.tokens, token)
	}
	if result.reportStatus && result.reportStatusV2 {
		return parsedCapabilities{}, fmt.Errorf("%w: conflicting status capabilities", ErrInvalidProtocol)
	}
	return result, nil
}

func parseUpdate(line []byte, format ObjectFormat, maxRefBytes int) (Update, error) {
	if len(line) == 0 || bytes.ContainsAny(line, "\x00\r\n\t") || bytes.Count(line, []byte{' '}) != 2 {
		return Update{}, fmt.Errorf("%w: malformed update command", ErrInvalidProtocol)
	}
	parts := bytes.Split(line, []byte{' '})
	oldOID, err := parseOID(string(parts[0]), format)
	if err != nil {
		return Update{}, err
	}
	newOID, err := parseOID(string(parts[1]), format)
	if err != nil {
		return Update{}, err
	}
	ref := string(parts[2])
	if err := validateRefNameBounded(ref, maxRefBytes); err != nil {
		return Update{}, err
	}
	oldZero := allZero(oldOID)
	newZero := allZero(newOID)
	var kind UpdateKind
	switch {
	case oldZero && newZero:
		return Update{}, fmt.Errorf("%w: both object ids are zero", ErrInvalidProtocol)
	case oldZero:
		kind = UpdateCreate
	case newZero:
		kind = UpdateDelete
	default:
		kind = UpdateModify
	}
	return Update{OldOID: oldOID, NewOID: newOID, Ref: ref, Kind: kind}, nil
}

func parseOID(value string, format ObjectFormat) (string, error) {
	if len(value) != format.oidHexLength() {
		return "", fmt.Errorf("%w: object id length", ErrInvalidProtocol)
	}
	for _, b := range []byte(value) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			return "", fmt.Errorf("%w: non-hexadecimal object id", ErrInvalidProtocol)
		}
	}
	return strings.ToLower(value), nil
}

func validUnboundOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := parseOID(value, map[int]ObjectFormat{40: ObjectFormatSHA1, 64: ObjectFormatSHA256}[len(value)])
	return err == nil
}

func inferShallowFormat(values []string) (ObjectFormat, error) {
	if len(values) == 0 {
		return ObjectFormatSHA1, nil
	}
	length := len(values[0])
	for _, value := range values {
		if len(value) != length || !validUnboundOID(value) {
			return "", fmt.Errorf("%w: mixed shallow object formats", ErrInvalidProtocol)
		}
	}
	if length == 40 {
		return ObjectFormatSHA1, nil
	}
	return ObjectFormatSHA256, nil
}

func canonicalizeOIDs(values []string) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = strings.ToLower(value)
	}
	return result
}

func protocolLine(payload []byte) ([]byte, error) {
	line := payload
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 || bytes.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("%w: malformed protocol line", ErrInvalidProtocol)
	}
	return line, nil
}

func parsePushOptions(reader *bufio.Reader, prefix *prefixBuffer, opts ParseOptions) ([]string, error) {
	var options []string
	for {
		pkt, err := readPacket(reader, prefix)
		if err != nil {
			return nil, err
		}
		switch pkt.kind {
		case packetFlush:
			return options, nil
		case packetDelimiter, packetResponseEnd:
			return nil, fmt.Errorf("%w: v2 marker in push options", ErrInvalidProtocol)
		case packetData:
			if len(options) >= opts.MaxPushOptions {
				return nil, ErrLimitExceeded
			}
			line := pkt.payload
			if len(line) > 0 && line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) == 0 || len(line) > opts.MaxPushOptionBytes {
				return nil, fmt.Errorf("%w: push option length", ErrInvalidProtocol)
			}
			for _, b := range line {
				if b < 0x20 || b > 0x7e {
					return nil, fmt.Errorf("%w: invalid push option", ErrInvalidProtocol)
				}
			}
			options = append(options, string(line))
		}
	}
}

func parsePushCertificate(reader *bufio.Reader, prefix *prefixBuffer, format ObjectFormat, opts ParseOptions) ([]Update, []string, error) {
	var certificate bytes.Buffer
	lines := 0
	for {
		pkt, err := readPacket(reader, prefix)
		if err != nil {
			return nil, nil, err
		}
		if pkt.kind != packetData {
			return nil, nil, fmt.Errorf("%w: unterminated push certificate", ErrInvalidProtocol)
		}
		lines++
		if lines > opts.MaxCertificateLines || certificate.Len()+len(pkt.payload) > opts.MaxCertificateBytes {
			return nil, nil, ErrLimitExceeded
		}
		if bytes.Equal(pkt.payload, []byte("push-cert-end\n")) {
			break
		}
		if len(pkt.payload) == 0 || pkt.payload[len(pkt.payload)-1] != '\n' || bytes.IndexByte(pkt.payload, 0) >= 0 {
			return nil, nil, fmt.Errorf("%w: malformed certificate line", ErrInvalidProtocol)
		}
		certificate.Write(pkt.payload)
	}

	value := certificate.Bytes()
	if !bytes.HasPrefix(value, []byte("certificate version 0.1\n")) {
		return nil, nil, fmt.Errorf("%w: unsupported certificate version", ErrInvalidProtocol)
	}
	headerEnd := bytes.Index(value, []byte("\n\n"))
	if headerEnd < 0 {
		return nil, nil, fmt.Errorf("%w: certificate missing header terminator", ErrInvalidProtocol)
	}
	headerLines := bytes.Split(value[:headerEnd], []byte{'\n'})
	if len(headerLines) < 4 || !bytes.HasPrefix(headerLines[1], []byte("pusher ")) || !bytes.HasPrefix(headerLines[2], []byte("pushee ")) || !bytes.HasPrefix(headerLines[3], []byte("nonce ")) {
		return nil, nil, fmt.Errorf("%w: malformed certificate headers", ErrInvalidProtocol)
	}
	for _, header := range headerLines[1:] {
		for _, b := range header {
			if b < 0x20 || b > 0x7e {
				return nil, nil, fmt.Errorf("%w: invalid certificate header", ErrInvalidProtocol)
			}
		}
	}
	var embeddedOptions []string
	for _, header := range headerLines[4:] {
		if !bytes.HasPrefix(header, []byte("push-option ")) {
			return nil, nil, fmt.Errorf("%w: unknown certificate header", ErrInvalidProtocol)
		}
		option := header[len("push-option "):]
		if len(option) == 0 || len(option) > opts.MaxPushOptionBytes || len(embeddedOptions) >= opts.MaxPushOptions {
			return nil, nil, fmt.Errorf("%w: invalid certificate push option", ErrInvalidProtocol)
		}
		embeddedOptions = append(embeddedOptions, string(option))
	}

	payloadStart := headerEnd + 2
	signatureOffset, err := findSignatureOffset(value[payloadStart:])
	if err != nil {
		return nil, nil, err
	}
	commandBytes := value[payloadStart : payloadStart+signatureOffset]
	if len(commandBytes) == 0 || commandBytes[len(commandBytes)-1] != '\n' {
		return nil, nil, fmt.Errorf("%w: certificate has no commands", ErrInvalidProtocol)
	}
	commandLines := bytes.Split(commandBytes[:len(commandBytes)-1], []byte{'\n'})
	if len(commandLines) > opts.MaxCommands {
		return nil, nil, ErrLimitExceeded
	}
	updates := make([]Update, 0, len(commandLines))
	for _, command := range commandLines {
		update, err := parseUpdate(command, format, opts.MaxRefBytes)
		if err != nil {
			return nil, nil, err
		}
		updates = append(updates, update)
	}
	if err := rejectDuplicateRefs(updates); err != nil {
		return nil, nil, err
	}
	return updates, embeddedOptions, nil
}

func findSignatureOffset(value []byte) (int, error) {
	markers := []string{
		"-----BEGIN PGP SIGNATURE-----\n",
		"-----BEGIN PGP MESSAGE-----\n",
		"-----BEGIN SIGNED MESSAGE-----\n",
		"-----BEGIN SSH SIGNATURE-----\n",
	}
	found := -1
	for _, marker := range markers {
		if offset := bytes.Index(value, []byte(marker)); offset >= 0 {
			if offset != 0 && value[offset-1] != '\n' {
				continue
			}
			if found >= 0 {
				return 0, fmt.Errorf("%w: multiple certificate signatures", ErrInvalidProtocol)
			}
			found = offset
		}
	}
	if found <= 0 {
		return 0, fmt.Errorf("%w: certificate signature missing", ErrInvalidProtocol)
	}
	return found, nil
}

func rejectDuplicateRefs(updates []Update) error {
	seen := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		if _, exists := seen[update.Ref]; exists {
			return fmt.Errorf("%w: duplicate destination ref", ErrInvalidProtocol)
		}
		seen[update.Ref] = struct{}{}
	}
	return nil
}

func requireEOF(reader *bufio.Reader) error {
	_, err := reader.ReadByte()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: read body terminator: %v", ErrInvalidProtocol, err)
	}
	return fmt.Errorf("%w: unexpected trailing body", ErrInvalidProtocol)
}

func allZero(value string) bool { return strings.Trim(value, "0") == "" }

func hasCapability(capabilities []string, name string) bool {
	for _, capability := range capabilities {
		capabilityName, _, _ := strings.Cut(capability, "=")
		if capabilityName == name {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
