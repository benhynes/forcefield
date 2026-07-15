package gitadapter

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const (
	zeroSHA1 = "0000000000000000000000000000000000000000"
	oidASHA1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oidBSHA1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oidCSHA1 = "cccccccccccccccccccccccccccccccccccccccc"
)

func pktLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

func firstCommand(oldOID, newOID, ref, capabilities string) string {
	return oldOID + " " + newOID + " " + ref + "\x00" + capabilities + "\n"
}

func TestParseReceivePackProbe(t *testing.T) {
	t.Parallel()
	wire := []byte("0000")
	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	if parsed.Request.Kind != ReceivePackProbe || len(parsed.Request.Updates) != 0 || parsed.Request.HasPack {
		t.Fatalf("request = %#v, want an empty probe", parsed.Request)
	}
	assertReplayedBody(t, parsed, wire)
}

func TestParsedReceivePackZeroValueBody(t *testing.T) {
	t.Parallel()
	got, err := io.ReadAll((&ParsedReceivePack{}).Body())
	if err != nil || len(got) != 0 {
		t.Fatalf("zero-value Body() = %x, %v", got, err)
	}
}

func TestParseReceivePackShallowNoop(t *testing.T) {
	t.Parallel()
	upper := strings.ToUpper(oidASHA1)
	wire := []byte(pktLine("shallow "+upper+"\n") + "0000")
	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	request := parsed.Request
	if request.Kind != ReceivePackNoop || request.ObjectFormat != ObjectFormatSHA1 {
		t.Fatalf("request kind/format = %q/%q, want noop/sha1", request.Kind, request.ObjectFormat)
	}
	if len(request.ShallowOIDs) != 1 || request.ShallowOIDs[0] != oidASHA1 {
		t.Fatalf("shallow OIDs = %#v, want canonical lowercase SHA-1", request.ShallowOIDs)
	}
	assertReplayedBody(t, parsed, wire)
}

func TestParseReceivePackCreateWithOptionsAndStreamingPack(t *testing.T) {
	t.Parallel()
	command := firstCommand(
		zeroSHA1,
		oidASHA1,
		"refs/heads/topic",
		"report-status delete-refs atomic push-options ofs-delta object-format=sha1 agent=git/2.52.0",
	)
	wire := []byte(pktLine(command) + "0000" + pktLine("ci.skip=true\n") + "0000" + "PACK\x00\x00payload")

	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	request := parsed.Request
	if request.Kind != ReceivePackPush || request.ObjectFormat != ObjectFormatSHA1 || !request.Atomic || !request.ReportStatus || !request.HasPack {
		t.Fatalf("request flags = %#v", request)
	}
	if request.ReportStatusV2 || request.Signed {
		t.Fatalf("unexpected status-v2 or signed flag: %#v", request)
	}
	if len(request.Updates) != 1 {
		t.Fatalf("updates = %#v", request.Updates)
	}
	wantUpdate := Update{OldOID: zeroSHA1, NewOID: oidASHA1, Ref: "refs/heads/topic", Kind: UpdateCreate}
	if request.Updates[0] != wantUpdate {
		t.Errorf("update = %#v, want %#v", request.Updates[0], wantUpdate)
	}
	if !request.PushOptionsNegotiated || len(request.PushOptions) != 1 || request.PushOptions[0] != "ci.skip=true" {
		t.Errorf("push options = %#v", request.PushOptions)
	}
	assertReplayedBody(t, parsed, wire)
}

func TestParseReceivePackSHA256MultiRefPush(t *testing.T) {
	t.Parallel()
	zero := strings.Repeat("0", 64)
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	c := strings.Repeat("c", 64)
	first := firstCommand(a, b, "refs/heads/one", "report-status-v2 object-format=sha256")
	second := b + " " + c + " refs/tags/two\n"
	third := a + " " + zero + " refs/heads/deleted\n"
	wire := []byte(pktLine("shallow "+strings.ToUpper(a)+"\n") + pktLine(first) + pktLine(second) + pktLine(third) + "0000PACKdata")

	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	request := parsed.Request
	if request.ObjectFormat != ObjectFormatSHA256 || !request.ReportStatusV2 || request.ReportStatus || !request.HasPack {
		t.Fatalf("request flags = %#v", request)
	}
	if len(request.ShallowOIDs) != 1 || request.ShallowOIDs[0] != a {
		t.Errorf("shallow OIDs = %#v", request.ShallowOIDs)
	}
	if len(request.Updates) != 3 || request.Updates[0].Kind != UpdateModify || request.Updates[1].Kind != UpdateModify || request.Updates[2].Kind != UpdateDelete {
		t.Errorf("updates = %#v", request.Updates)
	}
	assertReplayedBody(t, parsed, wire)
}

func TestParseReceivePackDeleteOnlyRequiresEndOfBody(t *testing.T) {
	t.Parallel()
	command := firstCommand(oidASHA1, zeroSHA1, "refs/heads/obsolete", "report-status")
	wire := []byte(pktLine(command) + "0000")
	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	if len(parsed.Request.Updates) != 1 || parsed.Request.Updates[0].Kind != UpdateDelete || parsed.Request.HasPack {
		t.Fatalf("request = %#v", parsed.Request)
	}
	assertReplayedBody(t, parsed, wire)

	if _, err := ParseReceivePackPrefix(bytes.NewReader(append(wire, []byte("PACK")...)), ParseOptions{}); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("trailing body error = %v, want ErrInvalidProtocol", err)
	}
}

func TestParseReceivePackCanonicalizesObjectIDs(t *testing.T) {
	t.Parallel()
	command := firstCommand(strings.ToUpper(oidASHA1), strings.ToUpper(oidBSHA1), "refs/heads/topic", "")
	wire := []byte(pktLine(command) + "0000PACK")
	parsed, err := ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseReceivePackPrefix() error = %v", err)
	}
	update := parsed.Request.Updates[0]
	if update.OldOID != oidASHA1 || update.NewOID != oidBSHA1 {
		t.Fatalf("canonical OIDs = %q %q", update.OldOID, update.NewOID)
	}
}

func TestParseReceivePackRejectsMalformedProtocol(t *testing.T) {
	t.Parallel()

	create := pktLine(firstCommand(zeroSHA1, oidASHA1, "refs/heads/topic", "")) + "0000"
	deleteCommand := pktLine(firstCommand(oidASHA1, zeroSHA1, "refs/heads/topic", ""))
	modify := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", ""))
	tests := []struct {
		name string
		wire string
		want error
	}{
		{name: "empty body", wire: "", want: ErrInvalidProtocol},
		{name: "truncated header", wire: "00", want: ErrInvalidProtocol},
		{name: "uppercase packet length", wire: "000Axxxxxx", want: ErrInvalidProtocol},
		{name: "v2 delimiter", wire: "0001", want: ErrInvalidProtocol},
		{name: "v2 response end", wire: "0002", want: ErrInvalidProtocol},
		{name: "reserved length", wire: "0003", want: ErrInvalidProtocol},
		{name: "oversize packet length", wire: "ffff", want: ErrInvalidProtocol},
		{name: "empty data packet", wire: "0004", want: ErrInvalidProtocol},
		{name: "first command has no nul", wire: pktLine(oidASHA1+" "+oidBSHA1+" refs/heads/topic\n") + "0000PACK", want: ErrInvalidProtocol},
		{name: "first command has two nuls", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "")+"\x00") + "0000PACK", want: ErrInvalidProtocol},
		{name: "carriage return", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "")+"\r") + "0000PACK", want: ErrInvalidProtocol},
		{name: "both object ids zero", wire: pktLine(firstCommand(zeroSHA1, zeroSHA1, "refs/heads/topic", "")) + "0000", want: ErrInvalidProtocol},
		{name: "non hexadecimal object id", wire: pktLine(firstCommand(strings.Repeat("g", 40), oidASHA1, "refs/heads/topic", "")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "short object id", wire: pktLine(firstCommand("aaaa", oidASHA1, "refs/heads/topic", "")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "invalid ref", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/../topic", "")) + "0000PACK", want: ErrInvalidRef},
		{name: "unknown capability", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "future-feature")) + "0000PACK", want: ErrUnsupported},
		{name: "duplicate capability", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "atomic atomic")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "malformed capability spacing", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "atomic  quiet")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "conflicting report status", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "report-status report-status-v2")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "mixed shallow formats", wire: pktLine("shallow "+oidASHA1+"\n") + pktLine("shallow "+strings.Repeat("b", 64)+"\n") + "0000", want: ErrInvalidProtocol},
		{name: "shallow disagrees with object format", wire: pktLine("shallow "+oidASHA1+"\n") + pktLine(firstCommand(strings.Repeat("a", 64), strings.Repeat("b", 64), "refs/heads/topic", "object-format=sha256")) + "0000PACK", want: ErrInvalidProtocol},
		{name: "shallow after command", wire: modify + pktLine("shallow "+oidASHA1+"\n") + "0000PACK", want: ErrInvalidProtocol},
		{name: "nul in subsequent command", wire: modify + pktLine(oidBSHA1+" "+oidCSHA1+" refs/heads/next\x00atomic\n") + "0000PACK", want: ErrInvalidProtocol},
		{name: "duplicate destination ref", wire: modify + pktLine(oidBSHA1+" "+oidCSHA1+" refs/heads/topic\n") + "0000PACK", want: ErrInvalidProtocol},
		{name: "create missing pack", wire: create, want: ErrInvalidProtocol},
		{name: "create wrong pack marker", wire: create + "NOPE", want: ErrInvalidProtocol},
		{name: "delete trailing byte", wire: deleteCommand + "0000x", want: ErrInvalidProtocol},
		{name: "push certificate denied by default", wire: pktLine("push-cert\x00report-status\n"), want: ErrUnsupported},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseReceivePackPrefix(strings.NewReader(test.wire), ParseOptions{})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseReceivePackEnforcesLimits(t *testing.T) {
	t.Parallel()

	twoCommands := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/one", "")) +
		pktLine(oidBSHA1+" "+oidCSHA1+" refs/heads/two\n") + "0000PACK"
	twoCapabilities := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "atomic quiet")) + "0000PACK"
	longRef := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/long-name", "")) + "0000PACK"
	pushOptions := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "push-options")) +
		"0000" + pktLine("one") + pktLine("two") + "0000PACK"

	tests := []struct {
		name    string
		wire    string
		options ParseOptions
		want    error
	}{
		{name: "negative limit", wire: "0000", options: ParseOptions{MaxCommands: -1}, want: ErrLimitExceeded},
		{name: "prefix bytes", wire: pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "")), options: ParseOptions{MaxPrefixBytes: 4}, want: ErrLimitExceeded},
		{name: "commands", wire: twoCommands, options: ParseOptions{MaxCommands: 1}, want: ErrLimitExceeded},
		{name: "capabilities", wire: twoCapabilities, options: ParseOptions{MaxCapabilities: 1}, want: ErrLimitExceeded},
		{name: "ref bytes", wire: longRef, options: ParseOptions{MaxRefBytes: len("refs/heads/x")}, want: ErrInvalidRef},
		{name: "push option count", wire: pushOptions, options: ParseOptions{MaxPushOptions: 1}, want: ErrLimitExceeded},
		{name: "push option bytes", wire: pushOptions, options: ParseOptions{MaxPushOptionBytes: 2}, want: ErrInvalidProtocol},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseReceivePackPrefix(strings.NewReader(test.wire), test.options)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseReceivePackRejectsInvalidPushOptions(t *testing.T) {
	t.Parallel()
	command := pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "push-options")) + "0000"
	for _, option := range []string{"", "has\x00nul", "has\x1fcontrol", "has\x7fdelete"} {
		wire := command + pktLine(option) + "0000PACK"
		if _, err := ParseReceivePackPrefix(strings.NewReader(wire), ParseOptions{}); !errors.Is(err, ErrInvalidProtocol) {
			t.Errorf("option %q: error = %v, want ErrInvalidProtocol", option, err)
		}
	}
}

func TestReadPacketAcceptsMaximumLength(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte{'x'}, maxPktLineBytes-4)
	wire := append([]byte("fff0"), payload...)
	reader := bytes.NewBuffer(wire)
	prefix := &prefixBuffer{max: maxPktLineBytes}
	pkt, err := readPacket(bufioReader(reader), prefix)
	if err != nil {
		t.Fatalf("readPacket() error = %v", err)
	}
	if pkt.kind != packetData || len(pkt.payload) != len(payload) || prefix.Len() != maxPktLineBytes {
		t.Fatalf("packet payload/prefix lengths = %d/%d", len(pkt.payload), prefix.Len())
	}
}

func bufioReader(reader io.Reader) *bufio.Reader {
	return bufio.NewReader(reader)
}

func assertReplayedBody(t *testing.T, parsed *ParsedReceivePack, want []byte) {
	t.Helper()
	prefix := parsed.PrefixBytes()
	if len(prefix) == 0 {
		t.Fatal("PrefixBytes() returned an empty prefix")
	}
	prefix[0] ^= 0xff
	got, err := io.ReadAll(parsed.Body())
	if err != nil {
		t.Fatalf("reading replayed body: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("replayed body differs:\n got %x\nwant %x", got, want)
	}
}

func FuzzParseReceivePackPrefix(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("0000"))
	f.Add([]byte("0001"))
	f.Add([]byte(pktLine(firstCommand(oidASHA1, oidBSHA1, "refs/heads/topic", "")) + "0000PACK"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ParseReceivePackPrefix(bytes.NewReader(wire), ParseOptions{
			MaxPrefixBytes:     128 << 10,
			MaxCommands:        128,
			MaxShallowOIDs:     128,
			MaxCapabilities:    32,
			MaxPushOptions:     32,
			MaxPushOptionBytes: 1024,
			MaxRefBytes:        1024,
		})
	})
}
