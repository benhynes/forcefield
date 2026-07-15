package gateway

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestGitRequestBodyStreamsAndEnforcesLimit(t *testing.T) {
	t.Parallel()
	request := &http.Request{
		Header: make(http.Header), Body: io.NopCloser(bytes.NewReader([]byte("12345"))), ContentLength: -1,
	}
	var charged uint64
	body, err := prepareGitRequestBody(request, 4, func(count uint64) bool {
		charged += count
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	value, readErr := io.ReadAll(body)
	if !errors.Is(readErr, errGitBodyLimit) || string(value) != "1234" || charged != 4 || body.BytesRead() != 4 {
		t.Fatalf("bounded stream = value %q err %v charged %d count %d", value, readErr, charged, body.BytesRead())
	}
}

func TestGitRequestBodyRejectsBudgetWithoutForwardingChunk(t *testing.T) {
	t.Parallel()
	request := &http.Request{
		Header: make(http.Header), Body: io.NopCloser(bytes.NewReader([]byte("payload"))), ContentLength: -1,
	}
	body, err := prepareGitRequestBody(request, 1024, func(uint64) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	value, readErr := io.ReadAll(body)
	if !errors.Is(readErr, errGitByteBudget) || len(value) != 0 || body.BytesRead() != 0 {
		t.Fatalf("budget stream = value %q err %v count %d", value, readErr, body.BytesRead())
	}
}

func TestGitRequestBodyStrictGzip(t *testing.T) {
	t.Parallel()
	plain := []byte("receive-pack-prefix-PACK-payload")
	compressed := gzipBytes(t, plain)
	for name, source := range map[string][]byte{
		"trailing byte":  append(append([]byte(nil), compressed...), 'x'),
		"second member":  append(append([]byte(nil), compressed...), compressed...),
		"truncated body": compressed[:len(compressed)-1],
	} {
		t.Run(name, func(t *testing.T) {
			request := &http.Request{
				Header: http.Header{"Content-Encoding": {"gzip"}},
				Body:   io.NopCloser(bytes.NewReader(source)), ContentLength: int64(len(source)),
			}
			body, err := prepareGitRequestBody(request, 1<<20, func(uint64) bool { return true })
			if err != nil {
				// A short corrupt stream may fail while constructing the decoder.
				if name != "truncated body" || !errors.Is(err, errGitGzip) {
					t.Fatalf("prepare = %v", err)
				}
				return
			}
			defer body.Close()
			if _, err := io.ReadAll(body); err == nil {
				t.Fatal("ambiguous gzip stream was accepted")
			}
		})
	}

	request := &http.Request{
		Header: http.Header{"Content-Encoding": {"gzip"}},
		Body:   io.NopCloser(bytes.NewReader(compressed)), ContentLength: int64(len(compressed)),
	}
	var charged uint64
	body, err := prepareGitRequestBody(request, 1<<20, func(count uint64) bool { charged += count; return true })
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	decoded, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(decoded, plain) || charged != uint64(len(plain)) || request.Header.Get("Content-Encoding") != "" || request.ContentLength != -1 {
		t.Fatalf("decoded gzip = %q err=%v charged=%d headers=%#v length=%d", decoded, err, charged, request.Header, request.ContentLength)
	}
}

func TestGitRequestBodyRejectsGzipBombRatio(t *testing.T) {
	t.Parallel()
	plain := make([]byte, 2<<20)
	compressed := gzipBytes(t, plain)
	request := &http.Request{
		Header: http.Header{"Content-Encoding": {"gzip"}},
		Body:   io.NopCloser(bytes.NewReader(compressed)), ContentLength: int64(len(compressed)),
	}
	body, err := prepareGitRequestBody(request, 3<<20, func(uint64) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	if _, err := io.ReadAll(body); !errors.Is(err, errGitGzip) {
		t.Fatalf("gzip ratio error = %v", err)
	}
}

func gzipBytes(t *testing.T, value []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
