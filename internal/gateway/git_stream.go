package gateway

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	errGitBodyLimit   = errors.New("git request body exceeds its configured limit")
	errGitByteBudget  = errors.New("git request body exceeds its byte budget")
	errGitBodyTrailer = errors.New("git request body supplied a trailer")
	errGitGzip        = errors.New("invalid git gzip request body")
)

const (
	gitGzipRatioSlack = uint64(1 << 20)
	gitGzipMaxRatio   = uint64(100)
)

// gitRequestBody accounts decoded client-to-upstream bytes as the transport
// consumes them. Prefix bytes inspected by the receive-pack parser are replayed
// above this reader, so they are charged exactly once rather than once for
// policy inspection and again for forwarding.
type gitRequestBody struct {
	reader    io.Reader
	source    io.ReadCloser
	gzip      *gzip.Reader
	count     atomic.Uint64
	closeOnce sync.Once
	closeErr  error
}

func (b *gitRequestBody) Read(value []byte) (int, error) {
	if b == nil || b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(value)
}

func (b *gitRequestBody) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		if b.gzip != nil {
			b.closeErr = b.gzip.Close()
		}
		if b.source != nil {
			b.closeErr = errors.Join(b.closeErr, b.source.Close())
		}
	})
	return b.closeErr
}

func (b *gitRequestBody) BytesRead() int64 {
	if b == nil {
		return 0
	}
	count := b.count.Load()
	if count > uint64(^uint64(0)>>1) {
		return int64(^uint64(0) >> 1)
	}
	return int64(count)
}

type replayedGitBody struct {
	io.Reader
	source io.Closer
}

func (b *replayedGitBody) Close() error { return b.source.Close() }

func prepareGitRequestBody(r *http.Request, maximum uint64, charge func(uint64) bool) (*gitRequestBody, error) {
	if r == nil || maximum == 0 || maximum > 1<<30 || charge == nil {
		return nil, errGitBodyLimit
	}
	if r.ContentLength > 0 && uint64(r.ContentLength) > maximum {
		return nil, errGitBodyLimit
	}
	if r.Body == nil {
		return &gitRequestBody{reader: strings.NewReader("")}, nil
	}

	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	body := &gitRequestBody{source: r.Body}
	rawCounter := &countingBoundedReader{reader: r.Body, maximum: maximum}
	var decoded io.Reader = rawCounter
	compressed := false
	switch encoding {
	case "", "identity":
	case "gzip", "x-gzip":
		buffered := bufio.NewReaderSize(rawCounter, 32<<10)
		decoder, err := gzip.NewReader(buffered)
		if err != nil {
			_ = r.Body.Close()
			return nil, errGitGzip
		}
		decoder.Multistream(false)
		body.gzip = decoder
		decoded = &strictGzipReader{decoder: decoder, source: buffered}
		compressed = true
		r.Header.Del("Content-Encoding")
		r.ContentLength = -1
	default:
		_ = r.Body.Close()
		return nil, errGitGzip
	}

	metered := &gitMeteredReader{
		reader: decoded, maximum: maximum, charge: charge, trailer: r.Trailer,
		count: &body.count, compressed: compressed, rawCount: &rawCounter.count,
	}
	body.reader = metered
	return body, nil
}

// countingBoundedReader rejects the byte after maximum instead of converting
// it to EOF. That distinction prevents a truncated request from being treated
// as a complete pack.
type countingBoundedReader struct {
	reader  io.Reader
	maximum uint64
	count   atomic.Uint64
}

func (r *countingBoundedReader) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	used := r.count.Load()
	if used >= r.maximum {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n != 0 {
			return 0, errGitBodyLimit
		}
		return 0, err
	}
	remaining := r.maximum - used
	if uint64(len(value)) > remaining {
		value = value[:remaining]
	}
	n, err := r.reader.Read(value)
	if n > 0 {
		r.count.Add(uint64(n))
	}
	return n, err
}

type strictGzipReader struct {
	decoder  *gzip.Reader
	source   *bufio.Reader
	terminal error
	checked  bool
}

func (r *strictGzipReader) Read(value []byte) (int, error) {
	if r.terminal != nil {
		err := r.terminal
		r.terminal = nil
		return 0, err
	}
	if r.checked {
		return 0, io.EOF
	}
	n, err := r.decoder.Read(value)
	if !errors.Is(err, io.EOF) {
		return n, err
	}
	r.checked = true
	_, trailingErr := r.source.Peek(1)
	switch {
	case trailingErr == nil:
		err = errGitGzip
	case !errors.Is(trailingErr, io.EOF):
		err = errors.Join(errGitGzip, trailingErr)
	default:
		err = io.EOF
	}
	if n > 0 && !errors.Is(err, io.EOF) {
		r.terminal = err
		return n, nil
	}
	return n, err
}

type gitMeteredReader struct {
	reader     io.Reader
	maximum    uint64
	charge     func(uint64) bool
	trailer    http.Header
	count      *atomic.Uint64
	compressed bool
	rawCount   *atomic.Uint64
	terminal   error
}

func (r *gitMeteredReader) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	if r.terminal != nil {
		err := r.terminal
		r.terminal = nil
		return 0, err
	}
	used := r.count.Load()
	if used >= r.maximum {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n != 0 {
			return 0, errGitBodyLimit
		}
		if errors.Is(err, io.EOF) && len(r.trailer) != 0 {
			return 0, errGitBodyTrailer
		}
		return 0, err
	}
	remaining := r.maximum - used
	if uint64(len(value)) > remaining {
		value = value[:remaining]
	}
	n, err := r.reader.Read(value)
	if n > 0 {
		count := uint64(n)
		next := used + count
		if r.compressed {
			raw := r.rawCount.Load()
			if raw > (^uint64(0)-gitGzipRatioSlack)/gitGzipMaxRatio || next > gitGzipRatioSlack+raw*gitGzipMaxRatio {
				return 0, errGitGzip
			}
		}
		if !r.charge(count) {
			return 0, errGitByteBudget
		}
		r.count.Add(count)
	}
	if errors.Is(err, io.EOF) && len(r.trailer) != 0 {
		if n > 0 {
			r.terminal = errGitBodyTrailer
			return n, nil
		}
		return 0, errGitBodyTrailer
	}
	return n, err
}
