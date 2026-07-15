package gateway

import (
	"net/http"
	"testing"
)

func TestHeaderAdapterExtractAndRewrite(t *testing.T) {
	t.Parallel()
	a, err := NewHeaderAdapter(HeaderAdapterConfig{
		ClientHeader: "X-Api-Key", UpstreamHeader: "Authorization", UpstreamPrefix: "Bearer ",
		ForwardHeaders: []string{"Accept", "Content-Type"},
		StaticHeaders:  map[string]string{"Anthropic-Version": "2023-06-01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodPost, "http://forcefield/anthropic/messages", nil)
	r.Header.Set("X-Api-Key", "ff_abcdefghijklmnopqrstuvwxyz")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cookie", "session=attacker")
	token, err := a.ExtractToken(r)
	if err != nil || token != "ff_abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	out := r.Header.Clone()
	if err := a.RewriteHeaders(r.Header, out, []byte("real-secret")); err != nil {
		t.Fatal(err)
	}
	if got := out.Get("Authorization"); got != "Bearer real-secret" {
		t.Fatalf("Authorization=%q", got)
	}
	if out.Get("X-Api-Key") != "" || out.Get("Cookie") != "" || out.Get("Accept") != "application/json" {
		t.Fatalf("unsafe outbound headers: %#v", out)
	}
	if got := out.Get("Anthropic-Version"); got != "2023-06-01" {
		t.Fatalf("static version header = %q", got)
	}
}

func TestHeaderAdapterRejectsAmbiguousToken(t *testing.T) {
	t.Parallel()
	a, err := NewHeaderAdapter(HeaderAdapterConfig{ClientHeader: "Authorization", ClientPrefix: "Bearer ", UpstreamHeader: "Authorization", UpstreamPrefix: "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, "http://forcefield/github", nil)
	r.Header.Add("Authorization", "Bearer ff_abcdefghijklmnopqrstuvwxyz")
	r.Header.Add("Authorization", "Bearer ff_otherabcdefghijklmnop")
	if _, err := a.ExtractToken(r); err == nil {
		t.Fatal("expected ambiguous credential to fail")
	}
}

func TestHeaderAdapterRejectsUnsafeOrAmbiguousStaticHeaders(t *testing.T) {
	t.Parallel()
	base := HeaderAdapterConfig{ClientHeader: "X-Api-Key", UpstreamHeader: "Authorization"}
	for name, edit := range map[string]func(*HeaderAdapterConfig){
		"case collision": func(cfg *HeaderAdapterConfig) {
			cfg.StaticHeaders = map[string]string{"X-Version": "1", "x-version": "2"}
		},
		"forward collision": func(cfg *HeaderAdapterConfig) {
			cfg.ForwardHeaders = []string{"X-Version"}
			cfg.StaticHeaders = map[string]string{"x-version": "1"}
		},
		"credential collision": func(cfg *HeaderAdapterConfig) { cfg.StaticHeaders = map[string]string{"Authorization": "value"} },
		"accept encoding":      func(cfg *HeaderAdapterConfig) { cfg.StaticHeaders = map[string]string{"Accept-Encoding": "gzip"} },
		"framing":              func(cfg *HeaderAdapterConfig) { cfg.StaticHeaders = map[string]string{"Content-Length": "1"} },
		"forwarded cookie": func(cfg *HeaderAdapterConfig) {
			cfg.ForwardHeaders = []string{"Cookie"}
		},
		"secondary authorization": func(cfg *HeaderAdapterConfig) {
			cfg.ClientHeader = "X-Forcefield-Token"
			cfg.UpstreamHeader = "X-Api-Key"
			cfg.ForwardHeaders = []string{"Authorization"}
		},
		"static token": func(cfg *HeaderAdapterConfig) {
			cfg.StaticHeaders = map[string]string{"X-Vault-Token": "configured-secret"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			edit(&cfg)
			if _, err := NewHeaderAdapter(cfg); err == nil {
				t.Fatal("unsafe adapter configuration was accepted")
			}
		})
	}
}

func TestHeaderAdapterRejectsNonCanonicalCredentialBytes(t *testing.T) {
	t.Parallel()
	adapter, err := NewHeaderAdapter(HeaderAdapterConfig{ClientHeader: "X-Api-Key", UpstreamHeader: "Authorization"})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte(" leading"), []byte("trailing\t"), []byte("line\nfeed"), []byte{0xff}} {
		if err := adapter.RewriteHeaders(make(http.Header), make(http.Header), secret); err == nil {
			t.Errorf("credential bytes %q were accepted", secret)
		}
	}
}
