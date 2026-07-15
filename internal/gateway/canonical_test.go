package gateway

import (
	"net/url"
	"testing"
)

func TestCanonicalizeURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		target    string
		wantPath  string
		wantQuery string
		wantErr   bool
	}{
		{name: "plain", target: "/repos/acme/widget?z=2&a=1", wantPath: "/repos/acme/widget", wantQuery: "a=1&z=2"},
		{name: "dot and repeated slash", target: "/repos//./acme/", wantErr: true},
		{name: "utf8", target: "/caf%C3%A9", wantPath: "/café"},
		{name: "encoded slash", target: "/safe%2f..%2fadmin", wantErr: true},
		{name: "encoded backslash", target: "/safe%5cadmin", wantErr: true},
		{name: "double encoded slash", target: "/safe%252fadmin", wantErr: true},
		{name: "traversal", target: "/safe/../admin", wantErr: true},
		{name: "bad query escape", target: "/safe?q=%zz", wantErr: true},
		{name: "query control", target: "/safe?q=%00", wantErr: true},
		{name: "semicolon query", target: "/safe?a=1;b=2", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.ParseRequestURI(test.target)
			if err != nil {
				if test.wantErr {
					return
				}
				t.Fatalf("parse target: %v", err)
			}
			got, err := CanonicalizeURL(u)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeURL: %v", err)
			}
			if got.Path != test.wantPath || got.RawQuery != test.wantQuery {
				t.Fatalf("got path=%q query=%q, want path=%q query=%q", got.Path, got.RawQuery, test.wantPath, test.wantQuery)
			}
		})
	}
}

func TestCanonicalApplyDropsRawPath(t *testing.T) {
	t.Parallel()
	u := &url.URL{Path: "/old", RawPath: "/%6fld", RawQuery: "z=2"}
	c := CanonicalURL{Path: "/new value", RawQuery: "a=1"}
	if err := c.Apply(u); err != nil {
		t.Fatal(err)
	}
	if got := u.EscapedPath(); got != "/new%20value" {
		t.Fatalf("escaped path = %q", got)
	}
	if u.RawPath != "" || u.RawQuery != "a=1" {
		t.Fatalf("unexpected URL: %#v", u)
	}
}
