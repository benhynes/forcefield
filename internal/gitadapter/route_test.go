package gitadapter

import (
	"errors"
	"testing"
)

func TestClassifyRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		request  RouteRequest
		want     Route
		response string
	}{
		{
			name: "upload discovery",
			request: RouteRequest{
				Method:      "GET",
				Path:        "/tenant/project.git/info/refs",
				RawQuery:    "service=git-upload-pack",
				ContentType: "application/ignored-on-get",
			},
			want: Route{
				Repository: "tenant/project.git",
				Service:    ServiceUploadPack,
				Phase:      RouteDiscovery,
			},
			response: uploadAdvertisement,
		},
		{
			name: "receive discovery",
			request: RouteRequest{
				Method:   "GET",
				Path:     "/project.git/info/refs",
				RawQuery: "service=git-receive-pack",
			},
			want: Route{
				Repository: "project.git",
				Service:    ServiceReceivePack,
				Phase:      RouteDiscovery,
			},
			response: receiveAdvertisement,
		},
		{
			name: "upload rpc",
			request: RouteRequest{
				Method:      "POST",
				Path:        "/deeply/nested/project.git/git-upload-pack",
				ContentType: uploadRequest,
			},
			want: Route{
				Repository:  "deeply/nested/project.git",
				Service:     ServiceUploadPack,
				Phase:       RouteRPC,
				ContentType: uploadRequest,
			},
			response: uploadResult,
		},
		{
			name: "receive rpc",
			request: RouteRequest{
				Method:      "POST",
				Path:        "/project.git/git-receive-pack",
				ContentType: receiveRequest,
			},
			want: Route{
				Repository:  "project.git",
				Service:     ServiceReceivePack,
				Phase:       RouteRPC,
				ContentType: receiveRequest,
			},
			response: receiveResult,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ClassifyRoute(test.request)
			if err != nil {
				t.Fatalf("ClassifyRoute() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ClassifyRoute() = %#v, want %#v", got, test.want)
			}
			contentType, err := ExpectedResponseContentType(got)
			if err != nil {
				t.Fatalf("ExpectedResponseContentType() error = %v", err)
			}
			if contentType != test.response {
				t.Errorf("response content type = %q, want %q", contentType, test.response)
			}
		})
	}
}

func TestClassifyRouteRejectsAmbiguousOrUnsupportedRoutes(t *testing.T) {
	t.Parallel()

	validReceive := RouteRequest{
		Method:      "POST",
		Path:        "/organization/repository.git/git-receive-pack",
		ContentType: receiveRequest,
	}
	tests := []struct {
		name   string
		mutate func(*RouteRequest)
	}{
		{name: "repository lacks dot git", mutate: func(r *RouteRequest) { r.Path = "/organization/repository/git-receive-pack" }},
		{name: "dot git is not exact suffix", mutate: func(r *RouteRequest) { r.Path = "/organization/repository.git.backup/git-receive-pack" }},
		{name: "lowercase method required", mutate: func(r *RouteRequest) { r.Method = "post" }},
		{name: "wrong method", mutate: func(r *RouteRequest) { r.Method = "GET" }},
		{name: "missing content type", mutate: func(r *RouteRequest) { r.ContentType = "" }},
		{name: "content type parameters", mutate: func(r *RouteRequest) { r.ContentType += "; charset=utf-8" }},
		{name: "unexpected rpc query", mutate: func(r *RouteRequest) { r.RawQuery = "service=git-receive-pack" }},
		{name: "trailing slash", mutate: func(r *RouteRequest) { r.Path += "/" }},
		{name: "duplicate slash", mutate: func(r *RouteRequest) { r.Path = "/organization//repository.git/git-receive-pack" }},
		{name: "dot component", mutate: func(r *RouteRequest) { r.Path = "/organization/./repository.git/git-receive-pack" }},
		{name: "dot dot component", mutate: func(r *RouteRequest) { r.Path = "/organization/../repository.git/git-receive-pack" }},
		{name: "percent encoding", mutate: func(r *RouteRequest) { r.Path = "/organization/repository%2egit/git-receive-pack" }},
		{name: "backslash", mutate: func(r *RouteRequest) { r.Path = "/organization\\repository.git/git-receive-pack" }},
		{name: "query delimiter in path", mutate: func(r *RouteRequest) { r.Path = "/organization/repository.git?/git-receive-pack" }},
		{name: "endpoint text becomes repository", mutate: func(r *RouteRequest) { r.Path = "/repository.git/info/refs/git-receive-pack" }},
		{name: "dumb http head", mutate: func(r *RouteRequest) { r.Method, r.Path, r.ContentType = "GET", "/repository.git/HEAD", "" }},
		{name: "dumb http object", mutate: func(r *RouteRequest) { r.Method, r.Path, r.ContentType = "GET", "/repository.git/objects/aa/bb", "" }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validReceive
			test.mutate(&request)
			if _, err := ClassifyRoute(request); !errors.Is(err, ErrInvalidRoute) {
				t.Fatalf("ClassifyRoute() error = %v, want ErrInvalidRoute", err)
			}
		})
	}
}

func TestClassifyRouteRejectsNonCanonicalDiscoveryQuery(t *testing.T) {
	t.Parallel()

	queries := []string{
		"",
		"service=git-upload-pack&extra=1",
		"extra=1&service=git-upload-pack",
		"service=git%2dupload-pack",
		"service=git-upload-pack&",
	}
	for _, query := range queries {
		request := RouteRequest{
			Method:   "GET",
			Path:     "/repository.git/info/refs",
			RawQuery: query,
		}
		if _, err := ClassifyRoute(request); !errors.Is(err, ErrInvalidRoute) {
			t.Errorf("query %q: error = %v, want ErrInvalidRoute", query, err)
		}
	}
}

func TestExpectedResponseContentTypeRejectsUnknownRoute(t *testing.T) {
	t.Parallel()
	if _, err := ExpectedResponseContentType(Route{}); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("error = %v, want ErrInvalidRoute", err)
	}
}
