package gitadapter

import (
	"fmt"
	"strings"
)

const (
	uploadAdvertisement  = "application/x-git-upload-pack-advertisement"
	uploadRequest        = "application/x-git-upload-pack-request"
	uploadResult         = "application/x-git-upload-pack-result"
	receiveAdvertisement = "application/x-git-receive-pack-advertisement"
	receiveRequest       = "application/x-git-receive-pack-request"
	receiveResult        = "application/x-git-receive-pack-result"
)

type RouteRequest struct {
	Method      string
	Path        string
	RawQuery    string
	ContentType string
}

// ClassifyRoute accepts only the four smart-HTTP discovery/RPC shapes. Path
// must already be a decoded, canonical absolute path; ambiguous path spellings
// and dumb-HTTP endpoints are rejected.
func ClassifyRoute(in RouteRequest) (Route, error) {
	if !validCanonicalPath(in.Path) {
		return Route{}, ErrInvalidRoute
	}

	type candidate struct {
		suffix      string
		service     Service
		phase       RoutePhase
		method      string
		query       string
		contentType string
	}
	candidates := [...]candidate{
		{suffix: "/info/refs", service: ServiceUploadPack, phase: RouteDiscovery, method: "GET", query: "service=git-upload-pack"},
		{suffix: "/info/refs", service: ServiceReceivePack, phase: RouteDiscovery, method: "GET", query: "service=git-receive-pack"},
		{suffix: "/git-upload-pack", service: ServiceUploadPack, phase: RouteRPC, method: "POST", contentType: uploadRequest},
		{suffix: "/git-receive-pack", service: ServiceReceivePack, phase: RouteRPC, method: "POST", contentType: receiveRequest},
	}

	for _, candidate := range candidates {
		if in.Method != candidate.method || !strings.HasSuffix(in.Path, candidate.suffix) {
			continue
		}
		repositoryPath := strings.TrimSuffix(in.Path, candidate.suffix)
		if repositoryPath == "" || repositoryPath == "/" || strings.HasSuffix(repositoryPath, "/") || !strings.HasSuffix(repositoryPath, ".git") {
			return Route{}, ErrInvalidRoute
		}
		if candidate.phase == RouteDiscovery {
			if in.RawQuery != candidate.query {
				continue
			}
		} else if in.RawQuery != "" || in.ContentType != candidate.contentType {
			continue
		}
		return Route{
			Repository:  strings.TrimPrefix(repositoryPath, "/"),
			Service:     candidate.service,
			Phase:       candidate.phase,
			ContentType: candidate.contentType,
		}, nil
	}
	return Route{}, ErrInvalidRoute
}

func validCanonicalPath(path string) bool {
	if path == "" || path[0] != '/' || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	for _, component := range strings.Split(path[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for i := 0; i < len(component); i++ {
			b := component[i]
			if b <= 0x20 || b == 0x7f || b == '\\' || b == '%' || b == '?' || b == '#' {
				return false
			}
		}
	}
	return true
}

func ExpectedResponseContentType(route Route) (string, error) {
	switch {
	case route.Service == ServiceUploadPack && route.Phase == RouteDiscovery:
		return uploadAdvertisement, nil
	case route.Service == ServiceUploadPack && route.Phase == RouteRPC:
		return uploadResult, nil
	case route.Service == ServiceReceivePack && route.Phase == RouteDiscovery:
		return receiveAdvertisement, nil
	case route.Service == ServiceReceivePack && route.Phase == RouteRPC:
		return receiveResult, nil
	default:
		return "", fmt.Errorf("%w: unknown service/phase", ErrInvalidRoute)
	}
}
