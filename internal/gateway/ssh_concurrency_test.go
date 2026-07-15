package gateway

import (
	"strconv"
	"testing"
)

func TestSSHConcurrencyManagerBoundsAndReleases(t *testing.T) {
	t.Parallel()
	manager := newSSHConcurrencyManager()
	if release, ok := manager.acquire("", "workload"); ok || release != nil {
		t.Fatal("empty token identity acquired an SSH slot")
	}
	releases := make([]func(), 0, maxConcurrentSSHSessionsPerToken)
	for index := 0; index < maxConcurrentSSHSessionsPerToken; index++ {
		release, ok := manager.acquire("token", "workload")
		if !ok || release == nil {
			t.Fatalf("token slot %d was denied", index)
		}
		releases = append(releases, release)
	}
	if release, ok := manager.acquire("token", "workload"); ok || release != nil {
		t.Fatal("per-token SSH concurrency ceiling was bypassed")
	}
	for _, release := range releases {
		release()
		release() // Releases are deliberately idempotent.
	}
	if manager.total != 0 || len(manager.byToken) != 0 || len(manager.byWorkload) != 0 {
		t.Fatalf("released SSH slots leaked state: total=%d tokens=%v workloads=%v", manager.total, manager.byToken, manager.byWorkload)
	}
	if release, ok := manager.acquire("token", "workload"); !ok {
		t.Fatal("released SSH slot could not be reacquired")
	} else {
		release()
	}
}

func TestSSHConcurrencyManagerWorkloadAndGlobalBounds(t *testing.T) {
	t.Parallel()
	manager := newSSHConcurrencyManager()
	var workloadReleases []func()
	for index := 0; index < maxConcurrentSSHSessionsPerWorkload; index++ {
		release, ok := manager.acquire(string(rune('a'+index)), "shared")
		if !ok {
			t.Fatalf("workload slot %d was denied", index)
		}
		workloadReleases = append(workloadReleases, release)
	}
	if release, ok := manager.acquire("overflow", "shared"); ok || release != nil {
		t.Fatal("per-workload SSH concurrency ceiling was bypassed")
	}
	for _, release := range workloadReleases {
		release()
	}

	globalReleases := make([]func(), 0, maxConcurrentSSHSessions)
	for index := 0; index < maxConcurrentSSHSessions; index++ {
		release, ok := manager.acquire("token-"+strconv.Itoa(index), "workload-"+strconv.Itoa(index))
		if !ok {
			t.Fatalf("global slot %d was denied", index)
		}
		globalReleases = append(globalReleases, release)
	}
	if release, ok := manager.acquire("global-overflow", "global-overflow"); ok || release != nil {
		t.Fatal("global SSH concurrency ceiling was bypassed")
	}
	for _, release := range globalReleases {
		release()
	}
}
