package gateway

import "sync"

const (
	maxConcurrentSSHSessions            = 128
	maxConcurrentSSHSessionsPerToken    = 8
	maxConcurrentSSHSessionsPerWorkload = 16
)

type sshConcurrencyManager struct {
	mu         sync.Mutex
	total      int
	byToken    map[string]int
	byWorkload map[string]int
}

func newSSHConcurrencyManager() *sshConcurrencyManager {
	return &sshConcurrencyManager{byToken: make(map[string]int), byWorkload: make(map[string]int)}
}

func (m *sshConcurrencyManager) acquire(tokenID, workload string) (func(), bool) {
	if m == nil || tokenID == "" || workload == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.total >= maxConcurrentSSHSessions || m.byToken[tokenID] >= maxConcurrentSSHSessionsPerToken ||
		m.byWorkload[workload] >= maxConcurrentSSHSessionsPerWorkload {
		return nil, false
	}
	m.total++
	m.byToken[tokenID]++
	m.byWorkload[workload]++
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.total--
			m.byToken[tokenID]--
			m.byWorkload[workload]--
			if m.byToken[tokenID] == 0 {
				delete(m.byToken, tokenID)
			}
			if m.byWorkload[workload] == 0 {
				delete(m.byWorkload, workload)
			}
		})
	}, true
}
