package session

import "time"

// TrackDuration records the elapsed time since invocation for the given provider.
func (s *Stats) TrackDuration(m map[string]time.Duration, provider string) func() {
	start := time.Now()

	return func() {
		s.Mu.Lock()
		m[provider] = time.Since(start)
		s.Mu.Unlock()
	}
}

// MarkCacheUsed marks the cache as used for the given provider.
func (s *Stats) MarkCacheUsed(m map[string]bool, provider string) {
	s.Mu.Lock()
	m[provider] = true
	s.Mu.Unlock()
}
