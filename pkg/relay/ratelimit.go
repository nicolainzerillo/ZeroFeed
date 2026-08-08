package relay

import (
	"net"
	"sync"
	"time"
)

const (
	MaxFailedAttempts = 3
	BanDuration       = 5 * time.Minute
)

type ipRecord struct {
	attempts     int
	bannedUntil  time.Time
	lastActivity time.Time
}

// RateLimiter tracks failed authentication attempts per IP address and enforces temporary bans.
type RateLimiter struct {
	records map[string]*ipRecord
	enabled bool
	mu      sync.Mutex
}

// NewRateLimiter creates a RateLimiter instance.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		records: make(map[string]*ipRecord),
		enabled: true,
	}
}

// SetEnabled toggles rate limiting active status.
func (r *RateLimiter) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// IsBanned checks if an IP is currently rate-limited.
func (r *RateLimiter) IsBanned(remoteAddr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.enabled {
		return false
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	rec, ok := r.records[ip]
	if !ok {
		return false
	}

	now := time.Now()
	rec.lastActivity = now

	if now.Before(rec.bannedUntil) {
		return true
	}

	if now.After(rec.bannedUntil) && rec.attempts >= MaxFailedAttempts {
		delete(r.records, ip)
	}

	return false
}

// RecordFailure increments failed attempts for an IP address.
func (r *RateLimiter) RecordFailure(remoteAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.enabled {
		return
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	now := time.Now()
	rec, ok := r.records[ip]
	if !ok {
		rec = &ipRecord{}
		r.records[ip] = rec
	}

	rec.lastActivity = now
	rec.attempts++
	if rec.attempts >= MaxFailedAttempts {
		rec.bannedUntil = now.Add(BanDuration)
	}
}

// RecordSuccess resets failed attempt counters for a successfully authenticated IP.
func (r *RateLimiter) RecordSuccess(remoteAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	delete(r.records, ip)
}

// CleanupStale removes stale IP failure records that have been inactive longer than maxAge.
func (r *RateLimiter) CleanupStale(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for ip, rec := range r.records {
		if now.After(rec.bannedUntil) && now.Sub(rec.lastActivity) > maxAge {
			delete(r.records, ip)
		}
	}
}

// Count returns the current number of tracked IP records.
func (r *RateLimiter) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}
