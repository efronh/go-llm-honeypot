package api

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultRateLimit           = 30
	defaultRateWindow          = time.Minute
	maxTrackedClients          = 10000
	rateLimitLogSampleInterval = 50
)

type clientWindow struct {
	count      int
	violations int
	windowEnd  time.Time
}

type RateLimiter struct {
	mu            sync.Mutex
	limit         int
	window        time.Duration
	maxClients    int
	overflowCount int
	clients       map[string]clientWindow
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = defaultRateLimit
	}
	if window <= 0 {
		window = defaultRateWindow
	}
	return &RateLimiter{
		limit:      limit,
		window:     window,
		maxClients: maxTrackedClients,
		clients:    make(map[string]clientWindow),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	allowed, _, _ := rl.Check(ip)
	return allowed
}

func (rl *RateLimiter) Check(ip string) (allowed bool, shouldLog bool, violations int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if state, exists := rl.clients[ip]; exists {
		if !now.Before(state.windowEnd) {
			rl.clients[ip] = clientWindow{
				count:     1,
				windowEnd: now.Add(rl.window),
			}
			return true, false, 0
		}
		if state.count >= rl.limit {
			state.violations++
			rl.clients[ip] = state
			sample := state.violations == 1 || state.violations%rateLimitLogSampleInterval == 0
			return false, sample, state.violations
		}
		state.count++
		rl.clients[ip] = state
		return true, false, 0
	}

	if len(rl.clients) >= rl.maxClients {
		rl.evictExpired(now)
		if len(rl.clients) >= rl.maxClients {
			rl.overflowCount++
			sample := rl.overflowCount == 1 || rl.overflowCount%rateLimitLogSampleInterval == 0
			return false, sample, rl.overflowCount
		}
	}

	rl.clients[ip] = clientWindow{
		count:     1,
		windowEnd: now.Add(rl.window),
	}
	return true, false, 0
}

func (rl *RateLimiter) evictExpired(now time.Time) {
	for k, v := range rl.clients {
		if !now.Before(v.windowEnd) {
			delete(rl.clients, k)
		}
	}
}

func clientIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
