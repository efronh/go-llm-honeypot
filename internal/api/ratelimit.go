package api

import (
	"net"
	"sync"
	"time"
)

const (
	defaultRateLimit  = 30
	defaultRateWindow = time.Minute
	maxTrackedClients = 10000
)

type clientWindow struct {
	count     int
	windowEnd time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]clientWindow
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:   limit,
		window:  window,
		clients: make(map[string]clientWindow),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if len(rl.clients) >= maxTrackedClients {
		for k, v := range rl.clients {
			if now.After(v.windowEnd) {
				delete(rl.clients, k)
			}
		}
	}

	state, exists := rl.clients[ip]
	if !exists || now.After(state.windowEnd) {
		rl.clients[ip] = clientWindow{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if state.count >= rl.limit {
		return false
	}

	state.count++
	rl.clients[ip] = state
	return true
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
