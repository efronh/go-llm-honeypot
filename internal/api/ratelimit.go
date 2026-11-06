package api

import (
	"net"
	"strings"
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
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxClients int
	clients    map[string]clientWindow
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
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if state, exists := rl.clients[ip]; exists {
		if !now.Before(state.windowEnd) {
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

	if len(rl.clients) >= rl.maxClients {
		rl.evictExpired(now)
		if len(rl.clients) >= rl.maxClients {
			return false
		}
	}

	rl.clients[ip] = clientWindow{
		count:     1,
		windowEnd: now.Add(rl.window),
	}
	return true
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
