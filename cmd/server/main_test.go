package main

import (
	"net/http"
	"testing"
	"time"
)

func TestServerBindAddressAndTimeouts(t *testing.T) {
	t.Setenv("HOST", "")
	t.Setenv("PORT", "")

	host := envOrDefault("HOST", "127.0.0.1")
	port := envOrDefault("PORT", "8080")
	srv := newServer(host, port, http.NewServeMux())

	if srv.Addr != "127.0.0.1:8080" {
		t.Errorf("default bind Addr = %q, want %q", srv.Addr, "127.0.0.1:8080")
	}
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second || srv.WriteTimeout != 10*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Errorf("unexpected server timeouts: %+v", srv)
	}
	if srv.MaxHeaderBytes != 1<<14 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 1<<14)
	}

	t.Setenv("HOST", "192.168.1.50")
	t.Setenv("PORT", "9090")
	customSrv := newServer(envOrDefault("HOST", "127.0.0.1"), envOrDefault("PORT", "8080"), http.NewServeMux())
	if customSrv.Addr != "192.168.1.50:9090" {
		t.Errorf("custom bind Addr = %q, want %q", customSrv.Addr, "192.168.1.50:9090")
	}
}
