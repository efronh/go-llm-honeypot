package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/efronh/go-llm-honeypot/internal/api"
	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/logger"
)

func main() {
	reportMode := flag.Bool("report", false, "print telemetry summary from LOG_FILE and exit")
	flag.Parse()

	logFile := envOrDefault("LOG_FILE", "logs/honeypot.log")
	if *reportMode {
		summary, err := logger.Summarize(logFile)
		if err != nil {
			log.Fatalf("summarize telemetry log: %v", err)
		}
		out, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			log.Fatalf("format summary: %v", err)
		}
		fmt.Println(string(out))
		return
	}

	port := envOrDefault("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("invalid PORT %q: must be a number", port)
	}

	requestLogger, err := logger.New(logFile)
	if err != nil {
		log.Fatalf("initialize request logger: %v", err)
	}
	defer func() {
		if err := requestLogger.Close(); err != nil {
			log.Printf("close request logger: %v", err)
		}
	}()

	mux := http.NewServeMux()
	api.NewHandler(detection.NewDetector(), requestLogger).RegisterRoutes(mux)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("go-llm-honeypot listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
