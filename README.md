# Go LLM Honeypot

A lightweight HTTP honeypot that accepts chat-completion-shaped requests,
records request metadata, and flags a small set of prompt-injection indicators.
It uses only the Go standard library.

## Run

```sh
go run ./cmd/server
```

The server listens on `:8080` by default. Configure it with:

- `PORT` — listening port (default `8080`)
- `LOG_FILE` — JSON-lines event log path (default `logs/honeypot.log`)

## Endpoints

- `GET /healthz` — returns `{"status":"ok"}`
- `GET /v1/models` — returns an OpenAI-compatible decoy model list and records reconnaissance probes
- `POST /v1/chat/completions` — accepts a JSON object with a non-empty
  `messages` array and returns a context-aware decoy completion

Example:

```sh
curl -X POST http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"example","messages":[{"role":"user","content":"Hello"}]}'
```

The event log records the HTTP method, path, remote address, user-agent,
`has_auth_header` flag, SHA-256 authorization header fingerprint (`auth_sha256`),
requested model, message count, SHA-256 prompt fingerprint (`prompt_sha256`),
`is_suspicious` flag, and categorized detector findings (`prompt_injection`,
`system_prompt_extraction`, `jailbreak`, `role_manipulation`, `obfuscation`).
It does not store plaintext message contents or raw API keys.

## Test

```sh
go test -v ./...
```
