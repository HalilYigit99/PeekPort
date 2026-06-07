package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"

	"peekport/internal/proto"
)

// ClientConfig holds connection parameters for the CLI client.
type ClientConfig struct {
	ServerURL string // e.g. "wss://scan.example.com" or "ws://localhost:8080"
	APIKey    string
	Insecure  bool // skip TLS verification (dev only)
}

// Result carries one streamed event from the server.
type Result struct {
	Port     *proto.PortResult
	Progress *proto.Progress
	Complete *proto.ScanComplete
	Err      error
}

// Connect establishes a WebSocket connection, sends the scan request, and
// streams Result values to the caller via the returned channel.
func Connect(ctx context.Context, cfg ClientConfig, req proto.ScanRequest) (<-chan Result, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	u.Path = "/ws"
	if cfg.APIKey != "" {
		q := u.Query()
		q.Set("key", cfg.APIKey)
		u.RawQuery = q.Encode()
	}

	dialer := websocket.DefaultDialer
	if cfg.Insecure {
		dialer = &websocket.Dialer{TLSClientConfig: insecureTLS()}
	}

	header := make(http.Header)
	if cfg.APIKey != "" {
		header.Set("X-API-Key", cfg.APIKey)
	}

	conn, _, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}

	if err := writeMsg(conn, proto.TypeScanRequest, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send request: %w", err)
	}

	out := make(chan Result, 64)

	go func() {
		defer close(out)
		defer conn.Close()

		go func() {
			<-ctx.Done()
			writeMsg(conn, proto.TypeCancel, nil) //nolint:errcheck
			conn.Close()
		}()

		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}

			var msg proto.Msg
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}

			payload, _ := json.Marshal(msg.Payload)

			switch msg.Type {
			case proto.TypePortResult:
				var r proto.PortResult
				if json.Unmarshal(payload, &r) == nil {
					out <- Result{Port: &r}
				}
			case proto.TypeProgress:
				var p proto.Progress
				if json.Unmarshal(payload, &p) == nil {
					out <- Result{Progress: &p}
				}
			case proto.TypeComplete:
				var c proto.ScanComplete
				if json.Unmarshal(payload, &c) == nil {
					out <- Result{Complete: &c}
				}
				return
			case proto.TypeError:
				var e map[string]string
				if json.Unmarshal(payload, &e) == nil {
					out <- Result{Err: fmt.Errorf("[%s] %s", e["code"], e["message"])}
				}
				return
			}
		}
	}()

	return out, nil
}
