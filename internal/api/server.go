package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/gorilla/websocket"

	"peekport/internal/proto"
	"peekport/internal/scanner"
)

var upgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	CheckOrigin:      func(r *http.Request) bool { return true },
}

// ServerConfig holds all server-side settings.
type ServerConfig struct {
	Domain  string
	Email   string
	APIKey  string
	CertDir string
	DevMode bool
	Port    int // dev mode port (default 8080)
}

// ListenAndServe starts the HTTPS (or HTTP in dev mode) server.
func ListenAndServe(cfg ServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", makeWSHandler(cfg.APIKey))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	})

	if cfg.DevMode {
		port := cfg.Port
		if port == 0 {
			port = 8080
		}
		addr := fmt.Sprintf(":%d", port)
		log.Printf("[PeekPort] Dev mode: HTTP on %s (no TLS)", addr)
		return http.ListenAndServe(addr, mux)
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.CertDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.Email,
	}

	// Port 80: ACME HTTP challenge + redirect to HTTPS
	go func() {
		if err := http.ListenAndServe(":80", m.HTTPHandler(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			},
		))); err != nil {
			log.Printf("[ACME] HTTP listener error: %v", err)
		}
	}()

	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    m.TLSConfig(),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}
	log.Printf("[PeekPort] HTTPS on :443 – domain %s", cfg.Domain)
	return srv.ListenAndServeTLS("", "")
}

func makeWSHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}
		if apiKey != "" && key != apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[WS] upgrade error: %v", err)
			return
		}
		defer conn.Close()

		log.Printf("[WS] client connected from %s", r.RemoteAddr)
		handleSession(conn)
		log.Printf("[WS] client disconnected: %s", r.RemoteAddr)
	}
}

func handleSession(conn *websocket.Conn) {
	// Read all incoming messages into a channel so we have a single reader.
	inbound := make(chan []byte, 8)
	go func() {
		defer close(inbound)
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			inbound <- raw
		}
	}()

	// Wait for the scan request (with 30s deadline).
	var req proto.ScanRequest
	select {
	case raw, ok := <-inbound:
		if !ok {
			return
		}
		var msg proto.Msg
		if err := json.Unmarshal(raw, &msg); err != nil || msg.Type != proto.TypeScanRequest {
			sendError(conn, "invalid_request", "expected scan_request as first message")
			return
		}
		payloadBytes, _ := json.Marshal(msg.Payload)
		if err := json.Unmarshal(payloadBytes, &req); err != nil {
			sendError(conn, "invalid_request", err.Error())
			return
		}
	case <-time.After(30 * time.Second):
		sendError(conn, "timeout", "no scan_request received within 30s")
		return
	}

	if req.Target == "" {
		sendError(conn, "invalid_request", "target is required")
		return
	}
	if req.Mode == "" {
		req.Mode = proto.ModeFast
	}
	if len(req.Protocols) == 0 {
		req.Protocols = []proto.Protocol{proto.TCP}
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Watch for cancel message from client.
	go func() {
		for raw := range inbound {
			var msg proto.Msg
			if json.Unmarshal(raw, &msg) == nil && msg.Type == proto.TypeCancel {
				cancel()
				return
			}
		}
		cancel() // connection closed
	}()

	log.Printf("[SCAN] target=%s mode=%s protocols=%v timeout=%v",
		req.Target, req.Mode, req.Protocols, timeout)

	cfg := scanner.Config{
		Target:      req.Target,
		Mode:        req.Mode,
		Protocols:   req.Protocols,
		Timeout:     timeout,
		Concurrency: req.Concurrency,
	}

	for res := range scanner.Run(ctx, cfg) {
		var err error
		switch {
		case res.Port != nil:
			err = writeMsg(conn, proto.TypePortResult, res.Port)
		case res.Progress != nil:
			err = writeMsg(conn, proto.TypeProgress, res.Progress)
		case res.Complete != nil:
			err = writeMsg(conn, proto.TypeComplete, res.Complete)
		}
		if err != nil {
			log.Printf("[WS] write error: %v", err)
			return
		}
	}
}

func writeMsg(conn *websocket.Conn, typ string, payload any) error {
	data, err := json.Marshal(proto.Msg{Type: typ, Payload: payload})
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

func sendError(conn *websocket.Conn, code, msg string) {
	writeMsg(conn, proto.TypeError, map[string]string{ //nolint:errcheck
		"code": code, "message": msg,
	})
}
