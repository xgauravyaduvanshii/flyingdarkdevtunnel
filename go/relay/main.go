package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flyingdarkdevtunnel/fdt/proto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type claims struct {
	UserID    string `json:"userId"`
	OrgID     string `json:"orgId"`
	TunnelID  string `json:"tunnelId"`
	Protocol  string `json:"protocol"`
	Subdomain string `json:"subdomain"`
	TokenType string `json:"tokenType"`
	jwt.RegisteredClaims
}

type pendingHTTPResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type tcpStream struct {
	Conn net.Conn
}

type session struct {
	Conn          *websocket.Conn
	WriteMu       sync.Mutex
	TunnelID      string
	Protocol      string
	Subdomain     string
	PublicHost    string
	PublicTCPPort int

	PendingMu   sync.Mutex
	PendingHTTP map[string]chan pendingHTTPResponse
	TCPStreams  map[string]*tcpStream
}

type relayState struct {
	BaseDomain   string
	AgentSecret  string
	HTTPPort     int
	ControlPort  int
	TCPStartPort int
	TCPEndPort   int

	Mu        sync.RWMutex
	ByTunnel  map[string]*session
	ByHost    map[string]*session
	ByTCPPort map[int]*session
}

func newRelayState() *relayState {
	return &relayState{
		BaseDomain:   getEnv("RELAY_BASE_DOMAIN", "tunnel.yourdomain.com"),
		AgentSecret:  getEnv("RELAY_AGENT_JWT_SECRET", "replace_with_at_least_32_characters_here"),
		HTTPPort:     getEnvInt("RELAY_HTTP_PORT", 8080),
		ControlPort:  getEnvInt("RELAY_CONTROL_PORT", 8081),
		TCPStartPort: getEnvInt("RELAY_TCP_START_PORT", 7000),
		TCPEndPort:   getEnvInt("RELAY_TCP_END_PORT", 7099),
		ByTunnel:     map[string]*session{},
		ByHost:       map[string]*session{},
		ByTCPPort:    map[int]*session{},
	}
}

func main() {
	state := newRelayState()

	go startControlServer(state)
	startPublicHTTPServer(state)
}

func startControlServer(state *relayState) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if token == "" {
			http.Error(w, "missing agent token", http.StatusUnauthorized)
			return
		}

		parsedClaims, err := parseAgentToken(token, state.AgentSecret)
		if err != nil {
			http.Error(w, "invalid agent token", http.StatusUnauthorized)
			return
		}

		if parsedClaims.TokenType != "agent" {
			http.Error(w, "invalid token type", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("upgrade failed: %v", err)
			return
		}

		s := &session{
			Conn:        conn,
			TunnelID:    parsedClaims.TunnelID,
			Protocol:    parsedClaims.Protocol,
			Subdomain:   parsedClaims.Subdomain,
			PendingHTTP: map[string]chan pendingHTTPResponse{},
			TCPStreams:  map[string]*tcpStream{},
		}

		log.Printf("agent connected tunnel=%s protocol=%s", s.TunnelID, s.Protocol)
		go handleSession(state, s)
	})

	addr := fmt.Sprintf(":%d", state.ControlPort)
	log.Printf("relay control listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("control server failed: %v", err)
	}
}

func startPublicHTTPServer(state *relayState) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if idx := strings.Index(host, ":"); idx > -1 {
			host = host[:idx]
		}

		state.Mu.RLock()
		s := state.ByHost[host]
		state.Mu.RUnlock()

		if s == nil {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		requestID := uuid.NewString()
		respCh := make(chan pendingHTTPResponse, 1)

		s.PendingMu.Lock()
		s.PendingHTTP[requestID] = respCh
		s.PendingMu.Unlock()

		headers := map[string]string{}
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		frame := proto.HTTPRequestFrame{
			Type:       "http.request",
			RequestID:  requestID,
			Method:     r.Method,
			Path:       r.URL.RequestURI(),
			Headers:    headers,
			BodyBase64: base64.StdEncoding.EncodeToString(body),
		}

		if err := writeJSON(s, frame); err != nil {
			http.Error(w, "relay write failed", http.StatusBadGateway)
			cleanupPendingRequest(s, requestID)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		select {
		case resp := <-respCh:
			for key, values := range resp.Headers {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			if resp.StatusCode <= 0 {
				resp.StatusCode = http.StatusOK
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(resp.Body)
		case <-ctx.Done():
			http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
		}

		cleanupPendingRequest(s, requestID)
	})

	go func() {
		for {
			time.Sleep(10 * time.Second)
			state.Mu.RLock()
			count := len(state.ByTunnel)
			state.Mu.RUnlock()
			log.Printf("active sessions=%d", count)
		}
	}()

	addr := fmt.Sprintf(":%d", state.HTTPPort)
	log.Printf("relay public HTTP listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("public http server failed: %v", err)
	}
}

func cleanupPendingRequest(s *session, requestID string) {
	s.PendingMu.Lock()
	delete(s.PendingHTTP, requestID)
	s.PendingMu.Unlock()
}

func handleSession(state *relayState, s *session) {
	defer func() {
		cleanupSession(state, s)
		_ = s.Conn.Close()
		log.Printf("agent disconnected tunnel=%s", s.TunnelID)
	}()

	for {
		_, message, err := s.Conn.ReadMessage()
		if err != nil {
			return
		}

		var base map[string]any
		if err := json.Unmarshal(message, &base); err != nil {
			_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "bad_json", Message: err.Error()})
			continue
		}

		typeValue, _ := base["type"].(string)
		switch typeValue {
		case "agent.hello":
			continue
		case "tunnel.open":
			handleTunnelOpen(state, s, base)
		case "http.response":
			handleHTTPResponse(s, base)
		case "tcp.data":
			handleTCPDataFromAgent(s, base)
		case "tcp.close":
			handleTCPCloseFromAgent(s, base)
		default:
			_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "unknown_type", Message: typeValue})
		}
	}
}

func handleTunnelOpen(state *relayState, s *session, payload map[string]any) {
	req := proto.TunnelOpenRequest{}
	bytes, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytes, &req); err != nil {
		_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "invalid_tunnel_open", Message: err.Error()})
		return
	}

	if req.Protocol == "http" || req.Protocol == "https" {
		subdomain := req.RequestedSubdomain
		if subdomain == "" {
			if s.Subdomain != "" {
				subdomain = s.Subdomain
			} else {
				subdomain = randomSubdomain()
			}
		}
		host := fmt.Sprintf("%s.%s", subdomain, state.BaseDomain)
		s.PublicHost = host

		state.Mu.Lock()
		state.ByTunnel[s.TunnelID] = s
		state.ByHost[host] = s
		state.Mu.Unlock()

		response := proto.TunnelOpenResponse{
			Type:         "tunnel.opened",
			TunnelID:     s.TunnelID,
			PublicURL:    fmt.Sprintf("http://%s", host),
			AssignedEdge: fmt.Sprintf("us-edge-%d", rand.Intn(4)+1),
		}
		_ = writeJSON(s, response)
		return
	}

	if req.Protocol == "tcp" {
		port, err := reserveTCPPort(state, s)
		if err != nil {
			_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "tcp_port_unavailable", Message: err.Error()})
			return
		}
		s.PublicTCPPort = port

		response := proto.TunnelOpenResponse{
			Type:         "tunnel.opened",
			TunnelID:     s.TunnelID,
			PublicURL:    fmt.Sprintf("tcp://%s:%d", state.BaseDomain, port),
			AssignedEdge: fmt.Sprintf("us-edge-%d", rand.Intn(4)+1),
		}
		_ = writeJSON(s, response)
		return
	}

	_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "protocol_not_supported", Message: req.Protocol})
}

func reserveTCPPort(state *relayState, s *session) (int, error) {
	state.Mu.Lock()
	defer state.Mu.Unlock()

	for port := state.TCPStartPort; port <= state.TCPEndPort; port++ {
		if state.ByTCPPort[port] != nil {
			continue
		}

		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}
		state.ByTCPPort[port] = s
		state.ByTunnel[s.TunnelID] = s

		go acceptTCPConnections(state, s, listener, port)
		return port, nil
	}

	return 0, fmt.Errorf("no ports available in range %d-%d", state.TCPStartPort, state.TCPEndPort)
}

func acceptTCPConnections(_ *relayState, s *session, listener net.Listener, _ int) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		streamID := uuid.NewString()
		s.PendingMu.Lock()
		s.TCPStreams[streamID] = &tcpStream{Conn: conn}
		s.PendingMu.Unlock()

		_ = writeJSON(s, proto.TCPOpenFrame{Type: "tcp.open", StreamID: streamID})

		go func(c net.Conn, id string) {
			defer c.Close()
			buf := make([]byte, 32*1024)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					_ = writeJSON(s, proto.TCPDataFrame{
						Type:       "tcp.data",
						StreamID:   id,
						DataBase64: base64.StdEncoding.EncodeToString(buf[:n]),
					})
				}
				if err != nil {
					_ = writeJSON(s, proto.TCPCloseFrame{Type: "tcp.close", StreamID: id})
					s.PendingMu.Lock()
					delete(s.TCPStreams, id)
					s.PendingMu.Unlock()
					return
				}
			}
		}(conn, streamID)
	}
}

func handleHTTPResponse(s *session, payload map[string]any) {
	frame := proto.HTTPResponseFrame{}
	bytes, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytes, &frame); err != nil {
		return
	}

	body, _ := base64.StdEncoding.DecodeString(frame.BodyBase64)

	s.PendingMu.Lock()
	ch := s.PendingHTTP[frame.RequestID]
	s.PendingMu.Unlock()
	if ch == nil {
		return
	}

	ch <- pendingHTTPResponse{StatusCode: frame.StatusCode, Headers: frame.Headers, Body: body}
}

func handleTCPDataFromAgent(s *session, payload map[string]any) {
	frame := proto.TCPDataFrame{}
	bytes, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytes, &frame); err != nil {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(frame.DataBase64)
	if err != nil {
		return
	}

	s.PendingMu.Lock()
	stream := s.TCPStreams[frame.StreamID]
	s.PendingMu.Unlock()

	if stream != nil {
		_, _ = stream.Conn.Write(decoded)
	}
}

func handleTCPCloseFromAgent(s *session, payload map[string]any) {
	frame := proto.TCPCloseFrame{}
	bytes, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytes, &frame); err != nil {
		return
	}

	s.PendingMu.Lock()
	stream := s.TCPStreams[frame.StreamID]
	delete(s.TCPStreams, frame.StreamID)
	s.PendingMu.Unlock()

	if stream != nil {
		_ = stream.Conn.Close()
	}
}

func writeJSON(s *session, v any) error {
	s.WriteMu.Lock()
	defer s.WriteMu.Unlock()
	return s.Conn.WriteJSON(v)
}

func cleanupSession(state *relayState, s *session) {
	state.Mu.Lock()
	defer state.Mu.Unlock()

	delete(state.ByTunnel, s.TunnelID)
	if s.PublicHost != "" {
		delete(state.ByHost, s.PublicHost)
	}
	if s.PublicTCPPort > 0 {
		delete(state.ByTCPPort, s.PublicTCPPort)
	}

	s.PendingMu.Lock()
	for _, stream := range s.TCPStreams {
		_ = stream.Conn.Close()
	}
	s.PendingMu.Unlock()
}

func parseAgentToken(raw string, secret string) (*claims, error) {
	result := &claims{}
	token, err := jwt.ParseWithClaims(raw, result, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return result, nil
}

func randomSubdomain() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	builder := strings.Builder{}
	builder.WriteString("t-")
	for i := 0; i < 8; i++ {
		builder.WriteRune(letters[rand.Intn(len(letters))])
	}
	return builder.String()
}

func getEnv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
