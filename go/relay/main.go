package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flyingdarkdevtunnel/fdt/proto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type claims struct {
	UserID             string            `json:"userId"`
	OrgID              string            `json:"orgId"`
	TunnelID           string            `json:"tunnelId"`
	Protocol           string            `json:"protocol"`
	Subdomain          string            `json:"subdomain"`
	Region             string            `json:"region"`
	Hosts              []string          `json:"hosts"`
	TLSModes           map[string]string `json:"tlsModes"`
	BasicAuthUser      string            `json:"basicAuthUser"`
	BasicAuthPassword  string            `json:"basicAuthPassword"`
	IPAllowlist        []string          `json:"ipAllowlist"`
	MaxConcurrentConns int               `json:"maxConcurrentConns"`
	TokenType          string            `json:"tokenType"`
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
	Conn               *websocket.Conn
	WriteMu            sync.Mutex
	TunnelID           string
	Protocol           string
	Subdomain          string
	Region             string
	PublicTCPPort      int
	PublicHosts        []string
	TLSModes           map[string]string
	BasicAuthUser      string
	BasicAuthPassword  string
	IPAllowlist        []string
	MaxConcurrentConns int

	PendingMu   sync.Mutex
	PendingHTTP map[string]chan pendingHTTPResponse
	TCPStreams  map[string]*tcpStream
}

type relayState struct {
	BaseDomain                string
	Region                    string
	EdgePool                  map[string][]string
	AgentSecret               string
	HTTPPort                  int
	HTTPSPort                 int
	ControlPort               int
	TLSPassthroughPort        int
	TCPStartPort              int
	TCPEndPort                int
	TLSEnabled                bool
	AutoCertEnabled           bool
	AutoCertCacheDir          string
	AutoCertEmail             string
	AutoCertAllowAny          bool
	StaticCertFile            string
	StaticKeyFile             string
	AllowedTLSHosts           map[string]struct{}
	DefaultMaxConcurrentConns int

	Mu        sync.RWMutex
	ByTunnel  map[string]*session
	ByHost    map[string]*session
	HostModes map[string]string
	ByTCPPort map[int]*session
}

func newRelayState() *relayState {
	allowedHosts := map[string]struct{}{}
	for _, host := range strings.Split(getEnv("RELAY_ALLOWED_TLS_HOSTS", ""), ",") {
		normalized := normalizeHost(host)
		if normalized != "" {
			allowedHosts[normalized] = struct{}{}
		}
	}

	state := &relayState{
		BaseDomain:                getEnv("RELAY_BASE_DOMAIN", "tunnel.yourdomain.com"),
		Region:                    strings.ToLower(strings.TrimSpace(getEnv("RELAY_REGION", "us"))),
		EdgePool:                  parseEdgePool(getEnv("RELAY_EDGE_POOL", "us=us-edge-1|us-edge-2|us-edge-3")),
		AgentSecret:               getEnv("RELAY_AGENT_JWT_SECRET", "replace_with_at_least_32_characters_here"),
		HTTPPort:                  getEnvInt("RELAY_HTTP_PORT", 8080),
		HTTPSPort:                 getEnvInt("RELAY_HTTPS_PORT", 8443),
		ControlPort:               getEnvInt("RELAY_CONTROL_PORT", 8081),
		TLSPassthroughPort:        getEnvInt("RELAY_TLS_PASSTHROUGH_PORT", 9443),
		TCPStartPort:              getEnvInt("RELAY_TCP_START_PORT", 7000),
		TCPEndPort:                getEnvInt("RELAY_TCP_END_PORT", 7099),
		TLSEnabled:                getEnvBool("RELAY_TLS_ENABLE", true),
		AutoCertEnabled:           getEnvBool("RELAY_AUTOCERT_ENABLE", false),
		AutoCertCacheDir:          getEnv("RELAY_AUTOCERT_CACHE_DIR", filepath.Join(".data", "autocert")),
		AutoCertEmail:             getEnv("RELAY_AUTOCERT_EMAIL", ""),
		AutoCertAllowAny:          getEnvBool("RELAY_AUTOCERT_ALLOW_ANY", false),
		StaticCertFile:            getEnv("RELAY_TLS_CERT_FILE", ""),
		StaticKeyFile:             getEnv("RELAY_TLS_KEY_FILE", ""),
		AllowedTLSHosts:           allowedHosts,
		DefaultMaxConcurrentConns: getEnvInt("RELAY_DEFAULT_MAX_CONCURRENT_CONNS", 100),
		ByTunnel:                  map[string]*session{},
		ByHost:                    map[string]*session{},
		HostModes:                 map[string]string{},
		ByTCPPort:                 map[int]*session{},
	}

	if state.Region == "" {
		state.Region = "us"
	}
	if len(state.EdgePool) == 0 {
		state.EdgePool[state.Region] = []string{fmt.Sprintf("%s-edge-1", state.Region)}
	}

	if state.BaseDomain != "" {
		state.AllowedTLSHosts[state.BaseDomain] = struct{}{}
	}

	return state
}

func main() {
	state := newRelayState()
	mrand.Seed(time.Now().UnixNano())

	errCh := make(chan error, 4)

	go func() { errCh <- startControlServer(state) }()
	go func() { errCh <- startPublicHTTPServer(state) }()

	if state.TLSEnabled {
		go func() { errCh <- startPublicHTTPSServer(state) }()
	}

	if state.TLSPassthroughPort > 0 {
		go func() { errCh <- startTLSPassthroughServer(state) }()
	}

	go func() {
		for {
			time.Sleep(10 * time.Second)
			state.Mu.RLock()
			sessions := len(state.ByTunnel)
			hosts := len(state.ByHost)
			state.Mu.RUnlock()
			log.Printf("active sessions=%d hosts=%d", sessions, hosts)
		}
	}()

	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
}

func startControlServer(state *relayState) error {
	upgrader := websocket.Upgrader{CheckOrigin: func(_ *http.Request) bool { return true }}
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

		maxConcurrent := parsedClaims.MaxConcurrentConns
		if maxConcurrent <= 0 {
			maxConcurrent = state.DefaultMaxConcurrentConns
		}

		s := &session{
			Conn:               conn,
			TunnelID:           parsedClaims.TunnelID,
			Protocol:           parsedClaims.Protocol,
			Subdomain:          parsedClaims.Subdomain,
			Region:             strings.ToLower(strings.TrimSpace(parsedClaims.Region)),
			PublicHosts:        uniqueHosts(parsedClaims.Hosts),
			TLSModes:           parsedClaims.TLSModes,
			BasicAuthUser:      parsedClaims.BasicAuthUser,
			BasicAuthPassword:  parsedClaims.BasicAuthPassword,
			IPAllowlist:        parsedClaims.IPAllowlist,
			MaxConcurrentConns: maxConcurrent,
			PendingHTTP:        map[string]chan pendingHTTPResponse{},
			TCPStreams:         map[string]*tcpStream{},
		}
		if s.TLSModes == nil {
			s.TLSModes = map[string]string{}
		}
		if s.Region == "" {
			s.Region = state.Region
		}

		log.Printf("agent connected tunnel=%s protocol=%s", s.TunnelID, s.Protocol)
		go handleSession(state, s)
	})

	addr := fmt.Sprintf(":%d", state.ControlPort)
	log.Printf("relay control listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func buildPublicHTTPHandler(state *relayState) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		if !isSafeHost(host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}

		state.Mu.RLock()
		s := state.ByHost[host]
		mode := state.HostModes[host]
		state.Mu.RUnlock()

		if s == nil {
			http.NotFound(w, r)
			return
		}

		if mode == "passthrough" {
			http.Error(w, "host is configured for TLS passthrough", http.StatusUpgradeRequired)
			return
		}

		if !isRemoteAllowed(r.RemoteAddr, s.IPAllowlist) {
			http.Error(w, "forbidden by IP policy", http.StatusForbidden)
			return
		}

		if !checkBasicAuth(r, s.BasicAuthUser, s.BasicAuthPassword) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tunnel"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
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
		if s.MaxConcurrentConns > 0 && len(s.PendingHTTP) >= s.MaxConcurrentConns {
			s.PendingMu.Unlock()
			w.Header().Set("Retry-After", "1")
			http.Error(w, "tunnel concurrency limit reached", http.StatusTooManyRequests)
			return
		}
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

	return mux
}

func startPublicHTTPServer(state *relayState) error {
	handler := buildPublicHTTPHandler(state)
	if state.AutoCertEnabled {
		manager := buildAutoCertManager(state)
		handler = manager.HTTPHandler(handler)
	}

	addr := fmt.Sprintf(":%d", state.HTTPPort)
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("relay public HTTP listening on %s", addr)
	return server.ListenAndServe()
}

func startPublicHTTPSServer(state *relayState) error {
	handler := buildPublicHTTPHandler(state)
	tlsConfig, err := buildTLSConfig(state)
	if err != nil {
		return fmt.Errorf("failed to build TLS config: %w", err)
	}

	addr := fmt.Sprintf(":%d", state.HTTPSPort)
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on https port: %w", err)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("relay public HTTPS listening on %s", addr)
	return server.Serve(ln)
}

func buildTLSConfig(state *relayState) (*tls.Config, error) {
	if state.StaticCertFile != "" && state.StaticKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(state.StaticCertFile, state.StaticKeyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}, nil
	}

	if state.AutoCertEnabled {
		manager := buildAutoCertManager(state)
		return &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: manager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto, "h2", "http/1.1"},
		}, nil
	}

	cert, err := generateSelfSignedCert(state.BaseDomain)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func buildAutoCertManager(state *relayState) *autocert.Manager {
	_ = os.MkdirAll(state.AutoCertCacheDir, 0o700)
	return &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  state.AutoCertEmail,
		Cache:  autocert.DirCache(state.AutoCertCacheDir),
		HostPolicy: func(_ context.Context, host string) error {
			host = normalizeHost(host)
			if state.AutoCertAllowAny {
				return nil
			}
			if state.isTLSHostAllowed(host) {
				return nil
			}
			return fmt.Errorf("host is not allowlisted for autocert: %s", host)
		},
	}
}

func (state *relayState) isTLSHostAllowed(host string) bool {
	if host == "" {
		return false
	}
	state.Mu.RLock()
	defer state.Mu.RUnlock()
	_, ok := state.AllowedTLSHosts[host]
	if ok {
		return true
	}
	if state.BaseDomain != "" && (host == state.BaseDomain || strings.HasSuffix(host, "."+state.BaseDomain)) {
		return true
	}
	return false
}

func (state *relayState) pickEdge(region string) string {
	state.Mu.RLock()
	defer state.Mu.RUnlock()

	normalizedRegion := strings.ToLower(strings.TrimSpace(region))
	if normalizedRegion == "" {
		normalizedRegion = state.Region
	}

	if edges := state.EdgePool[normalizedRegion]; len(edges) > 0 {
		return edges[mrand.Intn(len(edges))]
	}
	if edges := state.EdgePool[state.Region]; len(edges) > 0 {
		return edges[mrand.Intn(len(edges))]
	}
	return fmt.Sprintf("%s-edge-1", normalizedRegion)
}

func startTLSPassthroughServer(state *relayState) error {
	addr := fmt.Sprintf(":%d", state.TLSPassthroughPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen for tls passthrough: %w", err)
	}
	log.Printf("relay TLS passthrough listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("passthrough accept failed: %v", err)
			continue
		}

		go func(c net.Conn) {
			host, wrappedConn, err := extractTLSClientHelloSNI(c)
			if err != nil {
				_ = c.Close()
				return
			}

			state.Mu.RLock()
			s := state.ByHost[host]
			mode := state.HostModes[host]
			state.Mu.RUnlock()

			if s == nil || mode != "passthrough" {
				_ = wrappedConn.Close()
				return
			}

			if !isRemoteAllowed(wrappedConn.RemoteAddr().String(), s.IPAllowlist) {
				_ = wrappedConn.Close()
				return
			}

			attachTCPConnectionToSession(s, wrappedConn)
		}(conn)
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
	bytesPayload, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytesPayload, &req); err != nil {
		_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "invalid_tunnel_open", Message: err.Error()})
		return
	}

	effectiveRegion := strings.ToLower(strings.TrimSpace(req.Region))
	if s.Region != "" {
		effectiveRegion = s.Region
	}
	if effectiveRegion == "" {
		effectiveRegion = state.Region
	}
	s.Region = effectiveRegion
	assignedEdge := state.pickEdge(effectiveRegion)

	if req.Protocol == "http" || req.Protocol == "https" {
		hosts := uniqueHosts(s.PublicHosts)
		if len(hosts) == 0 {
			subdomain := req.RequestedSubdomain
			if subdomain == "" {
				if s.Subdomain != "" {
					subdomain = s.Subdomain
				} else {
					subdomain = randomSubdomain()
				}
			}
			hosts = []string{fmt.Sprintf("%s.%s", subdomain, state.BaseDomain)}
		}
		registerSessionHosts(state, s, hosts, "termination")
		state.Mu.Lock()
		state.ByTunnel[s.TunnelID] = s
		state.Mu.Unlock()

		publicScheme := "http"
		if state.TLSEnabled {
			publicScheme = "https"
		}
		response := proto.TunnelOpenResponse{
			Type:         "tunnel.opened",
			TunnelID:     s.TunnelID,
			PublicURL:    fmt.Sprintf("%s://%s", publicScheme, hosts[0]),
			AssignedEdge: assignedEdge,
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
		if len(s.PublicHosts) > 0 {
			registerSessionHosts(state, s, s.PublicHosts, "passthrough")
		}

		response := proto.TunnelOpenResponse{
			Type:         "tunnel.opened",
			TunnelID:     s.TunnelID,
			PublicURL:    fmt.Sprintf("tcp://%s:%d", state.BaseDomain, port),
			AssignedEdge: assignedEdge,
		}
		_ = writeJSON(s, response)
		return
	}

	_ = writeJSON(s, proto.ErrorFrame{Type: "error", Code: "protocol_not_supported", Message: req.Protocol})
}

func registerSessionHosts(state *relayState, s *session, hosts []string, defaultMode string) {
	normalizedHosts := uniqueHosts(hosts)
	s.PublicHosts = normalizedHosts

	state.Mu.Lock()
	defer state.Mu.Unlock()

	for _, host := range normalizedHosts {
		if !isSafeHost(host) {
			continue
		}
		mode := defaultMode
		if explicitMode, ok := s.TLSModes[host]; ok {
			if explicitMode == "passthrough" || explicitMode == "termination" {
				mode = explicitMode
			}
		}

		state.ByHost[host] = s
		state.HostModes[host] = mode
		state.AllowedTLSHosts[host] = struct{}{}
	}
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
		go acceptTCPConnections(s, listener)
		return port, nil
	}

	return 0, fmt.Errorf("no ports available in range %d-%d", state.TCPStartPort, state.TCPEndPort)
}

func acceptTCPConnections(s *session, listener net.Listener) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		attachTCPConnectionToSession(s, conn)
	}
}

func attachTCPConnectionToSession(s *session, conn net.Conn) {
	streamID := uuid.NewString()
	s.PendingMu.Lock()
	if s.MaxConcurrentConns > 0 && len(s.TCPStreams) >= s.MaxConcurrentConns {
		s.PendingMu.Unlock()
		_ = conn.Close()
		log.Printf("tcp stream rejected tunnel=%s reason=concurrency_limit limit=%d", s.TunnelID, s.MaxConcurrentConns)
		return
	}
	s.TCPStreams[streamID] = &tcpStream{Conn: conn}
	s.PendingMu.Unlock()

	_ = writeJSON(s, proto.TCPOpenFrame{Type: "tcp.open", StreamID: streamID})
	go pumpTCPToAgent(s, streamID, conn)
}

func pumpTCPToAgent(s *session, streamID string, conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			_ = writeJSON(s, proto.TCPDataFrame{
				Type:       "tcp.data",
				StreamID:   streamID,
				DataBase64: base64.StdEncoding.EncodeToString(buf[:n]),
			})
		}
		if err != nil {
			_ = writeJSON(s, proto.TCPCloseFrame{Type: "tcp.close", StreamID: streamID})
			s.PendingMu.Lock()
			delete(s.TCPStreams, streamID)
			s.PendingMu.Unlock()
			return
		}
	}
}

func handleHTTPResponse(s *session, payload map[string]any) {
	frame := proto.HTTPResponseFrame{}
	bytesPayload, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytesPayload, &frame); err != nil {
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
	bytesPayload, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytesPayload, &frame); err != nil {
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
	bytesPayload, _ := json.Marshal(payload)
	if err := json.Unmarshal(bytesPayload, &frame); err != nil {
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
	if s.PublicTCPPort > 0 {
		delete(state.ByTCPPort, s.PublicTCPPort)
	}
	for _, host := range s.PublicHosts {
		if current := state.ByHost[host]; current == s {
			delete(state.ByHost, host)
			delete(state.HostModes, host)
		}
	}

	s.PendingMu.Lock()
	for _, stream := range s.TCPStreams {
		_ = stream.Conn.Close()
	}
	s.PendingMu.Unlock()
}

func parseAgentToken(raw string, secret string) (*claims, error) {
	result := &claims{}
	token, err := jwt.ParseWithClaims(raw, result, func(_ *jwt.Token) (any, error) {
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

func extractTLSClientHelloSNI(conn net.Conn) (string, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", conn, err
	}
	if header[0] != 0x16 {
		return "", conn, fmt.Errorf("not a tls handshake record")
	}
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen <= 0 || recordLen > 16*1024 {
		return "", conn, fmt.Errorf("invalid tls record length")
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "", conn, err
	}
	_ = conn.SetReadDeadline(time.Time{})

	host, err := parseSNIFromTLSHandshake(payload)
	if err != nil {
		return "", conn, err
	}

	prefetch := append(header, payload...)
	wrapped := &prefixedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(prefetch), conn),
	}
	return normalizeHost(host), wrapped, nil
}

func parseSNIFromTLSHandshake(record []byte) (string, error) {
	if len(record) < 4 || record[0] != 0x01 {
		return "", fmt.Errorf("not a client hello")
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if handshakeLen+4 > len(record) {
		return "", fmt.Errorf("client hello truncated")
	}

	body := record[4 : 4+handshakeLen]
	offset := 0

	if len(body) < 2+32+1 {
		return "", fmt.Errorf("invalid client hello body")
	}
	offset += 2 + 32

	sessionIDLen := int(body[offset])
	offset++
	if offset+sessionIDLen > len(body) {
		return "", fmt.Errorf("invalid session id")
	}
	offset += sessionIDLen

	if offset+2 > len(body) {
		return "", fmt.Errorf("invalid cipher suites len")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(body) {
		return "", fmt.Errorf("invalid cipher suites")
	}
	offset += cipherSuitesLen

	if offset+1 > len(body) {
		return "", fmt.Errorf("invalid compression methods len")
	}
	compressionMethodsLen := int(body[offset])
	offset++
	if offset+compressionMethodsLen > len(body) {
		return "", fmt.Errorf("invalid compression methods")
	}
	offset += compressionMethodsLen

	if offset+2 > len(body) {
		return "", fmt.Errorf("extensions missing")
	}
	extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extLen > len(body) {
		return "", fmt.Errorf("extensions truncated")
	}

	extensions := body[offset : offset+extLen]
	for extOffset := 0; extOffset+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[extOffset : extOffset+2])
		extDataLen := int(binary.BigEndian.Uint16(extensions[extOffset+2 : extOffset+4]))
		extOffset += 4
		if extOffset+extDataLen > len(extensions) {
			return "", fmt.Errorf("extension length invalid")
		}

		extData := extensions[extOffset : extOffset+extDataLen]
		extOffset += extDataLen

		if extType != 0x0000 {
			continue
		}

		if len(extData) < 2 {
			return "", fmt.Errorf("sni extension truncated")
		}
		serverNameListLen := int(binary.BigEndian.Uint16(extData[:2]))
		if serverNameListLen+2 > len(extData) {
			return "", fmt.Errorf("invalid server name list")
		}

		list := extData[2 : 2+serverNameListLen]
		for listOffset := 0; listOffset+3 <= len(list); {
			nameType := list[listOffset]
			nameLen := int(binary.BigEndian.Uint16(list[listOffset+1 : listOffset+3]))
			listOffset += 3
			if listOffset+nameLen > len(list) {
				return "", fmt.Errorf("invalid server name entry")
			}
			if nameType == 0 {
				return string(list[listOffset : listOffset+nameLen]), nil
			}
			listOffset += nameLen
		}
	}

	return "", fmt.Errorf("no sni host present")
}

type prefixedConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func generateSelfSignedCert(baseDomain string) (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkixName("TunnelForge Relay"),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{baseDomain, "*" + "." + baseDomain},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName, Organization: []string{"TunnelForge"}}
}

func checkBasicAuth(r *http.Request, expectedUser, expectedPassword string) bool {
	if expectedUser == "" && expectedPassword == "" {
		return true
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	userMatch := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(expectedUser)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedPassword)) == 1
	return userMatch && passwordMatch
}

func isRemoteAllowed(remoteAddr string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, rule := range allowlist {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		if strings.Contains(rule, "/") {
			_, cidr, err := net.ParseCIDR(rule)
			if err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}

		exact := net.ParseIP(rule)
		if exact != nil && exact.Equal(ip) {
			return true
		}
	}
	return false
}

func uniqueHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(hosts))
	for _, host := range hosts {
		normalized := normalizeHost(host)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if idx := strings.Index(host, ":"); idx > -1 {
		host = host[:idx]
	}
	return host
}

func isSafeHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func randomSubdomain() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	builder := strings.Builder{}
	builder.WriteString("t-")
	for i := 0; i < 8; i++ {
		builder.WriteRune(letters[mrand.Intn(len(letters))])
	}
	return builder.String()
}

func parseEdgePool(raw string) map[string][]string {
	pool := map[string][]string{}
	entries := strings.Split(raw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		region := strings.ToLower(strings.TrimSpace(parts[0]))
		if region == "" {
			continue
		}
		rawEdges := strings.Split(parts[1], "|")
		edges := make([]string, 0, len(rawEdges))
		for _, edge := range rawEdges {
			edge = strings.TrimSpace(edge)
			if edge == "" {
				continue
			}
			edges = append(edges, edge)
		}
		if len(edges) > 0 {
			pool[region] = edges
		}
	}
	return pool
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

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
