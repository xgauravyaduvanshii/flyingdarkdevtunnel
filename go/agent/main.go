package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xgauravyaduvanshii/flyingdarkdevtunnel/go/proto"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type localConfig struct {
	APIBaseURL      string `json:"apiBaseUrl"`
	RelayControlURL string `json:"relayControlUrl"`
	AccessToken     string `json:"accessToken"`
	RefreshToken    string `json:"refreshToken"`
	Authtoken       string `json:"authtoken"`
}

type exchangeResponse struct {
	AgentToken string `json:"agentToken"`
	Tunnel     struct {
		ID        string  `json:"id"`
		Protocol  string  `json:"protocol"`
		Subdomain *string `json:"subdomain"`
		LocalAddr string  `json:"localAddr"`
		PublicURL *string `json:"publicUrl"`
	} `json:"tunnel"`
}

type startConfig struct {
	Authtoken       string `yaml:"authtoken"`
	APIBaseURL      string `yaml:"apiBaseUrl"`
	RelayControlURL string `yaml:"relayControlUrl"`
	Tunnels         []struct {
		Name      string `yaml:"name"`
		Protocol  string `yaml:"protocol"`
		TunnelID  string `yaml:"tunnelId"`
		LocalAddr string `yaml:"localAddr"`
		Region    string `yaml:"region"`
	} `yaml:"tunnels"`
}

func main() {
	root := &cobra.Command{Use: "fdt", Short: "TunnelForge CLI"}

	root.AddCommand(loginCmd(), httpCmd(), tcpCmd(), startCmd(), tunnelsCmd(), inspectCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loginCmd() *cobra.Command {
	var apiURL, email, password, authtoken string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and store local credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload := map[string]string{"email": email, "password": password}
			respBody, err := requestJSON(http.MethodPost, fmt.Sprintf("%s/v1/auth/login", strings.TrimRight(apiURL, "/")), payload, "")
			if err != nil {
				return err
			}

			parsed := map[string]string{}
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				return fmt.Errorf("failed to parse login response: %w", err)
			}

			cfg, _ := loadConfig()
			cfg.APIBaseURL = apiURL
			cfg.AccessToken = parsed["accessToken"]
			cfg.RefreshToken = parsed["refreshToken"]
			if authtoken != "" {
				cfg.Authtoken = authtoken
			}
			if cfg.RelayControlURL == "" {
				cfg.RelayControlURL = "ws://localhost:8081/control"
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}

			fmt.Println("Login successful.")
			if cfg.Authtoken == "" {
				fmt.Println("No authtoken saved. Provide --authtoken or register via API and rotate token.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&apiURL, "api", "http://localhost:4000", "Control plane API URL")
	cmd.Flags().StringVar(&email, "email", "", "Account email")
	cmd.Flags().StringVar(&password, "password", "", "Account password")
	cmd.Flags().StringVar(&authtoken, "authtoken", "", "Optional agent authtoken to save locally")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("password")

	return cmd
}

func httpCmd() *cobra.Command {
	var tunnelID, localAddr, authtoken, apiURL, relayURL, requestedSubdomain, region string

	cmd := &cobra.Command{
		Use:   "http",
		Short: "Start an HTTP/HTTPS tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := loadConfig()
			if apiURL == "" {
				apiURL = cfg.APIBaseURL
			}
			if relayURL == "" {
				relayURL = cfg.RelayControlURL
			}
			if authtoken == "" {
				authtoken = cfg.Authtoken
			}
			if apiURL == "" || relayURL == "" || authtoken == "" {
				return fmt.Errorf("missing api/relay/authtoken configuration")
			}

			if localAddr == "" {
				localAddr = "http://localhost:3000"
			}

			return runHTTPOrHTTPSAgentTunnel(apiURL, relayURL, authtoken, tunnelID, localAddr, "http", requestedSubdomain, region)
		},
	}

	cmd.Flags().StringVar(&tunnelID, "tunnel-id", "", "Tunnel UUID created in control plane")
	cmd.Flags().StringVar(&localAddr, "local", "http://localhost:3000", "Local HTTP target")
	cmd.Flags().StringVar(&authtoken, "authtoken", "", "Account authtoken")
	cmd.Flags().StringVar(&apiURL, "api", "", "Control plane API URL")
	cmd.Flags().StringVar(&relayURL, "relay", "", "Relay control websocket URL")
	cmd.Flags().StringVar(&requestedSubdomain, "subdomain", "", "Requested subdomain override")
	cmd.Flags().StringVar(&region, "region", "us", "Edge region preference (us/eu/ap)")
	_ = cmd.MarkFlagRequired("tunnel-id")

	return cmd
}

func tcpCmd() *cobra.Command {
	var tunnelID, localAddr, authtoken, apiURL, relayURL, region string

	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "Start a TCP tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := loadConfig()
			if apiURL == "" {
				apiURL = cfg.APIBaseURL
			}
			if relayURL == "" {
				relayURL = cfg.RelayControlURL
			}
			if authtoken == "" {
				authtoken = cfg.Authtoken
			}
			if apiURL == "" || relayURL == "" || authtoken == "" {
				return fmt.Errorf("missing api/relay/authtoken configuration")
			}

			if localAddr == "" {
				localAddr = "127.0.0.1:22"
			}

			return runTCPTunnel(apiURL, relayURL, authtoken, tunnelID, localAddr, region)
		},
	}

	cmd.Flags().StringVar(&tunnelID, "tunnel-id", "", "Tunnel UUID created in control plane")
	cmd.Flags().StringVar(&localAddr, "local", "127.0.0.1:22", "Local TCP target host:port")
	cmd.Flags().StringVar(&authtoken, "authtoken", "", "Account authtoken")
	cmd.Flags().StringVar(&apiURL, "api", "", "Control plane API URL")
	cmd.Flags().StringVar(&relayURL, "relay", "", "Relay control websocket URL")
	cmd.Flags().StringVar(&region, "region", "us", "Edge region preference (us/eu/ap)")
	_ = cmd.MarkFlagRequired("tunnel-id")

	return cmd
}

func startCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start multiple named tunnels from config",
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := os.ReadFile(configPath)
			if err != nil {
				return err
			}
			cfg := startConfig{}
			if err := yaml.Unmarshal(content, &cfg); err != nil {
				return err
			}

			if cfg.APIBaseURL == "" || cfg.RelayControlURL == "" || cfg.Authtoken == "" {
				return fmt.Errorf("config requires apiBaseUrl, relayControlUrl, authtoken")
			}

			var wg sync.WaitGroup
			errCh := make(chan error, len(cfg.Tunnels))

			for _, t := range cfg.Tunnels {
				tunnel := t
				wg.Add(1)
				go func() {
					defer wg.Done()
					switch strings.ToLower(tunnel.Protocol) {
					case "http", "https":
						region := tunnel.Region
						if region == "" {
							region = "us"
						}
						err := runHTTPOrHTTPSAgentTunnel(cfg.APIBaseURL, cfg.RelayControlURL, cfg.Authtoken, tunnel.TunnelID, tunnel.LocalAddr, tunnel.Protocol, "", region)
						if err != nil {
							errCh <- fmt.Errorf("tunnel %s failed: %w", tunnel.Name, err)
						}
					case "tcp":
						region := tunnel.Region
						if region == "" {
							region = "us"
						}
						err := runTCPTunnel(cfg.APIBaseURL, cfg.RelayControlURL, cfg.Authtoken, tunnel.TunnelID, tunnel.LocalAddr, region)
						if err != nil {
							errCh <- fmt.Errorf("tunnel %s failed: %w", tunnel.Name, err)
						}
					default:
						errCh <- fmt.Errorf("unsupported protocol %s in tunnel %s", tunnel.Protocol, tunnel.Name)
					}
				}()
			}

			wg.Wait()
			close(errCh)
			for err := range errCh {
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "ourdomain.yml", "Path to tunnel config file")
	return cmd
}

func tunnelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnels",
		Short: "Tunnel operations",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List tunnels",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			respBody, err := requestJSON(http.MethodGet, fmt.Sprintf("%s/v1/tunnels", strings.TrimRight(cfg.APIBaseURL, "/")), nil, cfg.AccessToken)
			if err != nil {
				return err
			}
			fmt.Println(string(respBody))
			return nil
		},
	})

	return cmd
}

func inspectCmd() *cobra.Command {
	var tunnelID string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Fetch request logs for a tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			endpoint := fmt.Sprintf("%s/v1/requests?tunnelId=%s", strings.TrimRight(cfg.APIBaseURL, "/"), tunnelID)
			respBody, err := requestJSON(http.MethodGet, endpoint, nil, cfg.AccessToken)
			if err != nil {
				return err
			}
			fmt.Println(string(respBody))
			return nil
		},
	}
	cmd.Flags().StringVar(&tunnelID, "tunnel-id", "", "Tunnel UUID")
	_ = cmd.MarkFlagRequired("tunnel-id")
	return cmd
}

func runHTTPOrHTTPSAgentTunnel(apiURL, relayURL, authtoken, tunnelID, localAddr, protocol, requestedSubdomain, region string) error {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		region = "us"
	}

	exchange, err := exchangeAgentToken(apiURL, authtoken, tunnelID)
	if err != nil {
		return err
	}

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.Dial(fmt.Sprintf("%s?token=%s", relayURL, exchange.AgentToken), nil)
	if err != nil {
		return fmt.Errorf("relay dial failed: %w", err)
	}
	defer conn.Close()

	hello := proto.AgentHello{
		Type:         "agent.hello",
		Version:      "1.0",
		AgentID:      uuid.NewString(),
		Capabilities: []string{"http", "tcp", "tls_passthrough"},
	}
	if err := conn.WriteJSON(hello); err != nil {
		return err
	}

	openReq := proto.TunnelOpenRequest{
		Type:               "tunnel.open",
		Protocol:           protocol,
		LocalAddr:          localAddr,
		RequestedSubdomain: requestedSubdomain,
		Region:             region,
		Inspect:            true,
	}
	if err := conn.WriteJSON(openReq); err != nil {
		return err
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var base map[string]any
		if err := json.Unmarshal(msg, &base); err != nil {
			continue
		}

		typeValue, _ := base["type"].(string)
		switch typeValue {
		case "tunnel.opened":
			var opened proto.TunnelOpenResponse
			_ = json.Unmarshal(msg, &opened)
			fmt.Printf("Tunnel opened: %s\n", opened.PublicURL)
		case "http.request":
			if err := handleIncomingHTTPRequest(conn, msg, localAddr); err != nil {
				fmt.Printf("request handling error: %v\n", err)
			}
		case "error":
			fmt.Printf("relay error: %s\n", string(msg))
		}
	}
}

func runTCPTunnel(apiURL, relayURL, authtoken, tunnelID, localAddr, region string) error {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		region = "us"
	}

	exchange, err := exchangeAgentToken(apiURL, authtoken, tunnelID)
	if err != nil {
		return err
	}

	conn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("%s?token=%s", relayURL, exchange.AgentToken), nil)
	if err != nil {
		return fmt.Errorf("relay dial failed: %w", err)
	}
	defer conn.Close()

	hello := proto.AgentHello{
		Type:         "agent.hello",
		Version:      "1.0",
		AgentID:      uuid.NewString(),
		Capabilities: []string{"tcp"},
	}
	if err := conn.WriteJSON(hello); err != nil {
		return err
	}

	openReq := proto.TunnelOpenRequest{
		Type:     "tunnel.open",
		Protocol: "tcp",
		LocalAddr: localAddr,
		Region: region,
		Inspect:  false,
	}
	if err := conn.WriteJSON(openReq); err != nil {
		return err
	}

	streamMu := sync.Mutex{}
	streams := map[string]net.Conn{}
	writeMu := sync.Mutex{}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var base map[string]any
		if err := json.Unmarshal(msg, &base); err != nil {
			continue
		}
		typeValue, _ := base["type"].(string)

		switch typeValue {
		case "tunnel.opened":
			var opened proto.TunnelOpenResponse
			_ = json.Unmarshal(msg, &opened)
			fmt.Printf("TCP tunnel opened: %s\n", opened.PublicURL)
		case "tcp.open":
			streamID, _ := base["streamId"].(string)
			localConn, err := net.Dial("tcp", localAddr)
			if err != nil {
				fmt.Printf("failed to dial local tcp service: %v\n", err)
				continue
			}
			streamMu.Lock()
			streams[streamID] = localConn
			streamMu.Unlock()

			go func(id string, c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						frame := proto.TCPDataFrame{
							Type:       "tcp.data",
							StreamID:   id,
							DataBase64: base64.StdEncoding.EncodeToString(buf[:n]),
						}
						writeMu.Lock()
						_ = conn.WriteJSON(frame)
						writeMu.Unlock()
					}
					if err != nil {
						writeMu.Lock()
						_ = conn.WriteJSON(proto.TCPCloseFrame{Type: "tcp.close", StreamID: id})
						writeMu.Unlock()
						streamMu.Lock()
						delete(streams, id)
						streamMu.Unlock()
						return
					}
				}
			}(streamID, localConn)
		case "tcp.data":
			frame := proto.TCPDataFrame{}
			_ = json.Unmarshal(msg, &frame)
			decoded, err := base64.StdEncoding.DecodeString(frame.DataBase64)
			if err != nil {
				continue
			}
			streamMu.Lock()
			localConn := streams[frame.StreamID]
			streamMu.Unlock()
			if localConn != nil {
				_, _ = localConn.Write(decoded)
			}
		case "tcp.close":
			frame := proto.TCPCloseFrame{}
			_ = json.Unmarshal(msg, &frame)
			streamMu.Lock()
			localConn := streams[frame.StreamID]
			delete(streams, frame.StreamID)
			streamMu.Unlock()
			if localConn != nil {
				_ = localConn.Close()
			}
		case "error":
			fmt.Printf("relay error: %s\n", string(msg))
		}
	}
}

func handleIncomingHTTPRequest(conn *websocket.Conn, raw []byte, localAddr string) error {
	frame := proto.HTTPRequestFrame{}
	if err := json.Unmarshal(raw, &frame); err != nil {
		return err
	}

	body, err := base64.StdEncoding.DecodeString(frame.BodyBase64)
	if err != nil {
		return err
	}

	target := strings.TrimRight(localAddr, "/") + frame.Path
	req, err := http.NewRequest(frame.Method, target, bytes.NewReader(body))
	if err != nil {
		return err
	}

	for key, value := range frame.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		response := proto.HTTPResponseFrame{
			Type:       "http.response",
			RequestID:  frame.RequestID,
			StatusCode: 502,
			Headers:    map[string][]string{"content-type": {"application/json"}},
			BodyBase64: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"error":%q}`, err.Error()))),
		}
		return conn.WriteJSON(response)
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(res.Body)
	response := proto.HTTPResponseFrame{
		Type:       "http.response",
		RequestID:  frame.RequestID,
		StatusCode: res.StatusCode,
		Headers:    res.Header,
		BodyBase64: base64.StdEncoding.EncodeToString(resBody),
	}

	return conn.WriteJSON(response)
}

func exchangeAgentToken(apiURL, authtoken, tunnelID string) (*exchangeResponse, error) {
	payload := map[string]string{
		"authtoken": authtoken,
		"tunnelId":  tunnelID,
	}
	endpoint := fmt.Sprintf("%s/v1/agent/exchange", strings.TrimRight(apiURL, "/"))
	body, err := requestJSON(http.MethodPost, endpoint, payload, "")
	if err != nil {
		return nil, err
	}
	resp := &exchangeResponse{}
	if err := json.Unmarshal(body, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func requestJSON(method, url string, payload any, bearerToken string) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if bearerToken != "" {
		req.Header.Set("authorization", "Bearer "+bearerToken)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func loadConfig() (*localConfig, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &localConfig{}, nil
		}
		return nil, err
	}

	cfg := &localConfig{}
	if err := json.Unmarshal(content, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func saveConfig(cfg *localConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

func configPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "fdt", "config.json"), nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".config", "fdt", "config.json"), nil
}
