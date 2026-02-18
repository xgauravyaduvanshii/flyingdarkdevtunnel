package proto

type AgentHello struct {
	Type         string   `json:"type"`
	Version      string   `json:"version"`
	AgentID      string   `json:"agentId"`
	AuthToken    string   `json:"authToken,omitempty"`
	Capabilities []string `json:"capabilities"`
}

type TunnelOpenRequest struct {
	Type               string `json:"type"`
	Protocol           string `json:"protocol"`
	LocalAddr          string `json:"localAddr"`
	RequestedSubdomain string `json:"requestedSubdomain,omitempty"`
	Region             string `json:"region"`
	Inspect            bool   `json:"inspect"`
}

type TunnelOpenResponse struct {
	Type         string `json:"type"`
	TunnelID     string `json:"tunnelId"`
	PublicURL    string `json:"publicUrl"`
	AssignedEdge string `json:"assignedEdge"`
}

type HTTPRequestFrame struct {
	Type       string            `json:"type"`
	RequestID  string            `json:"requestId"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	BodyBase64 string            `json:"bodyBase64,omitempty"`
}

type HTTPResponseFrame struct {
	Type       string              `json:"type"`
	RequestID  string              `json:"requestId"`
	StatusCode int                 `json:"statusCode"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"bodyBase64,omitempty"`
}

type TCPOpenFrame struct {
	Type     string `json:"type"`
	StreamID string `json:"streamId"`
}

type TCPDataFrame struct {
	Type       string `json:"type"`
	StreamID   string `json:"streamId"`
	DataBase64 string `json:"dataBase64"`
}

type TCPCloseFrame struct {
	Type     string `json:"type"`
	StreamID string `json:"streamId"`
}

type ErrorFrame struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
