export type AgentHello = {
  type: "agent.hello";
  version: "1.0";
  agentId: string;
  authToken: string;
  capabilities: ("http" | "tcp" | "tls_passthrough")[];
};

export type TunnelOpenRequest = {
  type: "tunnel.open";
  protocol: "http" | "tcp" | "https";
  localAddr: string;
  requestedSubdomain?: string;
  region: "us";
  inspect: boolean;
};

export type TunnelOpenResponse = {
  type: "tunnel.opened";
  tunnelId: string;
  publicUrl: string;
  assignedEdge: string;
  authPolicy?: {
    basicAuth?: boolean;
    ipAllowlist?: string[];
  };
};

export type ControlMessage = AgentHello | TunnelOpenRequest | TunnelOpenResponse;

export class ApiClient {
  private readonly baseUrl: string;
  private token?: string;

  constructor(baseUrl: string, token?: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.token = token;
  }

  setToken(token: string): void {
    this.token = token;
  }

  async login(email: string, password: string): Promise<{ accessToken: string; refreshToken: string }> {
    return this.request("/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
  }

  async listTunnels(): Promise<unknown> {
    return this.request("/v1/tunnels");
  }

  async listRequests(tunnelId: string): Promise<unknown> {
    return this.request(`/v1/requests?tunnelId=${encodeURIComponent(tunnelId)}`);
  }

  private async request(path: string, init?: RequestInit): Promise<any> {
    const headers = new Headers(init?.headers);
    headers.set("content-type", "application/json");
    if (this.token) {
      headers.set("authorization", `Bearer ${this.token}`);
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers
    });

    if (!response.ok) {
      throw new Error(`API error ${response.status}: ${await response.text()}`);
    }

    return response.json();
  }
}
