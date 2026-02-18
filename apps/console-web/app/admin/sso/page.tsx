"use client";

import { FormEvent, useEffect, useState } from "react";
import { api } from "@/lib/api";

type SsoConfig = {
  id: string;
  provider: "saml" | "oidc";
  enabled: boolean;
  issuer: string | null;
  entrypoint: string | null;
  audience: string | null;
  certificate: string | null;
  metadata_json: Record<string, unknown> | null;
};

export default function AdminSsoPage() {
  const [provider, setProvider] = useState<"saml" | "oidc">("saml");
  const [enabled, setEnabled] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [entrypoint, setEntrypoint] = useState("");
  const [audience, setAudience] = useState("");
  const [certificate, setCertificate] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const data = await api<{ sso: SsoConfig | null }>("/v1/admin/sso");
      if (!data.sso) return;
      setProvider(data.sso.provider);
      setEnabled(data.sso.enabled);
      setIssuer(data.sso.issuer ?? "");
      setEntrypoint(data.sso.entrypoint ?? "");
      setAudience(data.sso.audience ?? "");
      setCertificate(data.sso.certificate ?? "");
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/v1/admin/sso", {
        method: "PUT",
        body: JSON.stringify({
          provider,
          enabled,
          issuer: issuer || undefined,
          entrypoint: entrypoint || undefined,
          audience: audience || undefined,
          certificate: certificate || undefined,
        }),
      });
      setMessage(`SSO config saved (${provider}, enabled=${enabled})`);
      await load();
    } catch (error) {
      setMessage(`Save failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h3>SSO configuration</h3>
      <p className="muted">{message}</p>
      <form className="grid" onSubmit={save}>
        <div>
          <label>Provider</label>
          <select value={provider} onChange={(event) => setProvider(event.target.value as "saml" | "oidc")}>
            <option value="saml">SAML</option>
            <option value="oidc">OIDC</option>
          </select>
        </div>
        <div>
          <label>Enabled</label>
          <select value={enabled ? "true" : "false"} onChange={(event) => setEnabled(event.target.value === "true")}>
            <option value="false">Disabled</option>
            <option value="true">Enabled</option>
          </select>
        </div>
        <div>
          <label>Issuer</label>
          <input value={issuer} onChange={(event) => setIssuer(event.target.value)} placeholder="https://idp.example.com" />
        </div>
        <div>
          <label>Entrypoint</label>
          <input value={entrypoint} onChange={(event) => setEntrypoint(event.target.value)} placeholder="https://idp.example.com/sso" />
        </div>
        <div>
          <label>Audience</label>
          <input value={audience} onChange={(event) => setAudience(event.target.value)} placeholder="urn:tunnelforge:sp" />
        </div>
        <div>
          <label>Certificate (optional)</label>
          <textarea rows={6} value={certificate} onChange={(event) => setCertificate(event.target.value)} />
        </div>
        <button disabled={busy} type="submit">
          Save SSO config
        </button>
      </form>
    </section>
  );
}
