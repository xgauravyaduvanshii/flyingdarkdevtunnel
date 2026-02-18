"use client";

import { useEffect, useMemo, useState } from "react";
import { api, getToken } from "@/lib/api";

type Provider = "stripe" | "razorpay" | "paypal";
type Status = "draft" | "open" | "paid" | "past_due" | "void" | "uncollectible" | "failed" | "refunded";

type InvoiceRow = {
  id: string;
  org_id: string;
  provider: Provider;
  provider_invoice_id: string | null;
  provider_subscription_id: string | null;
  provider_payment_id: string | null;
  status: Status;
  currency: string | null;
  subtotal_cents: string | null;
  tax_cents: string | null;
  total_cents: string | null;
  amount_paid_cents: string | null;
  due_at: string | null;
  paid_at: string | null;
  created_at: string;
};

type TaxRow = {
  id: string;
  invoice_id: string;
  provider: Provider;
  tax_type: string;
  jurisdiction: string | null;
  amount_cents: string;
  currency: string | null;
  created_at: string;
};

type Stats = {
  total: string;
  paid: string;
  failed: string;
  refunded: string;
  total_amount_cents: string;
  total_tax_cents: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

export default function AdminBillingInvoicesPage() {
  const [invoices, setInvoices] = useState<InvoiceRow[]>([]);
  const [taxRecords, setTaxRecords] = useState<TaxRow[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [provider, setProvider] = useState<Provider | "all">("all");
  const [status, setStatus] = useState<Status | "all">("all");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (provider !== "all") params.set("provider", provider);
    if (status !== "all") params.set("status", status);
    params.set("includeTax", "true");
    params.set("limit", "200");
    return params.toString();
  }, [provider, status]);

  async function load() {
    try {
      const data = await api<{ invoices: InvoiceRow[]; taxRecords: TaxRow[]; stats: Stats }>(
        `/v1/admin/billing-invoices?${query}`,
      );
      setInvoices(data.invoices);
      setTaxRecords(data.taxRecords);
      setStats(data.stats);
      setMessage("");
    } catch (error) {
      setMessage(`Load failed: ${String(error)}`);
    }
  }

  useEffect(() => {
    void load();
  }, [query]);

  async function exportCsv(dataset: "invoices" | "tax") {
    setBusy(true);
    try {
      const token = getToken();
      const params = new URLSearchParams(query);
      params.set("dataset", dataset);
      const response = await fetch(`${API_BASE}/v1/admin/billing-invoices/export?${params.toString()}`, {
        headers: token ? { authorization: `Bearer ${token}` } : undefined,
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = dataset === "tax" ? "billing-tax-records.csv" : "billing-invoices.csv";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
      setMessage(`Exported ${dataset} CSV`);
    } catch (error) {
      setMessage(`Export failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h3>Billing invoices</h3>
      <p className="muted">
        {stats
          ? `total=${stats.total}, paid=${stats.paid}, failed=${stats.failed}, refunded=${stats.refunded}, gross=${stats.total_amount_cents}, tax=${stats.total_tax_cents}`
          : "No stats"}
      </p>
      <p className="muted">{message}</p>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <select value={provider} onChange={(event) => setProvider(event.target.value as Provider | "all")}>
          <option value="all">All providers</option>
          <option value="stripe">Stripe</option>
          <option value="razorpay">Razorpay</option>
          <option value="paypal">PayPal</option>
        </select>
        <select value={status} onChange={(event) => setStatus(event.target.value as Status | "all")}>
          <option value="all">All statuses</option>
          <option value="draft">draft</option>
          <option value="open">open</option>
          <option value="paid">paid</option>
          <option value="past_due">past_due</option>
          <option value="void">void</option>
          <option value="uncollectible">uncollectible</option>
          <option value="failed">failed</option>
          <option value="refunded">refunded</option>
        </select>
        <button onClick={() => void load()} disabled={busy}>
          Refresh
        </button>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button className="button secondary" onClick={() => void exportCsv("invoices")} disabled={busy}>
          Export invoices CSV
        </button>
        <button onClick={() => void exportCsv("tax")} disabled={busy}>
          Export tax CSV
        </button>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Org</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Total</th>
            <th>Tax</th>
            <th>Paid</th>
            <th>Due</th>
            <th>Refs</th>
          </tr>
        </thead>
        <tbody>
          {invoices.map((invoice) => (
            <tr key={invoice.id}>
              <td>{new Date(invoice.created_at).toLocaleString()}</td>
              <td>{invoice.org_id}</td>
              <td>{invoice.provider}</td>
              <td>{invoice.status}</td>
              <td>{invoice.total_cents ? `${invoice.total_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
              <td>{invoice.tax_cents ? `${invoice.tax_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
              <td>{invoice.amount_paid_cents ? `${invoice.amount_paid_cents} ${invoice.currency ?? "USD"}` : "-"}</td>
              <td>{invoice.due_at ? new Date(invoice.due_at).toLocaleDateString() : "-"}</td>
              <td style={{ maxWidth: 320, whiteSpace: "normal", wordBreak: "break-all" }}>
                {invoice.provider_invoice_id ?? invoice.provider_payment_id ?? "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4 style={{ marginTop: 16 }}>Tax records ({taxRecords.length})</h4>
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Invoice</th>
            <th>Type</th>
            <th>Jurisdiction</th>
            <th>Amount</th>
          </tr>
        </thead>
        <tbody>
          {taxRecords.map((tax) => (
            <tr key={tax.id}>
              <td>{new Date(tax.created_at).toLocaleString()}</td>
              <td>{tax.invoice_id}</td>
              <td>{tax.tax_type}</td>
              <td>{tax.jurisdiction ?? "-"}</td>
              <td>{`${tax.amount_cents} ${tax.currency ?? "USD"}`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
