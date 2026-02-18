import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "TunnelForge Docs",
  description: "CLI and API documentation"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0, fontFamily: "ui-sans-serif, system-ui", background: "#f8fafc" }}>
        <main style={{ maxWidth: 980, margin: "0 auto", padding: 24 }}>{children}</main>
      </body>
    </html>
  );
}
