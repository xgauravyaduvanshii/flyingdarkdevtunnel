import React, { PropsWithChildren } from "react";

export function Card({ children }: PropsWithChildren): JSX.Element {
  return (
    <div
      style={{
        borderRadius: "18px",
        border: "1px solid rgba(255,255,255,0.24)",
        padding: "20px",
        background: "linear-gradient(160deg, rgba(255,255,255,0.18), rgba(255,255,255,0.06))",
        backdropFilter: "blur(4px)",
        boxShadow: "0 14px 40px rgba(8, 12, 44, 0.18)"
      }}
    >
      {children}
    </div>
  );
}

export function StatusChip({ status }: { status: "active" | "stopped" | "error" }): JSX.Element {
  const palette = {
    active: { bg: "#ecfdf3", fg: "#067647" },
    stopped: { bg: "#fff8eb", fg: "#b54708" },
    error: { bg: "#fef3f2", fg: "#b42318" }
  }[status];

  return (
    <span
      style={{
        borderRadius: "999px",
        padding: "4px 10px",
        fontSize: "12px",
        fontWeight: 700,
        backgroundColor: palette.bg,
        color: palette.fg,
        textTransform: "uppercase",
        letterSpacing: "0.04em"
      }}
    >
      {status}
    </span>
  );
}

export const theme = {
  colors: {
    bg: "#071022",
    surface: "#102043",
    accent: "#f97316",
    accentAlt: "#06b6d4"
  }
};
