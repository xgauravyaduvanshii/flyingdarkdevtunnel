import type { Metadata } from "next";
import { Space_Grotesk, Sora } from "next/font/google";
import "./globals.css";
import { TopNav } from "@/components/nav";

const spaceGrotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-space-grotesk" });
const sora = Sora({ subsets: ["latin"], variable: "--font-sora" });

export const metadata: Metadata = {
  title: "TunnelForge Console",
  description: "Manage HTTP/HTTPS/TCP tunnels"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${sora.variable}`}>
      <body>
        <TopNav />
        <main>{children}</main>
      </body>
    </html>
  );
}
