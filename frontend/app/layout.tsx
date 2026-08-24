
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Providers from "./providers";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Sentinel - AI-Powered Website Security Scanner",
  description: "Know what attackers can see. AI-powered website security scanning and continuous monitoring.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} bg-slate-950 text-white min-h-screen m-0 p-0`}>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}