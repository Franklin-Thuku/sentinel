import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";  // ← This must be here
import Providers from "./providers";
import { Navbar } from "@/components/navigation";

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
      <body className={inter.className}>
        <Providers>
          <Navbar />
          <main className="pt-16 md:pt-[72px] min-h-screen">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}