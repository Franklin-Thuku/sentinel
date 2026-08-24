"use client";

import Link from "next/link";

export function Navbar() {
  return (
    <nav className="border-b bg-white">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link href="/" className="text-xl font-bold">
          Sentinel
        </Link>

        <div className="flex items-center gap-6 text-sm">
          <Link href="/" className="hover:text-blue-600">
            Dashboard
          </Link>

          <Link href="/auth" className="hover:text-blue-600">
            Login
          </Link>
        </div>
      </div>
    </nav>
  );
}