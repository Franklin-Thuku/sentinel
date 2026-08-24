"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Shield } from "lucide-react";

const navLinks = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/features" },
  { label: "Solutions", href: "/solutions" },
  { label: "Pricing", href: "/pricing" },
  { label: "Docs", href: "/docs" },
  { label: "About", href: "/about" },
  { label: "Contact", href: "/contact" },
];

export function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/10 bg-[#05070d]/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link href="/" className="flex items-center gap-2">
          <Shield className="h-6 w-6 fill-blue-500 text-blue-500" />
          <span className="text-lg font-bold tracking-wide text-white">
            SENTINEL
          </span>
        </Link>

        <div className="hidden items-center gap-8 text-sm font-medium text-slate-300 md:flex">
          {navLinks.map((link, i) => (
            <Link
              key={link.href}
              href={link.href}
              className={cn(
                "relative pb-1 transition-colors hover:text-white",
                i === 0 &&
                  "text-white after:absolute after:-bottom-[21px] after:left-0 after:h-[2px] after:w-full after:bg-blue-500"
              )}
            >
              {link.label}
            </Link>
          ))}
        </div>


        <div className="flex items-center gap-3">
          <Link
            href="/auth/login"
            className="hidden text-sm font-medium text-slate-200 hover:text-white sm:block"
          >
            Log in
          </Link>
         <Button
                render={<Link href="/auth/register" />}
                size="sm"
                className="bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:opacity-90"
            >
                Get Started
            </Button>
        </div>
      </div>
    </nav>
  );
}