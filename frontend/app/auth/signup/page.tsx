"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield,
  AlertCircle,
  Loader2,
  Lock,
  ShieldCheck,
  Check,
  X,
} from "lucide-react";
import apiClient from "@/lib/api-client";

function getPasswordStrength(password: string) {
  let score = 0;
  const checks = {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
  };
  score = Object.values(checks).filter(Boolean).length;
  const labels = ["Weak", "Fair", "Good", "Strong"];
  const colors = ["#ef4444", "#f59e0b", "#3b82f6", "#22c55e"];
  return {
    score,
    checks,
    label: password ? labels[Math.max(score - 1, 0)] : "",
    color: password ? colors[Math.max(score - 1, 0)] : "#334155",
  };
}

export default function SignupPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const strength = useMemo(() => getPasswordStrength(password), [password]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (strength.score < 3) {
      setError("Choose a stronger password before continuing.");
      return;
    }
    if (!agreed) {
      setError("You must accept the security policy to continue.");
      return;
    }

    setIsLoading(true);
    try {
      await apiClient.post("/auth/register", {
        full_name: fullName,
        email,
        password,
      });
      router.push("/auth/login");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Registration failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#05070c] text-white flex items-center justify-center px-4 py-16">
      <div className="w-full max-w-4xl">
        <div className="flex items-center justify-center gap-2 mb-8">
          <Shield className="w-7 h-7 text-blue-500" fill="currentColor" fillOpacity={0.15} />
          <span className="font-bold tracking-wide">SENTINEL</span>
        </div>

        <div className="border border-slate-800 rounded-xl bg-slate-950/40 grid md:grid-cols-2 overflow-hidden">
          {/* Left: security panel */}
          <div className="p-8 border-b md:border-b-0 md:border-r border-slate-800 flex flex-col justify-between">
            <div>
              <p className="text-white font-medium mb-1">Your data, protected</p>
              <p className="text-sm text-slate-500 mb-8">
                Every account is isolated and encrypted from the first keystroke.
              </p>

              <div className="space-y-4">
                <SecurityRow
                  icon={<Lock className="w-4 h-4" />}
                  label="AES-256 encryption at rest"
                />
                <SecurityRow
                  icon={<ShieldCheck className="w-4 h-4" />}
                  label="TLS 1.3 in transit"
                />
                <SecurityRow
                  icon={<Shield className="w-4 h-4" />}
                  label="Zero shared credentials"
                />
              </div>
            </div>

            <div className="mt-10 pt-6 border-t border-slate-800">
              <p className="font-mono text-[11px] text-slate-600 tracking-widest">
                COMPLIANCE
              </p>
              <div className="flex flex-wrap gap-2 mt-2">
                {["SOC 2 TYPE II", "ISO 27001", "GDPR"].map((badge) => (
                  <span
                    key={badge}
                    className="font-mono text-[10px] tracking-wide text-slate-400 border border-slate-800 rounded px-2 py-1"
                  >
                    {badge}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Right: form */}
          <div className="p-8">
            <h1 className="text-xl font-bold mb-1">Create your account</h1>
            <p className="text-sm text-slate-500 mb-6">
              Secure access starts here.
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              {error && (
                <div className="flex items-start gap-2 text-sm text-red-300 bg-red-950/50 border border-red-800 rounded-lg px-3 py-2">
                  <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="space-y-1.5">
                <label htmlFor="fullName" className="text-sm text-slate-300 font-medium">
                  Full name
                </label>
                <input
                  id="fullName"
                  type="text"
                  placeholder="Jane Doe"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  required
                  className="w-full h-11 rounded-lg bg-slate-900/60 border border-slate-700 px-3 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="email" className="text-sm text-slate-300 font-medium">
                  Corporate email address
                </label>
                <input
                  id="email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full h-11 rounded-lg bg-slate-900/60 border border-slate-700 px-3 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="password" className="text-sm text-slate-300 font-medium">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  placeholder="At least 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full h-11 rounded-lg bg-slate-900/60 border border-slate-700 px-3 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
                />

                {password && (
                  <div className="pt-1">
                    <div className="flex gap-1 mb-1.5">
                      {[0, 1, 2, 3].map((i) => (
                        <div
                          key={i}
                          className="h-1 flex-1 rounded-full transition-colors"
                          style={{
                            backgroundColor:
                              i < strength.score ? strength.color : "#1e293b",
                          }}
                        />
                      ))}
                    </div>
                    <div className="flex items-center justify-between">
                      <span
                        className="text-xs font-mono"
                        style={{ color: strength.color }}
                      >
                        {strength.label}
                      </span>
                      <div className="flex gap-3 text-[11px] text-slate-500">
                        <CheckItem ok={strength.checks.length} label="8+" />
                        <CheckItem ok={strength.checks.upper} label="A-Z" />
                        <CheckItem ok={strength.checks.number} label="0-9" />
                        <CheckItem ok={strength.checks.symbol} label="!@#" />
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-1.5">
                <label htmlFor="confirmPassword" className="text-sm text-slate-300 font-medium">
                  Confirm password
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  placeholder="Re-enter password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  className="w-full h-11 rounded-lg bg-slate-900/60 border border-slate-700 px-3 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
                />
              </div>

              <label className="flex items-start gap-2.5 text-sm text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={agreed}
                  onChange={(e) => setAgreed(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-900 accent-blue-600"
                />
                I agree to the security policy and terms of service.
              </label>

              <div className="rounded-lg p-[1px] bg-gradient-to-r from-blue-500 to-purple-600">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full h-11 rounded-[7px] bg-white hover:bg-slate-100 text-slate-900 font-semibold flex items-center justify-center transition-colors disabled:opacity-70"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating account...
                    </>
                  ) : (
                    "Create secure account"
                  )}
                </button>
              </div>
            </form>

            <p className="text-center text-sm text-slate-500 mt-6">
              Already have an account?{" "}
              <Link href="/auth/login" className="text-blue-400 hover:text-blue-300 font-medium">
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function SecurityRow({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="w-8 h-8 rounded-md bg-blue-500/10 text-blue-400 flex items-center justify-center shrink-0">
        {icon}
      </div>
      <span className="text-sm text-slate-300">{label}</span>
    </div>
  );
}

function CheckItem({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`flex items-center gap-0.5 font-mono ${ok ? "text-emerald-400" : "text-slate-600"}`}>
      {ok ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
      {label}
    </span>
  );
}