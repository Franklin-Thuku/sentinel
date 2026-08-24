"use client";

import Link from "next/link";
import {
  Shield,
  ArrowRight,
  Radar,
  Lock,
  Activity,
  KeyRound,
  ShieldCheck,
} from "lucide-react";

const LOG_LINES = [
  { t: "04:12:01", ip: "185.220.101.4", msg: "inbound scan detected", status: "BLOCKED", tone: "red" },
  { t: "04:12:03", ip: "10.0.4.221", msg: "auth handshake complete", status: "SECURE", tone: "green" },
  { t: "04:12:06", ip: "192.168.1.9", msg: "credential rotation", status: "SECURE", tone: "green" },
  { t: "04:12:09", ip: "77.83.19.201", msg: "port sweep 22,443,3389", status: "BLOCKED", tone: "red" },
  { t: "04:12:12", ip: "10.0.4.188", msg: "anomaly heuristics run", status: "SCANNING", tone: "amber" },
  { t: "04:12:15", ip: "10.0.4.221", msg: "session token refreshed", status: "SECURE", tone: "green" },
];

const toneClasses: Record<string, string> = {
  red: "text-red-400 bg-red-500/10 border-red-500/30",
  green: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  amber: "text-amber-400 bg-amber-500/10 border-amber-500/30",
};

export default function GetStartedPage() {
  return (
    <div className="min-h-screen bg-[#05070c] text-white relative overflow-hidden">
      <style jsx global>{`
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes sweep {
          from { transform: translateY(-100%); }
          to { transform: translateY(420%); }
        }
        @keyframes ping-soft {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
        .log-line {
          animation: fadeInUp 0.5s ease-out both;
        }
        .scan-sweep {
          animation: sweep 4s linear infinite;
        }
        .live-dot {
          animation: ping-soft 1.6s ease-in-out infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .log-line, .scan-sweep, .live-dot { animation: none !important; }
        }
      `}</style>

      {/* Ambient background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[900px] h-[900px] rounded-full bg-blue-600/[0.06] blur-[120px]" />
        <div className="absolute top-1/3 right-0 w-[500px] h-[500px] rounded-full bg-purple-600/[0.05] blur-[100px]" />
      </div>

      {/* Nav */}
      <nav className="relative z-10 flex items-center justify-between max-w-6xl mx-auto px-6 py-6">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-blue-500" fill="currentColor" fillOpacity={0.15} />
          <span className="font-bold tracking-wide">SENTINEL</span>
        </div>
        <Link
          href="/auth/login"
          className="text-sm text-slate-400 hover:text-white transition-colors"
        >
          Sign in
        </Link>
      </nav>

      {/* Hero */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 pt-16 pb-28 grid md:grid-cols-2 gap-16 items-center">
        <div>
          <div className="inline-flex items-center gap-2 text-xs font-mono tracking-widest text-blue-400 border border-blue-500/30 bg-blue-500/5 rounded-full px-3 py-1 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 live-dot" />
            THREAT INTELLIGENCE PLATFORM
          </div>

          <h1 className="text-4xl md:text-5xl font-bold leading-tight mb-5">
            Your infrastructure,
            <br />
            watched around the clock.
          </h1>

          <p className="text-slate-400 text-lg mb-8 max-w-md">
            Sentinel monitors every connection to your systems in real time,
            blocking intrusions before they become incidents.
          </p>

          <div className="flex flex-wrap items-center gap-4 mb-10">
            <Link
              href="/auth/signup"
              className="group inline-flex items-center gap-2 bg-white text-slate-900 font-semibold px-6 py-3 rounded-lg hover:bg-slate-100 transition-colors"
            >
              Sign Up
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <Link
              href="/auth/login"
              className="text-slate-300 hover:text-white text-sm font-medium transition-colors"
            >
              I already have an account
            </Link>
          </div>

          <div className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-xs text-slate-500">
            <span>SOC 2 TYPE II</span>
            <span className="text-slate-700">·</span>
            <span>99.99% UPTIME</span>
            <span className="text-slate-700">·</span>
            <span>&lt;12ms DETECTION</span>
          </div>
        </div>

        {/* Signature: live console */}
        <div className="relative rounded-xl border border-slate-800 bg-[#0a0d14] overflow-hidden shadow-2xl shadow-black/40">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="scan-sweep absolute left-0 right-0 h-24 bg-gradient-to-b from-transparent via-blue-500/[0.04] to-transparent" />
          </div>

          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 bg-slate-900/40">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
            <span className="ml-3 font-mono text-xs text-slate-500">
              sentinel://monitor · live
            </span>
          </div>

          <div className="p-4 space-y-2 font-mono text-xs">
            {LOG_LINES.map((line, i) => (
              <div
                key={i}
                className="log-line flex items-center gap-3 text-slate-400"
                style={{ animationDelay: `${i * 0.35}s` }}
              >
                <span className="text-slate-600">{line.t}</span>
                <span className="text-slate-500 hidden sm:inline">{line.ip}</span>
                <span className="flex-1 truncate">{line.msg}</span>
                <span
                  className={`px-2 py-0.5 rounded border text-[10px] tracking-wide ${toneClasses[line.tone]}`}
                >
                  {line.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Steps */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-20 border-t border-slate-900">
        <h2 className="text-2xl font-bold mb-2">Three steps to lockdown</h2>
        <p className="text-slate-500 mb-12">
          Most teams are fully monitored within five minutes.
        </p>

        <div className="grid md:grid-cols-3 gap-8">
          {[
            {
              n: "01",
              title: "Create your workspace",
              desc: "Sign up with your corporate email and set a secure passkey.",
            },
            {
              n: "02",
              title: "Connect your assets",
              desc: "Point Sentinel at your servers, endpoints, or cloud accounts.",
            },
            {
              n: "03",
              title: "Monitor in real time",
              desc: "Watch traffic, get alerted on anomalies, and review the audit trail.",
            },
          ].map((step) => (
            <div key={step.n}>
              <span className="font-mono text-sm text-blue-500">{step.n}</span>
              <h3 className="text-lg font-semibold mt-2 mb-1">{step.title}</h3>
              <p className="text-slate-500 text-sm leading-relaxed">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Feature grid */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-20 border-t border-slate-900">
        <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-6">
          {[
            { icon: Radar, title: "Real-time detection", desc: "Threats surfaced in under 12ms." },
            { icon: Lock, title: "Encrypted channels", desc: "End-to-end on every connection." },
            { icon: Activity, title: "Full audit trail", desc: "Every event, permanently logged." },
            { icon: ShieldCheck, title: "Role-based access", desc: "Granular control, by design." },
          ].map(({ icon: Icon, title, desc }) => (
            <div
              key={title}
              className="rounded-lg border border-slate-800 bg-slate-950/40 p-5 hover:border-slate-700 transition-colors"
            >
              <Icon className="w-5 h-5 text-blue-500 mb-3" />
              <h3 className="font-medium mb-1">{title}</h3>
              <p className="text-sm text-slate-500">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Final CTA */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-24 border-t border-slate-900 text-center">
        <KeyRound className="w-8 h-8 text-blue-500 mx-auto mb-6" />
        <h2 className="text-3xl font-bold mb-3">
          Secure your first asset in under five minutes.
        </h2>
        <p className="text-slate-500 mb-8">No credit card required to get started.</p>
        <Link
          href="/auth/register"
          className="inline-flex items-center gap-2 bg-white text-slate-900 font-semibold px-6 py-3 rounded-lg hover:bg-slate-100 transition-colors"
        >
          Get started — it&apos;s free
          <ArrowRight className="w-4 h-4" />
        </Link>
      </section>

      <footer className="relative z-10 max-w-6xl mx-auto px-6 py-8 border-t border-slate-900 text-xs text-slate-600 font-mono">
        SENTINEL CORE · ACTIVE
      </footer>
    </div>
  );
}