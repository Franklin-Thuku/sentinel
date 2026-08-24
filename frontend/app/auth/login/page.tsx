'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

// Sentinel Shield Logo filled with solid blue
function SentinelLogo({ className = "w-7 h-7" }: { className?: string }) {
  return (
    <svg 
      className={className} 
      viewBox="0 0 24 24" 
      fill="#2563eb" 
      stroke="#2563eb" 
      strokeWidth="1" 
      strokeLinecap="round" 
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000/api'}/auth/login`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Authentication protocol failed.');
      }

      if (data.token) {
        localStorage.setItem('sentinel_token', data.token);
      }

      router.push('/dashboard');
    } catch (err: any) {
      // Fallback for demo/testing until backend route is live
      if (process.env.NODE_ENV === 'development') {
        console.warn('Backend unavailable, navigating to dashboard for UI testing.');
        router.push('/dashboard');
        return;
      }
      setError(err.message || 'Unable to reach authentication gateway.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#05070B] text-slate-100 flex flex-col justify-center items-center px-4 relative overflow-hidden select-none">
      
      {/* Background radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] bg-blue-600/10 blur-[150px] pointer-events-none rounded-full" />

      {/* Sentinel Filled Blue Brand Header */}
      <div className="flex items-center gap-3 mb-6 z-10">
        <SentinelLogo className="w-8 h-8" />
        <span className="text-2xl font-black tracking-widest text-white">SENTINEL</span>
      </div>

      <div className="text-center mb-8 z-10">
        <h1 className="text-3xl font-extrabold text-white tracking-tight mb-2">
          Secure Authentication Protocol
        </h1>
        <p className="text-slate-400 text-sm font-medium">
          Initiating your workspace handshake.
        </p>
      </div>

      {/* Main Glass Card */}
      <div className="w-full max-w-4xl bg-[#090D16]/90 border border-slate-800/90 rounded-2xl p-6 md:p-8 backdrop-blur-2xl shadow-2xl z-10 grid grid-cols-1 md:grid-cols-2 gap-8 items-stretch">
        
        {/* Left Column: Detailed Realistic Cyber Security Visualization */}
        <div className="hidden md:flex flex-col justify-between p-6 bg-[#04060A] border border-slate-800/80 rounded-xl relative overflow-hidden">
          
          {/* Header Status */}
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 z-10">
            <span className="text-xs font-semibold tracking-wider text-slate-300 uppercase">
              Encrypted Channel
            </span>
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800/50 px-2 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              256-BIT TLS 1.3
            </span>
          </div>

          {/* Realistic Neural Cyber Graphic */}
          <div className="relative my-6 flex items-center justify-center h-48 w-full z-10">
            
            {/* Background Tech Grid Lines */}
            <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:12px_12px] opacity-40" />

            {/* Glowing Rings */}
            <div className="absolute w-40 h-40 rounded-full border border-blue-500/20 animate-[spin_12s_linear_infinite]" />
            <div className="absolute w-32 h-32 rounded-full border border-dashed border-cyan-500/30 animate-[spin_8s_linear_infinite_reverse]" />
            
            {/* Detailed Network Mesh SVG */}
            <svg className="w-48 h-48 relative z-10" viewBox="0 0 200 200" fill="none">
              {/* Connecting Edges */}
              <line x1="100" y1="100" x2="50" y2="60" stroke="#3b82f6" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.6" />
              <line x1="100" y1="100" x2="150" y2="60" stroke="#3b82f6" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.6" />
              <line x1="100" y1="100" x2="60" y2="140" stroke="#6366f1" strokeWidth="1.5" opacity="0.8" />
              <line x1="100" y1="100" x2="140" y2="140" stroke="#6366f1" strokeWidth="1.5" opacity="0.8" />
              <line x1="50" y1="60" x2="150" y2="60" stroke="#1e293b" strokeWidth="1" />
              <line x1="60" y1="140" x2="140" y2="140" stroke="#1e293b" strokeWidth="1" />

              {/* Peripheral Nodes */}
              <circle cx="50" cy="60" r="6" fill="#0f172a" stroke="#3b82f6" strokeWidth="2" />
              <circle cx="150" cy="60" r="6" fill="#0f172a" stroke="#3b82f6" strokeWidth="2" />
              <circle cx="60" cy="140" r="7" fill="#0f172a" stroke="#818cf8" strokeWidth="2" />
              <circle cx="140" cy="140" r="7" fill="#0f172a" stroke="#818cf8" strokeWidth="2" />
              <circle cx="165" cy="100" r="4" fill="#06b6d4" />

              {/* Pulse Signal animations */}
              <circle cx="75" cy="80" r="2" fill="#60a5fa" className="animate-ping" />
              <circle cx="120" cy="120" r="2" fill="#a78bfa" className="animate-ping" />

              {/* Central Core Firewall Node */}
              <circle cx="100" cy="100" r="16" fill="#1e1b4b" stroke="#6366f1" strokeWidth="2" />
              <circle cx="100" cy="100" r="8" fill="#3b82f6" className="animate-pulse" />
            </svg>
          </div>

          {/* Footer Telemetry Data */}
          <div className="space-y-1.5 border-t border-slate-800/80 pt-3 z-10">
            <div className="flex justify-between text-[11px] font-mono text-slate-400">
              <span>FIREWALL STATE:</span>
              <span className="text-blue-400 font-semibold">ACTIVE</span>
            </div>
            <div className="flex justify-between text-[11px] font-mono text-slate-400">
              <span>SECURITY SCOPE:</span>
              <span className="text-slate-300">Sentinel Core v2.4</span>
            </div>
          </div>

        </div>

        {/* Right Column: Form Inputs */}
        <div className="flex flex-col justify-center">
          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 font-medium">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-2">
                Corporate Email Address
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Corporate Email Address"
                className="w-full bg-[#05070C] border border-slate-800 rounded-lg px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-2">
                Secure Passkey
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Secure Passkey"
                className="w-full bg-[#05070C] border border-slate-800 rounded-lg px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
              />
            </div>

            {/* Glowing Accent Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full relative group p-[2px] rounded-lg font-bold text-sm overflow-hidden transition-all focus:outline-none active:scale-[0.99]"
              >
                {/* Outer Glow gradient matching screenshot */}
                <span className="absolute inset-0 bg-gradient-to-r from-blue-600 via-indigo-500 to-purple-600 rounded-lg group-hover:opacity-100 opacity-90 transition-opacity" />
                
                {/* Button Inner */}
                <span className="relative block w-full bg-white text-slate-950 hover:bg-slate-100 transition-colors py-3.5 rounded-[6px] text-center font-extrabold tracking-wide">
                  {loading ? 'Authenticating...' : 'Sign In to Dashboard'}
                </span>
              </button>
            </div>
          </form>
        </div>

      </div>
    </div>
  );
}