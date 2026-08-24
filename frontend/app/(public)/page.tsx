import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Lock, ArrowRight } from "lucide-react";
import { HeroDashboardPreview } from "@/components/hero-dashboard-preview";

const trustLogos = ["Acme Corp", "CloudNest", "DevStack", "InnovaLabs", "NextGen", "SecureWorks"];

const quickFeatures = [
  { icon: Shield, title: "Real-time Threat Detection", desc: "AI-driven monitoring 24/7" },
  { icon: Zap, title: "Instant Alerts", desc: "Know before it's a breach" },
  { icon: Lock, title: "Secure by Design", desc: "Enterprise-grade protection" },
];

export default function Home() {
  return (
    <div className="bg-[#05070d]">
      {/* Hero */}
      <section className="mx-auto max-w-7xl px-6 pb-24 pt-40">
        <div className="grid items-center gap-16 lg:grid-cols-2">
          <div>
            <Badge className="mb-6 border-blue-500/30 bg-blue-500/10 text-blue-400">
              AI-POWERED SECURITY
            </Badge>

            <h1 className="text-5xl font-bold leading-[1.1] tracking-tight text-white sm:text-6xl">
              Secure Today.
              <br />
              Confident{" "}
              <span className="bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
                Tomorrow.
              </span>
            </h1>

            <p className="mt-6 max-w-md text-lg text-slate-400">
              Sentinel monitors, detects, and responds to threats in real
              time so you can focus on building, not worrying.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <Button
                render={<Link href="/auth/register" className="flex items-center gap-2" />}
                size="lg"
                className="bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:opacity-90"
              >
                Get Started for Free <ArrowRight className="h-4 w-4" />
              </Button>
              <Button
                render={<Link href="/contact" />}
                size="lg"
                variant="outline"
                className="border-white/20 text-black hover:bg-black hover:text-white"
              >
                Request a Demo
              </Button>
            </div>

            <div className="mt-12 flex flex-wrap gap-8">
              {quickFeatures.map((f) => (
                <div key={f.title} className="flex items-start gap-3">
                  <div className="rounded-lg bg-blue-500/10 p-2">
                    <f.icon className="h-4 w-4 text-blue-400" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-white">{f.title}</p>
                    <p className="text-xs text-slate-500">{f.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <HeroDashboardPreview />
        </div>
      </section>

      {/* Trust bar */}
      <section className="border-t border-white/10 py-16">
        <div className="mx-auto max-w-7xl px-6">
          <p className="mb-8 text-center text-xs font-medium tracking-widest text-slate-500">
            TRUSTED BY DEVELOPERS AND SECURITY TEAMS WORLDWIDE
          </p>
          <div className="flex flex-wrap items-center justify-center gap-x-12 gap-y-4 text-slate-400">
            {trustLogos.map((name) => (
              <span key={name} className="text-lg font-semibold opacity-70">
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}