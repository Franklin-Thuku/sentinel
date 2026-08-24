import { Shield, Bell, User } from "lucide-react";

const sidebarItems = [
  { label: "Overview", active: true },
  { label: "Threats" },
  { label: "Alerts" },
  { label: "Scans" },
  { label: "Reports" },
  { label: "Settings" },
];

const stats = [
  { label: "Total Scans", value: "1,024", delta: "12.5%" },
  { label: "Threats Detected", value: "32", delta: "18.3%" },
  { label: "Blocked Attacks", value: "128", delta: "24.6%" },
  { label: "Assets Monitored", value: "56", delta: "8.1%" },
];

const alerts = [
  { severity: "High", alert: "Brute force attack detected", source: "192.168.1.45", time: "2 min ago" },
  { severity: "Medium", alert: "Suspicious login attempt", source: "203.0.113.10", time: "15 min ago" },
  { severity: "Low", alert: "Unusual traffic pattern", source: "198.51.100.7", time: "1 hr ago" },
  { severity: "Medium", alert: "Possible phishing domain", source: "mail.example.com", time: "2 hr ago" },
];

const severityColor: Record<string, string> = {
  High: "text-red-400",
  Medium: "text-amber-400",
  Low: "text-emerald-400",
};

export function HeroDashboardPreview() {
  return (
    <div className="flex overflow-hidden rounded-2xl border border-white/10 bg-[#0b0f1a] shadow-2xl shadow-blue-900/20">
      {/* Sidebar */}
      <div className="hidden w-40 shrink-0 border-r border-white/10 bg-[#080b13] p-4 sm:block">
        <div className="mb-6 flex items-center gap-2">
          <Shield className="h-4 w-4 fill-blue-500 text-blue-500" />
          <span className="text-xs font-bold tracking-wide text-white">
            SENTINEL
          </span>
        </div>
        <div className="flex flex-col gap-1 text-xs text-slate-400">
          {sidebarItems.map((item) => (
            <div
              key={item.label}
              className={cn(
                "rounded-md px-3 py-2",
                item.active
                  ? "bg-blue-600/20 text-blue-400"
                  : "hover:bg-white/5"
              )}
            >
              {item.label}
            </div>
          ))}
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-base font-semibold text-white">Overview</h3>
          <div className="flex items-center gap-2 text-slate-400">
            <Bell className="h-4 w-4" />
            <User className="h-4 w-4" />
          </div>
        </div>

        {/* Stat cards */}
        <div className="mb-4 grid grid-cols-2 gap-3">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className="rounded-lg border border-white/10 bg-white/[0.03] p-3"
            >
              <p className="text-[11px] text-slate-400">{stat.label}</p>
              <p className="text-xl font-bold text-white">{stat.value}</p>
              <p className="text-[11px] text-emerald-400">↑ {stat.delta}</p>
            </div>
          ))}
        </div>

        {/* Recent alerts table */}
        <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
          <p className="mb-2 text-[11px] font-medium text-slate-300">
            Recent Alerts
          </p>
          <div className="flex flex-col gap-2">
            {alerts.map((a, i) => (
              <div
                key={i}
                className="flex items-center justify-between text-[11px]"
              >
                <span className={cn("w-12 font-medium", severityColor[a.severity])}>
                  {a.severity}
                </span>
                <span className="flex-1 truncate px-2 text-slate-300">
                  {a.alert}
                </span>
                <span className="text-slate-500">{a.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}