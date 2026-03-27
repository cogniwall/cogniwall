"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "Events", icon: "📋" },
  { href: "/analytics", label: "Analytics", icon: "📊" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 min-h-screen bg-zinc-900 border-r border-zinc-800 flex flex-col">
      <div className="p-6 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" className="w-7 h-7 flex-shrink-0">
            <defs>
              <linearGradient id="cw-sb" x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#818CF8"/>
                <stop offset="100%" stopColor="#4338CA"/>
              </linearGradient>
            </defs>
            <path d="M16 2 L28 7 V17 C28 24.5 22.5 28 16 31 C9.5 28 4 24.5 4 17 V7 Z" fill="url(#cw-sb)"/>
            <line x1="6" y1="13" x2="26" y2="13" stroke="rgba(255,255,255,0.25)" strokeWidth="0.8"/>
            <line x1="6" y1="19" x2="26" y2="19" stroke="rgba(255,255,255,0.25)" strokeWidth="0.8"/>
            <circle cx="16" cy="16" r="2" fill="white" opacity="0.9"/>
          </svg>
          <div>
            <h1 className="text-xl font-bold text-white">CogniWall</h1>
            <p className="text-xs text-zinc-500">Audit Dashboard</p>
          </div>
        </div>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/" || pathname.startsWith("/events")
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? "bg-zinc-800 text-white"
                  : "text-zinc-400 hover:text-white hover:bg-zinc-800/50"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-zinc-800">
        <p className="text-xs text-zinc-600">v0.1.0</p>
      </div>
    </aside>
  );
}
