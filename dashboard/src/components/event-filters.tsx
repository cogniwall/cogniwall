"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

const STATUSES = ["all", "approved", "blocked", "error"];
const RULES = ["all", "pii_detection", "financial_limit", "prompt_injection", "tone_sentiment", "rate_limit"];

export function EventFilters() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const updateParam = useCallback(
    (key: string, value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value === "all" || value === "") {
        params.delete(key);
      } else {
        params.set(key, value);
      }
      params.set("page", "1");
      router.push(`/?${params.toString()}`);
    },
    [router, searchParams]
  );

  return (
    <div className="flex gap-3 mb-6">
      <select
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300"
        value={searchParams.get("status") || "all"}
        onChange={(e) => updateParam("status", e.target.value)}
      >
        {STATUSES.map((s) => (
          <option key={s} value={s}>
            {s === "all" ? "All Statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
          </option>
        ))}
      </select>
      <select
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300"
        value={searchParams.get("rule") || "all"}
        onChange={(e) => updateParam("rule", e.target.value)}
      >
        {RULES.map((r) => (
          <option key={r} value={r}>
            {r === "all" ? "All Rules" : r}
          </option>
        ))}
      </select>
      <input
        type="text"
        placeholder="Search by reason, rule, or details..."
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300 flex-1"
        defaultValue={searchParams.get("search") || ""}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            updateParam("search", (e.target as HTMLInputElement).value);
          }
        }}
      />
    </div>
  );
}
