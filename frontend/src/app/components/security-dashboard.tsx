"use client";

/**
 * Security Dashboard (SOC mode) — full-screen real-time operations view.
 *
 * Data sources:
 * - Live intercepts over SSE (`GET /api/v1/events/stream`, fetch-based so
 *   Authorization headers work; automatic reconnection with backoff).
 * - Recent history on mount (`GET /api/v1/logs?limit=12`).
 * - Aggregate traffic counters (`GET /metrics`, 10s polling).
 *
 * The overlay is keyboard accessible: ESC exits. Exiting aborts the stream.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Timer,
  X,
  Zap,
} from "lucide-react";

type LiveEvent = {
  key: string;
  requestId: string;
  threatType: string;
  category: string;
  riskScore: number;
  layer: string;
  reason: string;
  ts: number;
};

type MetricsSummary = {
  totalRequests: number;
  blocked: number;
  latencySum: number;
  latencyCount: number;
};

type SecurityDashboardProps = {
  apiBase: string;
  buildAuthHeaders: () => Record<string, string>;
  onExit: () => void;
};

const MAX_EVENTS = 24;
const METRICS_POLL_MS = 10_000;

function riskLevel(score: number): "high" | "medium" | "low" {
  if (score >= 0.9) return "high";
  if (score >= 0.75) return "medium";
  return "low";
}

function formatClock(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function parseMetricsSummary(body: string): MetricsSummary {
  let totalRequests = 0;
  let blocked = 0;
  let latencySum = 0;
  let latencyCount = 0;

  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const spaceIndex = line.lastIndexOf(" ");
    if (spaceIndex === -1) continue;
    const value = Number.parseFloat(line.slice(spaceIndex + 1));
    if (!Number.isFinite(value)) continue;

    const series = line.slice(0, spaceIndex);
    const name = series.split("{")[0];
    if (name === "shadow_agent_http_requests_total") {
      totalRequests += value;
      if (series.includes('status="403"')) blocked += value;
    } else if (name === "shadow_agent_http_request_duration_seconds_sum") {
      latencySum += value;
    } else if (name === "shadow_agent_http_request_duration_seconds_count") {
      latencyCount += value;
    }
  }
  return { totalRequests, blocked, latencySum, latencyCount };
}

export default function SecurityDashboard({ apiBase, buildAuthHeaders, onExit }: SecurityDashboardProps) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connection, setConnection] = useState<"connecting" | "live" | "reconnecting">("connecting");
  const [clock, setClock] = useState(() => formatClock(new Date()));
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const eventsRef = useRef<LiveEvent[]>([]);

  const pushEvent = useCallback((event: LiveEvent) => {
    // The same intercept arrives via /logs seeding AND SSE history replay;
    // deduplicate on requestId+threatType, keeping the newest copy.
    const dedupeKey = `${event.requestId}:${event.threatType}`;
    const withoutDuplicate = eventsRef.current.filter(
      (existing) => `${existing.requestId}:${existing.threatType}` !== dedupeKey
    );
    const next = [event, ...withoutDuplicate].slice(0, MAX_EVENTS);
    eventsRef.current = next;
    setEvents(next);
  }, []);

  // Seed with recent history so the wall is never empty on mount.
  useEffect(() => {
    let disposed = false;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch(`${apiBase.replace(/\/$/, "")}/api/v1/logs?limit=12`, {
            headers: buildAuthHeaders(),
            cache: "no-store",
          });
          if (!response.ok) return;
          const data = (await response.json().catch(() => ({}))) as {
            items?: Array<{
              request_id?: string;
              threat_type?: string;
              timestamp?: string;
              details?: Record<string, unknown>;
            }>;
          };
          if (disposed) return;
          const seeded: LiveEvent[] = (data.items ?? []).map((item, index) => ({
            key: `seed-${item.request_id ?? index}-${index}`,
            requestId: item.request_id ?? "unknown",
            threatType: item.threat_type ?? "Unknown",
            category: typeof item.details?.category === "string" ? item.details.category : "",
            riskScore: typeof item.details?.risk_score === "number" ? item.details.risk_score : 0,
            layer: typeof item.details?.layer === "string" ? item.details.layer : "",
            reason: typeof item.details?.reason === "string" ? item.details.reason : "",
            ts: item.timestamp ? new Date(item.timestamp).getTime() : Date.now(),
          }));
          if (seeded.length > 0) {
            const merged = [...seeded, ...eventsRef.current].slice(0, MAX_EVENTS);
            eventsRef.current = merged;
            setEvents(merged);
          }
        } catch {
          // History is best-effort; the live stream is the primary source.
        }
      })();
    }, 0);
    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [apiBase, buildAuthHeaders]);

  // Live SSE stream with reconnect + backoff.
  useEffect(() => {
    let disposed = false;
    let retryDelay = 2000;
    const controller = new AbortController();

    const handleFrame = (frame: string) => {
      const dataLine = frame
        .split("\n")
        .find((line) => line.startsWith("data:"));
      if (!dataLine) return;
      try {
        const payload = JSON.parse(dataLine.slice(5).trim()) as {
          type?: string;
          request_id?: string;
          threat_type?: string;
          category?: string;
          risk_score?: number;
          layer?: string;
          reason?: string;
          ts?: number;
        };
        if (payload.type !== "intercept") return;
        pushEvent({
          key: `${payload.request_id ?? "evt"}-${payload.ts ?? Date.now()}`,
          requestId: payload.request_id ?? "unknown",
          threatType: payload.threat_type ?? "Unknown",
          category: payload.category ?? "",
          riskScore: typeof payload.risk_score === "number" ? payload.risk_score : 0,
          layer: payload.layer ?? "",
          reason: payload.reason ?? "",
          ts: (payload.ts ?? Date.now()) * 1000,
        });
      } catch {
        // Malformed frame: skip.
      }
    };

    const connect = async () => {
      while (!disposed) {
        try {
          setConnection("connecting");
          const response = await fetch(`${apiBase.replace(/\/$/, "")}/api/v1/events/stream`, {
            headers: buildAuthHeaders(),
            signal: controller.signal,
            cache: "no-store",
          });
          if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);

          setConnection("live");
          retryDelay = 2000;
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const frames = buffer.split("\n\n");
            buffer = frames.pop() ?? "";
            for (const frame of frames) handleFrame(frame);
          }
        } catch {
          // Fall through to retry below.
        }
        if (disposed || controller.signal.aborted) return;
        setConnection("reconnecting");
        await new Promise<void>((resolve) => {
          window.setTimeout(resolve, retryDelay);
        });
        retryDelay = Math.min(retryDelay * 2, 30_000);
      }
    };

    void connect();
    return () => {
      disposed = true;
      controller.abort();
    };
  }, [apiBase, buildAuthHeaders, pushEvent]);

  // Aggregate traffic counters.
  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const response = await fetch(`${apiBase.replace(/\/$/, "")}/metrics`, {
          headers: buildAuthHeaders(),
          cache: "no-store",
        });
        if (!response.ok) return;
        if (disposed) return;
        setMetrics(parseMetricsSummary(await response.text()));
      } catch {
        // Metrics are supplemental.
      }
    };
    const timer = window.setTimeout(() => void load(), 0);
    const interval = window.setInterval(() => void load(), METRICS_POLL_MS);
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, [apiBase, buildAuthHeaders]);

  // Wall clock.
  useEffect(() => {
    const interval = window.setInterval(() => {
      setClock(formatClock(new Date()));
    }, 1000);
    return () => window.clearInterval(interval);
  }, []);

  // ESC exits the dashboard.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onExit();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onExit]);

  const threatDistribution = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events) {
      counts.set(event.threatType, (counts.get(event.threatType) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [events]);

  const riskDistribution = useMemo(() => {
    let high = 0;
    let medium = 0;
    let low = 0;
    for (const event of events) {
      const level = riskLevel(event.riskScore);
      if (level === "high") high += 1;
      else if (level === "medium") medium += 1;
      else low += 1;
    }
    return { high, medium, low };
  }, [events]);

  const maxThreatCount = threatDistribution.length > 0 ? threatDistribution[0][1] : 1;
  const avgLatencyMs =
    metrics && metrics.latencyCount > 0 ? (metrics.latencySum / metrics.latencyCount) * 1000 : null;

  const connectionBadge =
    connection === "live"
      ? { label: "实时连接", dotClass: "bg-emerald-300", textClass: "text-emerald-200", borderClass: "border-emerald-300/30 bg-emerald-400/10" }
      : connection === "reconnecting"
        ? { label: "重连中", dotClass: "bg-amber-300 animate-pulse", textClass: "text-amber-200", borderClass: "border-amber-300/30 bg-amber-400/10" }
        : { label: "连接中", dotClass: "bg-sky-300 animate-pulse", textClass: "text-sky-200", borderClass: "border-sky-300/30 bg-sky-400/10" };

  return (
    <div
      className="fixed inset-0 z-[70] overflow-hidden bg-[#030712] text-zinc-200"
      role="dialog"
      aria-modal="true"
      aria-label="安全大屏"
    >
      {/* Grid backdrop */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(45,212,191,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(45,212,191,0.05) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }}
        aria-hidden
      />
      {/* Ambient glows */}
      <div className="pointer-events-none absolute -left-40 -top-40 h-[480px] w-[480px] rounded-full bg-teal-500/[0.07] blur-3xl" aria-hidden />
      <div className="pointer-events-none absolute -bottom-40 -right-40 h-[480px] w-[480px] rounded-full bg-rose-500/[0.06] blur-3xl" aria-hidden />
      {/* Scan line */}
      <motion.div
        className="pointer-events-none absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-teal-300/30 to-transparent"
        animate={{ top: ["0%", "100%", "0%"] }}
        transition={{ duration: 18, repeat: Infinity, ease: "linear" }}
        aria-hidden
      />

      <div className="relative flex h-full flex-col">
        {/* Header */}
        <header className="flex items-center justify-between gap-4 border-b border-teal-300/10 px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-md border border-teal-300/30 bg-teal-400/10 shadow-[0_0_28px_rgba(45,212,191,0.25)]">
              <ShieldCheck className="h-6 w-6 text-teal-200" aria-hidden />
            </span>
            <div>
              <h1 className="text-lg font-semibold tracking-wide text-white sm:text-xl">
                SHADOW AGENT <span className="text-teal-200">安全作战大屏</span>
              </h1>
              <p className="text-xs text-zinc-500">Runtime Security Operations Center</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${connectionBadge.borderClass} ${connectionBadge.textClass}`}>
              <span className={`h-2 w-2 rounded-full ${connectionBadge.dotClass}`} aria-hidden />
              <Radio className="h-3.5 w-3.5" aria-hidden />
              {connectionBadge.label}
            </span>
            <span className="hidden font-mono text-2xl font-semibold tabular-nums text-teal-100 sm:block">{clock}</span>
            <button
              type="button"
              onClick={onExit}
              className="flex h-9 items-center gap-2 rounded-md border border-white/10 bg-white/[0.04] px-3 text-sm text-zinc-300 transition hover:border-rose-300/40 hover:bg-rose-400/10 hover:text-rose-100 focus:outline-none focus:ring-2 focus:ring-teal-300/60"
            >
              <X className="h-4 w-4" aria-hidden />
              退出大屏 <kbd className="hidden rounded bg-white/10 px-1.5 py-0.5 text-[10px] text-zinc-400 sm:inline">ESC</kbd>
            </button>
          </div>
        </header>

        {/* Body */}
        <div className="grid min-h-0 flex-1 gap-4 p-4 xl:grid-cols-[minmax(280px,1fr)_minmax(0,1.9fr)_minmax(280px,1fr)] xl:p-6">
          {/* Left column: KPIs + threat distribution */}
          <div className="flex min-h-0 flex-col gap-4 overflow-y-auto">
            <section className="grid grid-cols-2 gap-3">
              <div className="relative overflow-hidden rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
                <div className="text-xs text-zinc-500">实时拦截</div>
                <motion.div key={`events-${events.length}`} initial={{ opacity: 0.4, y: 5 }} animate={{ opacity: 1, y: 0 }} className="mt-1 font-mono text-3xl font-bold tabular-nums text-rose-300">
                  {events.length}
                </motion.div>
                <ShieldAlert className="absolute right-3 top-3 h-4 w-4 text-rose-300/60" aria-hidden />
              </div>
              <div className="relative overflow-hidden rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
                <div className="text-xs text-zinc-500">网关请求</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-teal-200">
                  {metrics ? metrics.totalRequests.toLocaleString("zh-CN") : "—"}
                </div>
                <Activity className="absolute right-3 top-3 h-4 w-4 text-teal-200/60" aria-hidden />
              </div>
              <div className="relative overflow-hidden rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
                <div className="text-xs text-zinc-500">累计阻断 403</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-amber-200">
                  {metrics ? metrics.blocked.toLocaleString("zh-CN") : "—"}
                </div>
                <Zap className="absolute right-3 top-3 h-4 w-4 text-amber-200/60" aria-hidden />
              </div>
              <div className="relative overflow-hidden rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
                <div className="text-xs text-zinc-500">平均延迟</div>
                <div className="mt-1 font-mono text-3xl font-bold tabular-nums text-sky-200">
                  {avgLatencyMs !== null ? `${avgLatencyMs.toFixed(0)}ms` : "—"}
                </div>
                <Timer className="absolute right-3 top-3 h-4 w-4 text-sky-200/60" aria-hidden />
              </div>
            </section>

            <section className="rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
              <h2 className="text-sm font-semibold text-zinc-100">威胁类型分布</h2>
              <div className="mt-4 space-y-3">
                {threatDistribution.length === 0 && (
                  <p className="py-6 text-center text-xs text-zinc-600">暂无拦截记录</p>
                )}
                {threatDistribution.map(([threat, count]) => (
                  <div key={threat} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="truncate text-zinc-300">{threat}</span>
                      <span className="ml-2 font-mono tabular-nums text-zinc-400">{count}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                      <motion.div
                        className="h-full rounded-full bg-gradient-to-r from-teal-400/80 to-rose-400/80"
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.max(4, (count / maxThreatCount) * 100)}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
              <h2 className="text-sm font-semibold text-zinc-100">风险等级</h2>
              <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                {[
                  { label: "高危", value: riskDistribution.high, className: "border-rose-300/25 bg-rose-400/10 text-rose-200" },
                  { label: "中危", value: riskDistribution.medium, className: "border-amber-300/25 bg-amber-400/10 text-amber-200" },
                  { label: "低危", value: riskDistribution.low, className: "border-teal-300/25 bg-teal-400/10 text-teal-200" },
                ].map((item) => (
                  <div key={item.label} className={`rounded-md border px-2 py-3 ${item.className}`}>
                    <div className="font-mono text-2xl font-bold tabular-nums">{item.value}</div>
                    <div className="mt-1 text-xs opacity-80">{item.label}</div>
                  </div>
                ))}
              </div>
            </section>
          </div>

          {/* Center column: live event stream */}
          <section className="flex min-h-0 flex-col rounded-lg border border-teal-300/15 bg-white/[0.02]">
            <div className="flex items-center justify-between border-b border-teal-300/10 px-4 py-3">
              <h2 className="text-sm font-semibold text-zinc-100">实时拦截事件流</h2>
              <span className="inline-flex items-center gap-1.5 text-xs text-zinc-500">
                <span className={`h-1.5 w-1.5 rounded-full ${connection === "live" ? "bg-emerald-300" : "bg-zinc-600"}`} aria-hidden />
                {connection === "live" ? "SSE 推送中" : "等待推送"}
              </span>
            </div>
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
              <AnimatePresence initial={false}>
                {events.length === 0 && (
                  <div className="flex h-full items-center justify-center px-6 text-center">
                    <div>
                      <ShieldCheck className="mx-auto h-10 w-10 text-teal-300/30" aria-hidden />
                      <p className="mt-3 text-sm text-zinc-500">暂无拦截事件</p>
                      <p className="mt-1 text-xs text-zinc-600">
                        在「网关测试」发送恶意请求，或等待上游触发策略，事件将实时推送到此处
                      </p>
                    </div>
                  </div>
                )}
                {events.map((event) => {
                  const level = riskLevel(event.riskScore);
                  const levelStyle =
                    level === "high"
                      ? "border-rose-400/30 bg-rose-500/[0.08]"
                      : level === "medium"
                        ? "border-amber-400/25 bg-amber-500/[0.06]"
                        : "border-teal-400/20 bg-teal-500/[0.05]";
                  return (
                    <motion.article
                      key={event.key}
                      layout
                      initial={{ opacity: 0, x: -24, scale: 0.98 }}
                      animate={{ opacity: 1, x: 0, scale: 1 }}
                      exit={{ opacity: 0, x: 24 }}
                      transition={{ type: "spring", stiffness: 320, damping: 30 }}
                      className={`rounded-md border px-3.5 py-3 ${levelStyle}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <AlertTriangle
                            className={`h-4 w-4 shrink-0 ${level === "high" ? "text-rose-300" : level === "medium" ? "text-amber-300" : "text-teal-300"}`}
                            aria-hidden
                          />
                          <span className="truncate text-sm font-semibold text-white">{event.threatType}</span>
                          <span className="shrink-0 rounded border border-white/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-zinc-400">
                            {level}
                          </span>
                        </div>
                        <span className="shrink-0 font-mono text-xs tabular-nums text-zinc-500">
                          {new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}
                        </span>
                      </div>
                      <div className="mt-1.5 flex items-center gap-2 text-[11px] text-zinc-500">
                        <span className="truncate font-mono">req {event.requestId}</span>
                        <span className="shrink-0 rounded bg-white/[0.06] px-1.5 py-0.5 font-mono">{(event.riskScore * 100).toFixed(0)}%</span>
                        {event.layer && <span className="shrink-0 truncate">{event.layer}</span>}
                      </div>
                      {event.reason && (
                        <p className="mt-1.5 line-clamp-2 text-xs leading-5 text-zinc-400">{event.reason}</p>
                      )}
                    </motion.article>
                  );
                })}
              </AnimatePresence>
            </div>
          </section>

          {/* Right column: recent request ids + stream info */}
          <div className="flex min-h-0 flex-col gap-4 overflow-y-auto">
            <section className="rounded-lg border border-teal-300/15 bg-white/[0.03] p-4">
              <h2 className="text-sm font-semibold text-zinc-100">最近拦截对象</h2>
              <div className="mt-3 space-y-1.5">
                {events.slice(0, 10).map((event) => (
                  <div key={`rid-${event.key}`} className="flex items-center justify-between gap-2 rounded border border-white/[0.06] bg-white/[0.02] px-2.5 py-1.5 font-mono text-[11px]">
                    <span className="truncate text-zinc-400">{event.requestId}</span>
                    <span
                      className={`shrink-0 ${(riskLevel(event.riskScore)) === "high" ? "text-rose-300" : "text-zinc-500"}`}
                    >
                      {(event.riskScore * 100).toFixed(0)}
                    </span>
                  </div>
                ))}
                {events.length === 0 && <p className="py-4 text-center text-xs text-zinc-600">暂无数据</p>}
              </div>
            </section>

            <section className="rounded-lg border border-teal-300/15 bg-white/[0.03] p-4 text-xs leading-6 text-zinc-400">
              <h2 className="text-sm font-semibold text-zinc-100">数据通道</h2>
              <dl className="mt-3 space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-zinc-500">实时事件</dt>
                  <dd className="truncate font-mono text-[11px] text-teal-200">GET /api/v1/events/stream</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-zinc-500">历史日志</dt>
                  <dd className="truncate font-mono text-[11px] text-teal-200">GET /api/v1/logs</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-zinc-500">聚合指标</dt>
                  <dd className="truncate font-mono text-[11px] text-teal-200">GET /metrics · 10s</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-zinc-500">网关地址</dt>
                  <dd className="ml-2 truncate font-mono text-[11px] text-zinc-300">{apiBase}</dd>
                </div>
              </dl>
              <p className="mt-4 border-t border-white/[0.06] pt-3 text-[11px] leading-5 text-zinc-600">
                事件来自策略引擎的实时判定，断线自动重连（最长 30s 退避）；持久记录以数据库审计日志为准。
              </p>
            </section>
          </div>
        </div>

        {/* Footer ticker */}
        <footer className="overflow-hidden border-t border-teal-300/10 bg-black/40 py-2">
          <div className="flex whitespace-nowrap">
            <motion.div
              className="flex shrink-0 items-center gap-10 pr-10 font-mono text-xs text-zinc-500"
              animate={{ x: ["0%", "-100%"] }}
              transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
            >
              {(events.length > 0
                ? events.slice(0, 8).map((event) => `[${new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}] ${event.threatType} · risk ${(event.riskScore * 100).toFixed(0)}% · ${event.requestId}`)
                : ["Shadow Agent 安全运行中 · 实时监控所有经过网关的 LLM 请求", "等待策略引擎事件推送…"]
              ).map((text, index) => (
                <span key={index} className="flex items-center gap-2">
                  <span className="h-1 w-1 rounded-full bg-teal-300/60" aria-hidden />
                  {text}
                </span>
              ))}
            </motion.div>
            <motion.div
              className="flex shrink-0 items-center gap-10 pr-10 font-mono text-xs text-zinc-500"
              animate={{ x: ["0%", "-100%"] }}
              transition={{ duration: 40, repeat: Infinity, ease: "linear" }}
              aria-hidden
            >
              {(events.length > 0
                ? events.slice(0, 8).map((event) => `[${new Date(event.ts).toLocaleTimeString("zh-CN", { hour12: false })}] ${event.threatType} · risk ${(event.riskScore * 100).toFixed(0)}% · ${event.requestId}`)
                : ["Shadow Agent 安全运行中 · 实时监控所有经过网关的 LLM 请求", "等待策略引擎事件推送…"]
              ).map((text, index) => (
                <span key={`dup-${index}`} className="flex items-center gap-2">
                  <span className="h-1 w-1 rounded-full bg-teal-300/60" />
                  {text}
                </span>
              ))}
            </motion.div>
          </div>
        </footer>
      </div>
    </div>
  );
}
