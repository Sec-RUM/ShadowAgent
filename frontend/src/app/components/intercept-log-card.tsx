"use client";

import { AnimatePresence, motion, type Variants } from "framer-motion";
import { AlertTriangle, Clock, Copy, Fingerprint, ShieldAlert, Sparkles } from "lucide-react";
import type { KeyboardEvent } from "react";

export type InterceptLogCardData = {
  id: number;
  timestamp: string;
  threat_type: string;
  action_taken: string;
  original_prompt: string;
  details: Record<string, unknown>;
};

type AnimatedInterceptLogListProps = {
  logs: InterceptLogCardData[];
  onSelect: (log: InterceptLogCardData) => void;
  onCopyRequestId?: (requestId: string) => void;
  compact?: boolean;
};

type GlassInterceptLogCardProps = {
  log: InterceptLogCardData;
  index?: number;
  compact?: boolean;
  onSelect: (log: InterceptLogCardData) => void;
  onCopyRequestId?: (requestId: string) => void;
};

const listVariants: Variants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.06, delayChildren: 0.04 },
  },
};

const cardVariants: Variants = {
  hidden: { opacity: 0, y: 24, filter: "blur(10px)", scale: 0.985 },
  show: {
    opacity: 1,
    y: 0,
    filter: "blur(0px)",
    scale: 1,
    transition: { type: "spring", stiffness: 420, damping: 34, mass: 0.72 },
  },
  exit: { opacity: 0, y: 14, filter: "blur(8px)", transition: { duration: 0.16 } },
};

function detailText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(detailText).filter(Boolean).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function asNumber(value: unknown, fallback = 0): number {
  const next = Number(value);
  return Number.isFinite(next) ? next : fallback;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function riskMeta(score: number) {
  if (score >= 0.9) {
    return {
      label: "High",
      caption: "高危",
      ring: "border-rose-300/35 bg-rose-500/12 text-[var(--tone-danger-text)] shadow-[0_0_24px_rgba(244,63,94,0.25)]",
      glow: "from-rose-400/28 via-orange-300/12 to-transparent",
      dot: "bg-rose-300 shadow-[0_0_12px_rgba(253,164,175,0.85)]",
      reason: "检测到覆盖系统指令、泄露隐藏上下文、绕过工具权限或诱导代理执行越权动作的强信号。",
    };
  }

  if (score >= 0.65) {
    return {
      label: "Medium",
      caption: "中危",
      ring: "border-amber-200/35 bg-amber-400/12 text-[var(--tone-warning-text)] shadow-[0_0_20px_rgba(251,191,36,0.18)]",
      glow: "from-amber-300/24 via-yellow-200/10 to-transparent",
      dot: "bg-amber-200 shadow-[0_0_12px_rgba(253,230,138,0.72)]",
      reason: "命中了可疑提示模式，需要结合来源、上下文隔离和工具权限继续审计。",
    };
  }

  return {
    label: "Low",
    caption: "低危",
    ring: "border-emerald-200/30 bg-emerald-400/10 text-[var(--tone-success-text)] shadow-[0_0_18px_rgba(52,211,153,0.16)]",
    glow: "from-emerald-300/18 via-cyan-200/8 to-transparent",
    dot: "bg-emerald-200 shadow-[0_0_12px_rgba(167,243,208,0.64)]",
    reason: "当前风险信号较弱，但仍保留审计记录，便于追踪间接提示词注入链路。",
  };
}

function buildTooltip(log: InterceptLogCardData, fallback: string): string {
  const details = log.details;
  const reason = detailText(details.reason) || detailText(details.block_reason) || fallback;
  const rules = detailText(details.matched_rules) || detailText(details.rule_name) || detailText(details.triggered_rule);
  const excerpt = detailText(details.source_excerpt) || detailText(details.evidence);
  const layer = detailText(details.layer);

  return [
    reason,
    rules ? `命中规则: ${rules}` : "",
    layer ? `检测层: ${layer}` : "",
    excerpt ? `证据片段: ${excerpt}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function getRequestId(log: InterceptLogCardData): string {
  return detailText(log.details.request_id) || `local-${log.id}`;
}

function safeDomId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 80);
}

export function AnimatedInterceptLogList({
  logs,
  compact = false,
  onSelect,
  onCopyRequestId,
}: AnimatedInterceptLogListProps) {
  return (
    <motion.div
      variants={listVariants}
      initial="hidden"
      animate="show"
      className={compact ? "space-y-3 p-4" : "space-y-3 p-4 sm:p-5"}
    >
      <AnimatePresence mode="popLayout">
        {logs.map((log, index) => (
          <GlassInterceptLogCard
            key={`${log.id}-${getRequestId(log)}`}
            log={log}
            index={index}
            compact={compact}
            onSelect={onSelect}
            onCopyRequestId={onCopyRequestId}
          />
        ))}
      </AnimatePresence>
    </motion.div>
  );
}

export function GlassInterceptLogCard({
  log,
  index = 0,
  compact = false,
  onSelect,
  onCopyRequestId,
}: GlassInterceptLogCardProps) {
  const score = Math.max(0, Math.min(1, asNumber(log.details.risk_score)));
  const meta = riskMeta(score);
  const requestId = getRequestId(log);
  const layer = detailText(log.details.layer) || "prompt";
  const tooltip = buildTooltip(log, meta.reason);
  const tooltipId = `risk-tip-${log.id}-${safeDomId(requestId)}`;

  const handleKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(log);
    }
  };

  return (
    <motion.article
      layout
      variants={cardVariants}
      exit="exit"
      custom={index}
      tabIndex={0}
      role="button"
      aria-label={`查看拦截日志 ${requestId}`}
      onClick={() => onSelect(log)}
      onKeyDown={handleKeyDown}
      whileHover={{ y: -2, scale: 1.003 }}
      whileTap={{ scale: 0.995 }}
      className="group relative isolate cursor-pointer overflow-visible rounded-md border border-[var(--panel-border-soft)] bg-[var(--panel-bg)] p-px shadow-[var(--panel-shadow)] outline-none backdrop-blur-[28px] transition duration-300 hover:border-[var(--panel-border-strong)] hover:shadow-[var(--panel-shadow-hover)] focus-visible:ring-2 focus-visible:ring-teal-200/45"
    >
      <div className={`pointer-events-none absolute inset-x-8 -top-px h-px bg-gradient-to-r ${meta.glow}`} />
      <div className="pointer-events-none absolute -inset-px rounded-md bg-[radial-gradient(circle_at_18%_0%,rgba(20,184,166,0.17),transparent_38%),radial-gradient(circle_at_96%_10%,rgba(244,63,94,0.12),transparent_34%)] opacity-70 transition group-hover:opacity-100" />
      <div className="relative rounded-[7px] bg-[var(--log-card-inner)] px-4 py-4 ring-1 ring-white/[0.035] sm:px-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-md border border-cyan-200/18 bg-cyan-300/[0.06] px-2.5 py-1 text-xs font-medium text-[var(--tone-info-text)]">
                <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
                {log.threat_type || "Prompt Injection"}
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.045] px-2 py-1 font-mono text-[11px] text-zinc-300">
                <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                {layer}
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.035] px-2 py-1 text-[11px] text-zinc-400">
                <Clock className="h-3.5 w-3.5" aria-hidden />
                {formatTime(log.timestamp)}
              </span>
            </div>

            <p className={`mt-3 max-w-4xl overflow-hidden text-ellipsis text-zinc-100 ${compact ? "line-clamp-2 text-sm leading-6" : "line-clamp-3 text-sm leading-6"}`}>
              {log.original_prompt || "No prompt payload captured."}
            </p>

            <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
              <span className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-black/20 px-2.5 py-1 font-mono">
                <Fingerprint className="h-3.5 w-3.5 text-teal-200" aria-hidden />
                <span className="max-w-[15rem] truncate" title={requestId}>{requestId}</span>
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-rose-200/18 bg-rose-500/[0.075] px-2.5 py-1 text-[var(--tone-danger-text)]">
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                {log.action_taken || "Blocked"}
              </span>
              {onCopyRequestId ? (
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    onCopyRequestId(requestId);
                  }}
                  className="inline-flex h-7 items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.04] px-2 text-zinc-300 transition hover:border-teal-200/25 hover:bg-teal-300/[0.08] hover:text-[var(--tone-accent-text)] focus:outline-none focus:ring-2 focus:ring-teal-200/40"
                  aria-label={`复制请求 ID ${requestId}`}
                  title="复制请求 ID"
                >
                  <Copy className="h-3.5 w-3.5" aria-hidden />
                  Copy
                </button>
              ) : null}
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-3 lg:flex-col lg:items-end">
            <div className="relative">
              <button
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  onSelect(log);
                }}
                className={`peer inline-flex min-w-24 items-center justify-center gap-2 rounded-md border px-3 py-2 font-mono text-xs font-semibold tracking-normal transition hover:-translate-y-0.5 focus:outline-none focus:ring-2 focus:ring-teal-200/40 ${meta.ring}`}
                aria-describedby={tooltipId}
              >
                <Sparkles className="h-3.5 w-3.5" aria-hidden />
                {meta.label}
                <span className="text-[11px] opacity-70">{score.toFixed(2)}</span>
              </button>
              <div
                id={tooltipId}
                role="tooltip"
                className="pointer-events-none absolute right-0 top-[calc(100%+0.7rem)] z-30 w-72 translate-y-1 whitespace-pre-line rounded-md border border-[var(--tooltip-border)] bg-[var(--tooltip-bg)] px-3.5 py-3 text-left text-xs leading-5 text-[var(--tooltip-fg)] opacity-0 shadow-[var(--tooltip-shadow)] backdrop-blur-[22px] transition duration-200 peer-hover:translate-y-0 peer-hover:opacity-100 peer-focus:translate-y-0 peer-focus:opacity-100"
              >
                <div className="mb-1.5 font-medium text-[var(--text-primary)]">{meta.caption}风险说明</div>
                {tooltip}
              </div>
            </div>
          </div>
        </div>
      </div>
    </motion.article>
  );
}
