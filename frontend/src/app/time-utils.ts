"use client";

const BEIJING_TIME_ZONE = "Asia/Shanghai";

function padTimePart(value: string) {
  return value.padStart(2, "0");
}

function formatFromParts(date: Date, timeZone: string) {
  const formatter = new Intl.DateTimeFormat("zh-CN", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const parts = formatter.formatToParts(date);
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));

  return [
    values.year || "0000",
    padTimePart(values.month || "00"),
    padTimePart(values.day || "00"),
  ].join("-") + ` ${padTimePart(values.hour || "00")}:${padTimePart(values.minute || "00")}:${padTimePart(values.second || "00")}`;
}

export function parseDateValue(value: string | null | undefined) {
  if (!value) return null;

  const normalized = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(value)
    ? `${value}Z`
    : value;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

export function formatBeijingTime(value: string | null | undefined, fallback = "未知时间") {
  const date = parseDateValue(value);
  if (!date) return fallback;
  return formatFromParts(date, BEIJING_TIME_ZONE);
}

export function formatUtcTime(value: string | null | undefined, fallback = "未知时间") {
  const date = parseDateValue(value);
  if (!date) return fallback;
  return `${formatFromParts(date, "UTC")} UTC`;
}

export function buildTimeTooltip(value: string | null | undefined, fallback = "未知时间") {
  const date = parseDateValue(value);
  if (!date) return fallback;
  return `北京时间 ${formatFromParts(date, BEIJING_TIME_ZONE)}\n原始 UTC ${formatFromParts(date, "UTC")} UTC`;
}

export function formatRelativeTime(value: string | null, fallback = "未知") {
  if (!value) return "尚未发生";
  const date = parseDateValue(value);
  if (!date) return fallback;

  const diffMs = date.getTime() - Date.now();
  const diffMinutes = Math.round(diffMs / (1000 * 60));
  if (Math.abs(diffMinutes) < 1) return "刚刚";
  if (Math.abs(diffMinutes) < 60) return diffMinutes > 0 ? `${diffMinutes} 分钟后` : `${Math.abs(diffMinutes)} 分钟前`;

  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) return diffHours > 0 ? `${diffHours} 小时后` : `${Math.abs(diffHours)} 小时前`;

  const diffDays = Math.round(diffHours / 24);
  return diffDays > 0 ? `${diffDays} 天后` : `${Math.abs(diffDays)} 天前`;
}
