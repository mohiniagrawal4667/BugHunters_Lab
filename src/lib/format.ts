import type { Severity, Confidence, FindingStatus, CheckId } from "../types";

const dateFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
});

const dateTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const timeFormatter = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

export function formatDate(iso: string): string {
  return dateFormatter.format(new Date(iso));
}

export function formatDateTime(iso: string): string {
  return dateTimeFormatter.format(new Date(iso)).replace(",", " ·");
}

export function formatTime(iso: string): string {
  return timeFormatter.format(new Date(iso));
}

export function formatRelative(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  if (delta < 45_000) return "just now";
  const minutes = Math.round(delta / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(iso);
}

export function formatDuration(startIso: string, endIso?: string): string {
  const end = endIso ? new Date(endIso).getTime() : Date.now();
  const seconds = Math.max(1, Math.round((end - new Date(startIso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

export function hostnameOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const CONFIDENCE_ORDER: Confidence[] = ["high", "medium", "low"];
export const STATUS_ORDER: FindingStatus[] = ["open", "pending", "resolved"];
export const CATEGORY_ORDER: CheckId[] = ["headers", "cookies", "paths", "injection"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Open",
  pending: "Pending verification",
  resolved: "Resolved",
};

export const CATEGORY_LABEL: Record<CheckId, string> = {
  headers: "Header inspector",
  cookies: "Cookie analyzer",
  paths: "Exposed path",
  injection: "Injection tester",
};

export function severityRank(value: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }[value];
}

export function confidenceRank(value: Confidence): number {
  return { high: 0, medium: 1, low: 2 }[value];
}

export function statusRank(value: FindingStatus): number {
  return { open: 0, pending: 1, resolved: 2 }[value];
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}

export function classNames(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(" ");
}
