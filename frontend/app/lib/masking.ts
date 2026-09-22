"use client";

import { useEffect, useState } from "react";

export const MASKING_STORAGE_KEY = "mailtrace_mask_sensitive";
export const MASKING_EVENT = "mailtrace-masking-changed";

export function maskEmail(value: string): string {
  const [local, domain] = value.split("@", 2);
  if (!domain) return value;
  return `${local ? `${local[0]}${"*".repeat(Math.max(1, local.length - 1))}` : "***"}@${domain}`;
}

export function maskIp(value: string): string {
  const parts = value.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.**.**` : value;
}

export function maskText(value: string): string {
  if (value.length <= 2) return "*".repeat(value.length);
  return `${value[0]}${"*".repeat(Math.max(1, value.length - 2))}${value[value.length - 1]}`;
}

export function maskSensitiveValue(value: unknown, enabled: boolean, kind: "email" | "ip" | "text" = "text"): string {
  const text = value == null ? "—" : String(value);
  if (!enabled || !text || text === "—") return text;
  if (kind === "email") return maskEmail(text);
  if (kind === "ip") return maskIp(text);
  return maskText(text);
}

export function useMaskingPreference(): boolean {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    const read = () => setEnabled(window.localStorage.getItem(MASKING_STORAGE_KEY) === "true");
    read();
    window.addEventListener(MASKING_EVENT, read);
    window.addEventListener("storage", read);
    return () => {
      window.removeEventListener(MASKING_EVENT, read);
      window.removeEventListener("storage", read);
    };
  }, []);
  return enabled;
}
