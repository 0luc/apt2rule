import { isReason, type GroupReason } from "./engine/reason";

export type { GroupReason };

/** Groups threat2apt sends to apt2rule. Both pages are on the same origin, so local storage carries it. */
export interface Handoff {
  version: 1;
  createdAt: string;
  profile: string;
  attackVersion: string;
  groups: { id: string; name: string; reason: GroupReason }[];
}

const KEY = "apt2rule.handoff";

export function writeHandoff(handoff: Handoff): boolean {
  try {
    localStorage.setItem(KEY, JSON.stringify(handoff));
    return true;
  } catch {
    return false;
  }
}

/** The pending handoff, or null when there is none or it is unreadable. */
export function readHandoff(): Handoff | null {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? "null") as Handoff | null;
    if (!v || v.version !== 1 || !Array.isArray(v.groups)) return null;
    const groups = v.groups.filter((g) => g && typeof g.id === "string" && typeof g.name === "string" && isReason(g.reason));
    return groups.length ? { ...v, groups } : null;
  } catch {
    return null;
  }
}

export function clearHandoff() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    // nothing to clear
  }
}
