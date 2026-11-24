import type { GroupReason } from "../threat2apt/types";

export type { GroupReason };

export function isReason(r: unknown): r is GroupReason {
  const v = r as GroupReason;
  return (
    !!v &&
    typeof v === "object" &&
    v.source === "threat2apt" &&
    typeof v.date === "string" &&
    typeof v.profile === "string" &&
    [1, 2, 3].includes(v.tier) &&
    Array.isArray(v.countries) &&
    Array.isArray(v.matched)
  );
}

/** One line explaining why a group was selected; "manual" for groups added by hand. */
export function describeReason(r: GroupReason | undefined): string {
  if (!r) return "manual";
  const parts = [`threat2apt tier ${r.tier}`];
  if (r.countries.length) parts.push(`attributed to ${r.countries.map((c) => c.name).join(", ")}`);
  if (r.ransomware?.length) parts.push(`ransomware (${r.ransomware.join(", ")})`);
  if (r.matched.length) parts.push(`targets ${r.matched.map((m) => `${m.target} (${m.terms.join(", ")})`).join("; ")}`);
  if (r.location) {
    const places = r.location.places.join(", ");
    parts.push(r.location.status === "area" ? `your area (${places})` : r.location.status === "elsewhere" ? `elsewhere (${places})` : "location unknown");
  }
  parts.push(`last seen ${r.lastSeen ?? "unknown"}`);
  return `${parts.join(" · ")} (profile “${r.profile}”, ${r.date})`;
}
