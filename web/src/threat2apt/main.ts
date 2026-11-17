import { writeHandoff } from "../handoff";
import {
  buildTable,
  countryCounts,
  prepare,
  reasonFor,
  suggest,
  targetCounts,
  TIER_LABELS,
  type Context,
  type Hit,
  type Suggestion,
  type T2aDataset,
  type T2aGroup,
  type T2aProfile,
  type TargetGroup,
  type Tier,
} from "./engine";
import { exportProfile, loadProfiles, newProfile, parseProfile, saveProfiles } from "./profiles";

interface IndexFile {
  builtAt: string;
  threat2apt?: { attackVersion: string; file: string };
}

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

const state = {
  ctx: null as Context | null,
  countryCounts: new Map<string, number>(),
  targetCounts: new Map<string, number>(),
  profiles: {} as Record<string, T2aProfile>,
  current: "",
  countrySearch: "",
  targetSearch: "",
  openTargetKinds: new Set<string>(["region", "sector"]),
  expanded: new Set<string>(),
  suggestions: [] as Suggestion[],
  notice: "",
};

function profile(): T2aProfile {
  return state.profiles[state.current]!;
}

function selectProfile(name: string) {
  state.current = name;
  state.expanded.clear();
  update();
}

/** Persist, recompute and re-render after any change to the current profile. */
function update() {
  saveProfiles(state.profiles, state.current);
  state.suggestions = suggest(state.ctx!, profile());
  render();
}

function today(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// ---------- rendering ----------

function render() {
  const p = profile();
  const ctx = state.ctx!;

  $<HTMLSelectElement>("profile-select").innerHTML = Object.keys(state.profiles)
    .sort()
    .map((n) => `<option ${n === state.current ? "selected" : ""}>${esc(n)}</option>`)
    .join("");
  const nameInput = $<HTMLInputElement>("profile-name");
  if (document.activeElement !== nameInput) nameInput.value = p.name;

  renderCountries(ctx, p);
  renderTargets(ctx, p);
  const custom = $<HTMLTextAreaElement>("custom-terms");
  if (document.activeElement !== custom) custom.value = p.customTerms.join(", ");

  for (const box of document.querySelectorAll<HTMLInputElement>("[data-tier]")) {
    box.checked = p.tiers.includes(Number(box.dataset.tier) as Tier);
  }
  const seen = $<HTMLInputElement>("seen-since");
  if (document.activeElement !== seen) seen.value = p.seenSince === null ? "" : String(p.seenSince);
  const hideUnknown = $<HTMLInputElement>("hide-unknown");
  hideUnknown.checked = p.hideUnknownSeen;
  hideUnknown.disabled = p.seenSince === null;

  renderResults(ctx, p);
}

function renderCountries(ctx: Context, p: T2aProfile) {
  const ticked = new Set(p.countries);
  const query = state.countrySearch.trim().toLowerCase();
  const rows = ctx.dataset.countries
    .filter((c) => (state.countryCounts.get(c.code) ?? 0) > 0 || ticked.has(c.code))
    .filter((c) => !query || c.terms.some((t) => t.toLowerCase().includes(query)))
    .sort(
      (a, b) =>
        Number(ticked.has(b.code)) - Number(ticked.has(a.code)) ||
        (state.countryCounts.get(b.code) ?? 0) - (state.countryCounts.get(a.code) ?? 0) ||
        a.name.localeCompare(b.name),
    );
  $("country-list").innerHTML =
    rows
      .map(
        (c) => `<li><label class="check"><input type="checkbox" data-country="${c.code}" ${ticked.has(c.code) ? "checked" : ""}>
          ${esc(c.name)} <span class="hint">${state.countryCounts.get(c.code) ?? 0}</span></label></li>`,
      )
      .join("") || `<li class="hint">No country matches “${esc(state.countrySearch)}”.</li>`;
}

const KIND_LABELS: Record<TargetGroup["kind"], string> = { region: "Regions", sector: "Sectors", country: "Countries" };

function renderTargets(ctx: Context, p: T2aProfile) {
  const ticked = new Set(p.targets);
  const query = state.targetSearch.trim().toLowerCase();
  $("target-list").innerHTML = (["region", "sector", "country"] as const)
    .map((kind) => {
      const targets = ctx.targets
        .filter((t) => t.kind === kind)
        .filter((t) => !query || t.label.toLowerCase().includes(query) || t.terms.some((x) => x.toLowerCase().includes(query)))
        .sort((a, b) => Number(ticked.has(b.id)) - Number(ticked.has(a.id)) || (kind === "country" ? a.label.localeCompare(b.label) : 0));
      if (!targets.length) return "";
      const nTicked = targets.filter((t) => ticked.has(t.id)).length;
      const open = query || state.openTargetKinds.has(kind) || nTicked > 0;
      return `<details data-kind="${kind}" ${open ? "open" : ""}>
        <summary>${KIND_LABELS[kind]} <span class="hint">${targets.length}${nTicked ? `, ${nTicked} ticked` : ""}</span></summary>
        <ul class="checklist t2a-list">${targets
          .map(
            (t) => `<li><label class="check"><input type="checkbox" data-target="${esc(t.id)}" ${ticked.has(t.id) ? "checked" : ""}>
              ${esc(t.label)} <span class="hint">${state.targetCounts.get(t.id) ?? 0}</span></label>
              <details class="terms"><summary>terms</summary>${esc(t.terms.join(", "))}</details></li>`,
          )
          .join("")}</ul></details>`;
    })
    .join("") || `<p class="hint">No target matches “${esc(state.targetSearch)}”.</p>`;
}

function renderResults(ctx: Context, p: T2aProfile) {
  const all = state.suggestions;
  const picked = all.filter((s) => s.picked);
  $("picked-count").textContent = String(picked.length);
  $<HTMLButtonElement>("send").disabled = picked.length === 0;
  $<HTMLButtonElement>("copy-md").disabled = picked.length === 0;
  $<HTMLButtonElement>("download-csv").disabled = picked.length === 0;

  const byTier = (t: Tier) => all.filter((s) => s.tier === t);
  const stat = (n: number, label: string, kind: string) =>
    `<div class="stat ${kind}"><span class="stat-n">${n}</span><span class="stat-label">${label}</span></div>`;
  $("summary").innerHTML =
    (state.notice ? `<p class="t2a-notice" role="status">${esc(state.notice)}</p>` : "") +
    ([1, 2, 3] as const)
      .filter((t) => p.tiers.includes(t))
      .map((t) => stat(byTier(t).length, TIER_LABELS[t], `stat-tier${t}`))
      .join("") +
    stat(picked.length, "ticked", "stat-enable");

  if (!p.countries.length && !p.targets.length && !p.customTerms.length) {
    $("results").innerHTML = `<section class="panel t2a-empty"><h3>Start on the left</h3>
      <p>Tick the countries your threat assessment names (01), and the regions, sectors or countries your organisation belongs to (02).
      Groups attributed to a ticked country <em>and</em> targeting something like you land in tier 1.</p></section>`;
    return;
  }
  if (!p.tiers.length) {
    $("results").innerHTML = `<section class="panel t2a-empty"><p>No tiers ticked under “Show”.</p></section>`;
    return;
  }

  $("results").innerHTML = ([1, 2, 3] as const)
    .filter((t) => p.tiers.includes(t))
    .map((tier) => {
      const rows = byTier(tier);
      const nPicked = rows.filter((s) => s.picked).length;
      return `<section class="panel t2a-tier t2a-tier${tier}" aria-labelledby="tier-${tier}-h">
        <div class="t2a-tier-head">
          <h2 id="tier-${tier}-h"><span class="step">T${tier}</span> ${esc(TIER_LABELS[tier].replace(/^Tier \d: /, ""))} <span class="count">${rows.length}</span></h2>
          ${rows.length ? `<div class="actions">
            <button type="button" class="ghost" data-tick-tier="${tier}" data-value="1" ${nPicked === rows.length ? "disabled" : ""}>Tick all</button>
            <button type="button" class="ghost" data-tick-tier="${tier}" data-value="0" ${nPicked === 0 ? "disabled" : ""}>Untick all</button>
          </div>` : ""}
        </div>
        ${rows.length ? `<div class="table-wrap"><table>
          <thead><tr><th><span class="sr-only">Pick</span></th><th>Group</th><th>Attributed to</th><th>Matched targets</th><th>Last seen</th></tr></thead>
          <tbody>${rows.map((s) => renderRow(ctx, s)).join("")}</tbody></table></div>`
          : `<p class="hint">No group in this tier.</p>`}
      </section>`;
    })
    .join("");
}

function renderRow(ctx: Context, s: Suggestion): string {
  const g = s.group;
  const open = state.expanded.has(g.id);
  const ticked = new Set(s.countryMatches.map((a) => a.country));
  const countries = g.attribution.length
    ? g.attribution
        .map((a) => `<span class="${ticked.has(a.country) ? "t2a-hit" : ""}">${esc(ctx.countryNames.get(a.country) ?? a.country)}</span>`)
        .join(", ")
    : `<span class="hint">unknown</span>`;
  const targets = s.targetMatches.length
    ? s.targetMatches.map((m) => `<span class="t2a-tag" title="${esc(m.terms.join(", "))}">${esc(m.label)}</span>`).join(" ")
    : `<span class="hint">none</span>`;
  const row = `<tr class="${s.picked ? "" : "excluded"}">
    <td><input type="checkbox" data-pick="${g.id}" ${s.picked ? "checked" : ""} aria-label="Pick ${esc(g.name)}"></td>
    <td><button type="button" class="t2a-expand" data-expand="${g.id}" aria-expanded="${open}">
        <span class="t2a-caret" aria-hidden="true">${open ? "▾" : "▸"}</span> <strong>${esc(g.name)}</strong></button>
      <span class="hint">${g.id}${g.aliases.length ? ` · ${esc(g.aliases.slice(0, 3).join(", "))}` : ""}</span></td>
    <td>${countries}</td>
    <td>${targets}</td>
    <td class="mono">${g.lastSeen ?? `<span class="hint">unknown</span>`}</td></tr>`;
  return open ? row + `<tr class="t2a-evidence"><td></td><td colspan="4">${renderEvidence(ctx, s)}</td></tr>` : row;
}

function renderEvidence(ctx: Context, s: Suggestion): string {
  const g = s.group;
  const ticked = new Set(s.countryMatches.map((a) => a.country));
  const attribution = g.attribution.length
    ? `<ul class="t2a-evidence-list">${g.attribution
        .map(
          (a) => `<li><strong class="${ticked.has(a.country) ? "t2a-hit" : ""}">${esc(ctx.countryNames.get(a.country) ?? a.country)}</strong>
            “${esc(a.evidence)}” <span class="hint">${esc(sourceLabel(g, a.source))}</span></li>`,
        )
        .join("")}</ul>`
    : `<p class="hint">No attribution phrase found in the ATT&amp;CK text.</p>`;
  const targets = s.targetMatches.length
    ? `<ul class="t2a-evidence-list">${s.targetMatches
        .map((m) => {
          const snippets = snippetsFor(g, m.hits);
          const more = snippets.length > 3 ? ` <span class="hint">+${snippets.length - 3} more</span>` : "";
          return `<li><strong>${esc(m.label)}</strong> <span class="hint">${esc(m.terms.join(", "))}</span>
            <ul>${snippets.slice(0, 3).map((x) => `<li>${x}</li>`).join("")}</ul>${more}</li>`;
        })
        .join("")}</ul>`
    : `<p class="hint">No ticked target found.</p>`;
  return `<div class="t2a-evidence-grid">
    <div><h3>Attribution</h3>${attribution}</div>
    <div><h3>Targets</h3>${targets}</div></div>
    <p class="hint"><a href="https://attack.mitre.org/groups/${g.id}/" target="_blank" rel="noopener">${g.id} on attack.mitre.org</a></p>`;
}

function sourceLabel(g: T2aGroup, source: string): string {
  if (source === "override") return "(manual correction in apt2rule's override file)";
  if (source === g.id) return "(group description)";
  const t = g.texts.find((x) => x.source === source);
  return `(campaign ${source}${t && t.name !== source ? ` ${t.name}` : ""})`;
}

/** Highlighted snippets around hits; hits close together share one snippet. */
function snippetsFor(g: T2aGroup, hits: Hit[]): string[] {
  const out: string[] = [];
  const WINDOW = 90;
  let i = 0;
  while (i < hits.length) {
    const first = hits[i]!;
    const text = g.texts[first.text]!.text;
    let start = Math.max(0, first.start - WINDOW);
    let end = Math.min(text.length, first.end + WINDOW);
    const inside: Hit[] = [];
    while (i < hits.length && hits[i]!.text === first.text && hits[i]!.start < end) {
      inside.push(hits[i]!);
      end = Math.min(text.length, Math.max(end, hits[i]!.end + 20));
      i++;
    }
    if (start > 0) start = text.indexOf(" ", start) + 1 || start;
    if (end < text.length) end = text.lastIndexOf(" ", end) > inside.at(-1)!.end ? text.lastIndexOf(" ", end) : end;
    let html = start > 0 ? "…" : "";
    let pos = start;
    for (const h of inside) {
      if (h.start < pos) continue;
      html += esc(text.slice(pos, h.start)) + `<mark>${esc(text.slice(h.start, h.end))}</mark>`;
      pos = h.end;
    }
    html += esc(text.slice(pos, end)) + (end < text.length ? "…" : "");
    out.push(`${html} <span class="hint">${esc(sourceLabel(g, first.source))}</span>`);
  }
  return out;
}

// ---------- events ----------

function toggle(list: string[], value: string, on: boolean): string[] {
  return on ? [...new Set([...list, value])] : list.filter((v) => v !== value);
}

function setPick(s: Suggestion, on: boolean) {
  const picks = { ...profile().picks };
  if (on === (s.tier === 1)) delete picks[s.group.id];
  else picks[s.group.id] = on;
  profile().picks = picks;
}

function bind() {
  $("profile-select").addEventListener("change", (e) => selectProfile((e.target as HTMLSelectElement).value));
  $("profile-name").addEventListener("change", (e) => {
    const name = (e.target as HTMLInputElement).value.trim();
    if (!name || name === state.current) return;
    const p = { ...profile(), name: uniqueName(name) };
    delete state.profiles[state.current];
    state.profiles[p.name] = p;
    state.current = p.name;
    update();
  });
  $("profile-new").addEventListener("click", () => {
    const p = newProfile(uniqueName("New profile"));
    state.profiles[p.name] = p;
    selectProfile(p.name);
  });
  $("profile-delete").addEventListener("click", () => {
    const button = $<HTMLButtonElement>("profile-delete");
    if (button.dataset.confirm !== "yes") {
      button.dataset.confirm = "yes";
      button.textContent = "Click again to delete";
      setTimeout(() => ((button.dataset.confirm = ""), (button.textContent = "Delete")), 3000);
      return;
    }
    button.dataset.confirm = "";
    button.textContent = "Delete";
    delete state.profiles[state.current];
    if (!Object.keys(state.profiles).length) {
      const p = newProfile("My threat assessment");
      state.profiles[p.name] = p;
    }
    selectProfile(Object.keys(state.profiles).sort()[0]!);
  });
  $("profile-export").addEventListener("click", () =>
    download(`${slug(profile().name)}.threat2apt.json`, exportProfile(profile()), "application/json"),
  );
  $("profile-import").addEventListener("change", async (e) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    try {
      const p = parseProfile(await file.text());
      p.name = uniqueName(p.name);
      state.profiles[p.name] = p;
      state.notice = "";
      selectProfile(p.name);
    } catch (err) {
      state.notice = `Could not import ${file.name}: ${String(err)}`;
      render();
    }
  });

  $("country-search").addEventListener("input", (e) => {
    state.countrySearch = (e.target as HTMLInputElement).value;
    renderCountries(state.ctx!, profile());
  });
  $("country-list").addEventListener("change", (e) => {
    const box = e.target as HTMLInputElement;
    if (!box.dataset.country) return;
    profile().countries = toggle(profile().countries, box.dataset.country, box.checked);
    update();
  });
  $("target-search").addEventListener("input", (e) => {
    state.targetSearch = (e.target as HTMLInputElement).value;
    renderTargets(state.ctx!, profile());
  });
  $("target-list").addEventListener("change", (e) => {
    const box = e.target as HTMLInputElement;
    if (!box.dataset.target) return;
    profile().targets = toggle(profile().targets, box.dataset.target, box.checked);
    update();
  });
  $("target-list").addEventListener(
    "toggle",
    (e) => {
      const details = e.target as HTMLDetailsElement;
      const kind = details.dataset.kind;
      if (kind === undefined || state.targetSearch.trim()) return;
      if (details.open) state.openTargetKinds.add(kind);
      else state.openTargetKinds.delete(kind);
    },
    true,
  );
  $("custom-terms").addEventListener("change", (e) => {
    const terms = (e.target as HTMLTextAreaElement).value.split(/[,\n]/).map((t) => t.trim()).filter(Boolean);
    profile().customTerms = [...new Set(terms)];
    update();
  });

  for (const box of document.querySelectorAll<HTMLInputElement>("[data-tier]")) {
    box.addEventListener("change", () => {
      const tier = Number(box.dataset.tier) as Tier;
      const tiers = new Set(profile().tiers);
      if (box.checked) tiers.add(tier);
      else tiers.delete(tier);
      profile().tiers = [...tiers].sort() as Tier[];
      update();
    });
  }
  $("seen-since").addEventListener("change", (e) => {
    const value = (e.target as HTMLInputElement).value.trim();
    const year = Number(value);
    profile().seenSince = value && Number.isInteger(year) ? year : null;
    update();
  });
  $("hide-unknown").addEventListener("change", (e) => {
    profile().hideUnknownSeen = (e.target as HTMLInputElement).checked;
    update();
  });

  $("results").addEventListener("change", (e) => {
    const id = (e.target as HTMLInputElement).dataset.pick;
    const s = state.suggestions.find((x) => x.group.id === id);
    if (!s) return;
    setPick(s, (e.target as HTMLInputElement).checked);
    update();
  });
  $("results").addEventListener("click", (e) => {
    const target = (e.target as HTMLElement).closest<HTMLElement>("[data-expand],[data-tick-tier]");
    if (!target) return;
    if (target.dataset.expand) {
      const id = target.dataset.expand;
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      return renderResults(state.ctx!, profile());
    }
    const tier = Number(target.dataset.tickTier);
    for (const s of state.suggestions) if (s.tier === tier) setPick(s, target.dataset.value === "1");
    update();
  });

  const picked = () => state.suggestions.filter((s) => s.picked);
  $("send").addEventListener("click", () => {
    const p = profile();
    const date = today();
    const ok = writeHandoff({
      version: 1,
      createdAt: new Date().toISOString(),
      profile: p.name,
      attackVersion: state.ctx!.dataset.attack.version,
      groups: picked().map((s) => ({ id: s.group.id, name: s.group.name, reason: reasonFor(state.ctx!, s, p, date) })),
    });
    if (!ok) {
      state.notice = "Your browser blocks local storage, so the groups can't be handed over. Copy the table and paste the IDs into apt2rule instead.";
      return render();
    }
    location.href = "../";
  });
  $("copy-md").addEventListener("click", (e) => copy(buildTable(state.ctx!, picked()).markdown, e.target as HTMLButtonElement));
  $("download-csv").addEventListener("click", () =>
    download(`threat2apt-${slug(profile().name)}-${today()}.csv`, buildTable(state.ctx!, picked()).csv, "text/csv"),
  );
}

function uniqueName(name: string): string {
  let candidate = name;
  for (let i = 2; candidate in state.profiles && candidate !== state.current; i++) candidate = `${name} (${i})`;
  return candidate;
}

async function copy(text: string, button: HTMLButtonElement) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy failed";
  }
  setTimeout(() => (button.textContent = label), 1500);
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "profile";
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

async function start() {
  try {
    const indexResponse = await fetch("../data/index.json");
    if (!indexResponse.ok) throw new Error(`data/index.json: ${indexResponse.status}`);
    const index = (await indexResponse.json()) as IndexFile;
    if (!index.threat2apt) throw new Error("this data build has no threat2apt dataset yet");
    const response = await fetch(`../data/${index.threat2apt.file}`);
    if (!response.ok) throw new Error(`${index.threat2apt.file}: ${response.status}`);
    const dataset = (await response.json()) as T2aDataset;
    state.ctx = prepare(dataset);
    state.countryCounts = countryCounts(dataset);
    state.targetCounts = targetCounts(state.ctx);
    $("built-at").textContent = `ATT&CK ${dataset.attack.version} · ${dataset.groups.length} groups · data built ${index.builtAt.slice(0, 10)}`;
    const { profiles, current } = loadProfiles();
    state.profiles = profiles;
    if (!Object.keys(profiles).length) {
      const p = newProfile("My threat assessment");
      state.profiles[p.name] = p;
    }
    bind();
    selectProfile(current && current in state.profiles ? current : Object.keys(state.profiles).sort()[0]!);
  } catch (err) {
    document.querySelector(".t2a-layout")!.innerHTML = `<section class="panel"><h2>Could not load threat2apt data</h2><p>${esc(String(err))}</p>
      <p class="hint">If you opened the files directly, serve the folder instead, e.g. <code>python3 -m http.server</code>.</p></section>`;
  }
}

start();
