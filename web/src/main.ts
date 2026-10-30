import { run, tagCategory, techniqueStatus, type Dataset, type Group, type Profile, type Result } from "./engine";
import { loadProfiles, newProfile, parseProfile, saveProfiles } from "./profiles";

interface IndexFile {
  builtAt: string;
  versions: { packageVersion: string; stackMinor: string; attackVersion: string; file: string }[];
}

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

const state = {
  index: null as IndexFile | null,
  datasets: new Map<string, Dataset>(),
  dataset: null as Dataset | null,
  profiles: {} as Record<string, Profile>,
  current: "",
  search: "",
  tagSearch: "",
  openCategories: new Set<string>(["Data Source", "OS"]),
  tab: "snippet",
  snippetMode: "dryRun" as "dryRun" | "apply",
  result: null as Result | null,
};

function profile(): Profile {
  return state.profiles[state.current]!;
}

async function loadDataset(version: string): Promise<Dataset> {
  const entry = state.index!.versions.find((v) => v.packageVersion === version) ?? state.index!.versions[0]!;
  let dataset = state.datasets.get(entry.packageVersion);
  if (!dataset) {
    const response = await fetch(`data/${entry.file}`);
    if (!response.ok) throw new Error(`Could not load ${entry.file} (${response.status})`);
    dataset = (await response.json()) as Dataset;
    state.datasets.set(entry.packageVersion, dataset);
  }
  return dataset;
}

async function selectProfile(name: string) {
  state.current = name;
  const p = profile();
  state.dataset = await loadDataset(p.rulesetVersion);
  if (p.rulesetVersion !== state.dataset.ruleset.packageVersion) p.rulesetVersion = state.dataset.ruleset.packageVersion;
  update();
}

/** Persist, recompute and re-render after any change to the current profile. */
function update() {
  state.profiles = { ...state.profiles };
  saveProfiles(state.profiles, state.current);
  state.result = run(state.dataset!, profile(), today());
  render();
}

function today(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// ---------- rendering ----------

function render() {
  const p = profile();
  const dataset = state.dataset!;
  const result = state.result!;
  const groupsById = new Map(dataset.groups.map((g) => [g.id, g]));

  $<HTMLSelectElement>("profile-select").innerHTML = Object.keys(state.profiles)
    .sort()
    .map((n) => `<option ${n === state.current ? "selected" : ""}>${esc(n)}</option>`)
    .join("");
  const nameInput = $<HTMLInputElement>("profile-name");
  if (document.activeElement !== nameInput) nameInput.value = p.name;

  $<HTMLSelectElement>("ruleset").innerHTML = state.index!.versions
    .map(
      (v) =>
        `<option value="${esc(v.packageVersion)}" ${v.packageVersion === p.rulesetVersion ? "selected" : ""}>` +
        `${esc(v.packageVersion)} (Kibana ${esc(v.stackMinor)}.x)</option>`,
    )
    .join("");
  $("ruleset-info").textContent = `ATT&CK ${dataset.attack.version} · ${dataset.rules.length} rules · ${dataset.groups.length} groups`;

  // groups
  const query = state.search.trim().toLowerCase();
  const matches = query ? searchGroups(dataset.groups, query).slice(0, 30) : [];
  $("group-results").innerHTML = matches
    .map((g) => {
      const chosen = p.groups.includes(g.id);
      const count = new Set([...g.techniques.direct, ...g.techniques.campaign]).size;
      return `<li><div class="meta"><strong>${esc(g.name)}</strong> <span class="hint">${g.id} · ${count} techniques</span>
        <div class="aliases">${esc(otherAliases(g).join(", "))}</div><div class="desc">${esc(g.description)}</div></div>
        <button type="button" data-add-group="${g.id}" ${chosen ? "disabled" : ""}>${chosen ? "Added" : "Add"}</button></li>`;
    })
    .join("") || (query ? `<li class="hint">No group matches “${esc(state.search)}”.</li>` : "");
  $("group-count").textContent = String(p.groups.length);
  $("group-clear").hidden = p.groups.length === 0;
  $("group-selected").innerHTML = p.groups
    .map((id) => {
      const g = groupsById.get(dataset.groupRedirects[id] ?? id);
      const label = [g?.id ?? id, ...(g ? otherAliases(g).slice(0, 3) : [])].join(", ");
      return `<li title="${esc(g ? otherAliases(g).join(", ") : "not in this ATT&CK version")}">${esc(g?.name ?? id)} <span class="hint">(${esc(label)})</span>
        <button type="button" data-remove-group="${id}" aria-label="Remove ${esc(g?.name ?? id)}">×</button></li>`;
    })
    .join("");

  // techniques
  $<HTMLInputElement>("include-software").checked = p.includeSoftware;
  const slider = $<HTMLInputElement>("min-groups");
  slider.max = String(Math.max(1, p.groups.length));
  slider.value = String(p.minGroups);
  $("min-groups-out").textContent = String(p.minGroups);
  $("technique-table").innerHTML = result.techniques.length
    ? `<thead><tr><th>Include</th><th>Technique</th><th>Groups</th><th>Rules</th><th>Status</th></tr></thead><tbody>` +
      result.techniques
        .map((t) => {
          const status = techniqueStatus(t);
          const groups = t.groups.map((g) => `${groupsById.get(g.id)?.name ?? g.id} (${g.via.join(", ")})`).join("; ");
          return `<tr class="${t.included ? "" : "excluded"}">
            <td><input type="checkbox" data-technique="${t.id}" ${t.included ? "checked" : ""} aria-label="Include ${t.id}"></td>
            <td><a href="https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/" target="_blank" rel="noopener">${t.id}</a> ${esc(t.name)}</td>
            <td>${t.count} <span class="hint">${esc(groups)}</span></td>
            <td>${t.selectedRuleIds.length}${t.filteredRuleIds.length ? ` <span class="hint">+${t.filteredRuleIds.length} filtered out</span>` : ""}</td>
            <td class="${status === "covered" ? "status-covered" : "status-gap"}">${t.included ? status : "excluded"}</td></tr>`;
        })
        .join("") +
      "</tbody>"
    : `<tbody><tr><td class="hint">Select one or more groups.</td></tr></tbody>`;

  // filters
  $<HTMLInputElement>("include-bb").checked = p.includeBuildingBlocks;
  $<HTMLInputElement>("include-ml").checked = p.includeMl;
  $<HTMLInputElement>("skip-disabled-run").checked = p.skipDisabledAfterRun;
  renderTagFilter(dataset, p);

  // output
  $("warnings").innerHTML = result.warnings.map((w) => `<li>${esc(w)}</li>`).join("");
  const stat = (n: number, label: string, tag: string, kind: string) =>
    `<div class="stat ${kind}"><span class="stat-n">${n}</span><span class="stat-label">${label}</span>${tag ? `<code>${esc(tag)}</code>` : ""}</div>`;
  $("summary").innerHTML =
    stat(result.selected.length, "rules to enable", result.tag, "stat-enable") +
    stat(result.filtered.length, "matching rules removed by tag filter", "no tag", "stat-filtered");
  $("tag-selected").textContent = result.tag;
  const ignoreInput = $<HTMLInputElement>("ignore-tags");
  if (document.activeElement !== ignoreInput) ignoreInput.value = p.ignoreTags.join(", ");
  $("snippet").textContent = result.snippets[state.snippetMode];
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-mode]")) {
    button.setAttribute("aria-pressed", String(button.dataset.mode === state.snippetMode));
  }
  for (const note of document.querySelectorAll<HTMLElement>("[data-mode-note]")) note.hidden = note.dataset.modeNote !== state.snippetMode;
  $("report").textContent = result.report.markdown;
  $("ids").textContent = result.ruleIdList || "(no rules selected)";
  for (const tab of document.querySelectorAll<HTMLButtonElement>("[data-tab]")) {
    tab.setAttribute("aria-selected", String(tab.dataset.tab === state.tab));
  }
  for (const panel of document.querySelectorAll<HTMLElement>("[data-panel]")) panel.hidden = panel.dataset.panel !== state.tab;
}

function setTag(tag: string, on: boolean) {
  const p = profile();
  p.tagFilters = on ? [...new Set([...p.tagFilters, tag])] : p.tagFilters.filter((t) => t !== tag);
  update();
}

const FIRST_CATEGORIES = ["Data Source", "OS"];

/** Tag checklist grouped by category, as in Kibana; categories open when searched or holding a ticked tag. */
function renderTagFilter(dataset: Dataset, p: Profile) {
  const counts = new Map<string, number>();
  for (const r of dataset.rules) for (const t of r.tags) counts.set(t, (counts.get(t) ?? 0) + 1);
  const query = state.tagSearch.trim().toLowerCase();
  const categories = new Map<string, string[]>();
  for (const tag of dataset.tags) {
    if (query && !tag.toLowerCase().includes(query)) continue;
    const category = tagCategory(tag);
    categories.set(category, [...(categories.get(category) ?? []), tag]);
  }
  const rank = (c: string) => (FIRST_CATEGORIES.includes(c) ? FIRST_CATEGORIES.indexOf(c) : FIRST_CATEGORIES.length);
  const ordered = [...categories.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]));
  const ticked = new Set(p.tagFilters);

  $("tag-chips").innerHTML = p.tagFilters
    .map((t) => `<li>${esc(t)} <button type="button" data-remove-tag="${esc(t)}" aria-label="Remove ${esc(t)}">×</button></li>`)
    .join("");
  $("tag-categories").innerHTML =
    ordered
      .map(([category, tags]) => {
        const nTicked = tags.filter((t) => ticked.has(t)).length;
        const open = query || state.openCategories.has(category) || nTicked > 0;
        return `<details data-category="${esc(category)}" ${open ? "open" : ""}>
          <summary>${esc(category)} <span class="hint">${tags.length} tags${nTicked ? `, ${nTicked} ticked` : ""}</span></summary>
          <ul class="checklist">${tags
            .map(
              (t) => `<li><label class="check"><input type="checkbox" data-tag="${esc(t)}" ${ticked.has(t) ? "checked" : ""}>
                ${esc(t.slice(category === "Other" ? 0 : category.length + 1).trim())} <span class="hint">${counts.get(t) ?? 0}</span></label></li>`,
            )
            .join("")}</ul></details>`;
      })
      .join("") || `<p class="hint">No tag matches “${esc(state.tagSearch)}”.</p>`;
}

function otherAliases(g: Group): string[] {
  return g.aliases.filter((a) => a !== g.name);
}

function searchGroups(groups: Group[], query: string): Group[] {
  const score = (g: Group) => {
    const names = [g.id, g.name, ...g.aliases].map((n) => n.toLowerCase());
    if (names.includes(query)) return 0;
    if (names.some((n) => n.startsWith(query))) return 1;
    if (names.some((n) => n.includes(query))) return 2;
    return 3;
  };
  return groups
    .map((g) => [g, score(g)] as const)
    .filter(([, s]) => s < 3)
    .sort((a, b) => a[1] - b[1] || a[0].name.localeCompare(b[0].name))
    .map(([g]) => g);
}

/** Matches pasted lines exactly (case-insensitive) against group IDs, names and aliases. */
function matchPasted(dataset: Dataset, text: string) {
  const lookup = new Map<string, string>();
  for (const g of dataset.groups) for (const n of [g.id, g.name, ...g.aliases]) lookup.set(n.toLowerCase(), g.id);
  for (const [from, to] of Object.entries(dataset.groupRedirects)) lookup.set(from.toLowerCase(), to);
  const found: string[] = [];
  const unmatched: string[] = [];
  for (const line of text.split(/[\n;,\t]+/).map((l) => l.trim()).filter(Boolean)) {
    const id = lookup.get(line.toLowerCase());
    if (id) found.push(id);
    else unmatched.push(line);
  }
  return { found: [...new Set(found)], unmatched };
}

// ---------- events ----------

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
    const p = newProfile(state.dataset!, uniqueName("New profile"));
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
      const p = newProfile(state.dataset!, "My threat profile");
      state.profiles[p.name] = p;
    }
    selectProfile(Object.keys(state.profiles).sort()[0]!);
  });
  $("profile-export").addEventListener("click", () =>
    download(`${slug(profile().name)}.apt2rule.json`, JSON.stringify(profile(), null, 2), "application/json"),
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
      await selectProfile(p.name);
    } catch (err) {
      $("warnings").innerHTML = `<li>Could not import ${esc(file.name)}: ${esc(String(err))}</li>`;
    }
  });
  $("ruleset").addEventListener("change", async (e) => {
    profile().rulesetVersion = (e.target as HTMLSelectElement).value;
    state.dataset = await loadDataset(profile().rulesetVersion);
    update();
  });

  $("group-search").addEventListener("input", (e) => {
    state.search = (e.target as HTMLInputElement).value;
    render();
  });
  document.addEventListener("click", (e) => {
    const target = (e.target as HTMLElement).closest<HTMLElement>("[data-add-group],[data-remove-group],[data-tab],[data-mode]");
    if (!target) return;
    if (target.dataset.mode) {
      state.snippetMode = target.dataset.mode === "apply" ? "apply" : "dryRun";
      return render();
    }
    const p = profile();
    if (target.dataset.addGroup) {
      p.groups = [...p.groups, target.dataset.addGroup];
    } else if (target.dataset.removeGroup) {
      p.groups = p.groups.filter((g) => g !== target.dataset.removeGroup);
      p.minGroups = Math.min(p.minGroups, Math.max(1, p.groups.length));
    } else if (target.dataset.tab) {
      state.tab = target.dataset.tab;
      return render();
    }
    update();
  });
  $("group-paste-add").addEventListener("click", () => {
    const p = profile();
    const { found, unmatched } = matchPasted(state.dataset!, $<HTMLTextAreaElement>("group-paste").value);
    const added = found.filter((id) => !p.groups.includes(id));
    p.groups = [...p.groups, ...added];
    $("group-paste-result").textContent =
      `Added ${added.length} group(s).` + (unmatched.length ? ` Not recognised: ${unmatched.join(", ")}.` : "");
    update();
  });

  $("group-clear").addEventListener("click", () => {
    const p = profile();
    if (!confirm(`Remove all ${p.groups.length} selected groups?`)) return;
    p.groups = [];
    p.minGroups = 1;
    update();
  });

  $("include-software").addEventListener("change", (e) => {
    profile().includeSoftware = (e.target as HTMLInputElement).checked;
    update();
  });
  $("min-groups").addEventListener("input", (e) => {
    profile().minGroups = Number((e.target as HTMLInputElement).value);
    update();
  });
  $("technique-table").addEventListener("change", (e) => {
    const box = e.target as HTMLInputElement;
    const id = box.dataset.technique;
    const row = state.result!.techniques.find((t) => t.id === id);
    if (!id || !row) return;
    const p = profile();
    const overrides = { ...p.techniqueOverrides };
    if (box.checked === row.count >= p.minGroups) delete overrides[id];
    else overrides[id] = box.checked ? "include" : "exclude";
    p.techniqueOverrides = overrides;
    update();
  });

  $("include-bb").addEventListener("change", (e) => {
    profile().includeBuildingBlocks = (e.target as HTMLInputElement).checked;
    update();
  });
  $("include-ml").addEventListener("change", (e) => {
    profile().includeMl = (e.target as HTMLInputElement).checked;
    update();
  });
  $("skip-disabled-run").addEventListener("change", (e) => {
    profile().skipDisabledAfterRun = (e.target as HTMLInputElement).checked;
    update();
  });
  $("tag-categories").addEventListener("change", (e) => {
    const tag = (e.target as HTMLInputElement).dataset.tag;
    if (tag !== undefined) setTag(tag, (e.target as HTMLInputElement).checked);
  });
  $("tag-categories").addEventListener(
    "toggle",
    (e) => {
      const details = e.target as HTMLDetailsElement;
      const category = details.dataset.category;
      if (category === undefined || state.tagSearch.trim()) return;
      if (details.open) state.openCategories.add(category);
      else state.openCategories.delete(category);
    },
    true,
  );
  $("tag-search").addEventListener("input", (e) => {
    state.tagSearch = (e.target as HTMLInputElement).value;
    render();
  });
  $("ignore-tags").addEventListener("change", (e) => {
    profile().ignoreTags = (e.target as HTMLInputElement).value.split(",").map((t) => t.trim()).filter(Boolean);
    update();
  });
  $("tag-clear").addEventListener("click", () => {
    profile().tagFilters = [];
    update();
  });
  $("tag-chips").addEventListener("click", (e) => {
    const tag = (e.target as HTMLElement).closest<HTMLElement>("[data-remove-tag]")?.dataset.removeTag;
    if (tag !== undefined) setTag(tag, false);
  });

  const base = () => `apt2rule-${slug(profile().name)}-${today()}`;
  const snippet = () => state.result!.snippets[state.snippetMode];
  $("copy-snippet").addEventListener("click", (e) => copy(snippet(), e.target as HTMLButtonElement));
  $("copy-fleet").addEventListener("click", (e) => copy($("fleet-request").textContent ?? "", e.target as HTMLButtonElement));
  $("copy-ids").addEventListener("click", (e) => copy(state.result!.ruleIdList, e.target as HTMLButtonElement));
  $("download-snippet").addEventListener("click", () =>
    download(`${base()}-${state.snippetMode === "apply" ? "production" : "dry-run"}.txt`, snippet(), "text/plain"),
  );
  $("download-md").addEventListener("click", () => download(`${base()}-report.md`, state.result!.report.markdown, "text/markdown"));
  $("download-csv").addEventListener("click", () => download(`${base()}-report.csv`, state.result!.report.csv, "text/csv"));
  $("download-ids").addEventListener("click", () => download(`${base()}-rule-ids.txt`, state.result!.ruleIdList, "text/plain"));
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
    button.textContent = "Copy failed: select the text instead";
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
    const response = await fetch("data/index.json");
    if (!response.ok) throw new Error(`data/index.json: ${response.status}`);
    state.index = (await response.json()) as IndexFile;
    $("built-at").textContent = `Data built ${state.index.builtAt.slice(0, 10)}`;
    const newest = await loadDataset(state.index.versions[0]!.packageVersion);
    const { profiles, current } = loadProfiles();
    state.profiles = profiles;
    if (!Object.keys(profiles).length) {
      const p = newProfile(newest, "My threat profile");
      state.profiles[p.name] = p;
    }
    bind();
    await selectProfile(current && current in state.profiles ? current : Object.keys(state.profiles).sort()[0]!);
  } catch (err) {
    document.querySelector("main")!.innerHTML = `<section><h2>Could not load apt2rule data</h2><p>${esc(String(err))}</p>
      <p class="hint">If you opened the files directly, serve the folder instead, e.g. <code>python3 -m http.server</code>.</p></section>`;
  }
}

start();
