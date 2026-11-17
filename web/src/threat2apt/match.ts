import { BLOCKING_PHRASES } from "./targets";
import type { Country, T2aGroup } from "./types";

/** Capitalised terms (DPRK, US, U.S., IT) match case-sensitively; others ignore case. */
export function isCaseSensitive(term: string): boolean {
  const letters = term.replace(/[^\p{L}]/gu, "");
  return letters.length >= 2 && letters === letters.toUpperCase();
}

const regexCache = new Map<string, RegExp>();

/** Regex for a term's text; findAll checks the word boundaries (cheaper than \p{L} in every regex). */
export function termRegex(term: string): RegExp {
  let re = regexCache.get(term);
  if (!re) {
    const body = term
      .trim()
      .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      .replace(/['’]/g, "['’]")
      .replace(/\s+/g, "\\s+");
    re = new RegExp(body, isCaseSensitive(term) ? "g" : "gi");
    regexCache.set(term, re);
  }
  re.lastIndex = 0;
  return re;
}

const WORD_CHAR = /[\p{L}\p{N}_]/u;
const isWordChar = (c: string | undefined) => c !== undefined && WORD_CHAR.test(c);

const WORD = /[\p{L}\p{N}_]+/gu;

/** Lowercased words of a text or term. */
export function words(s: string): string[] {
  return s.toLowerCase().match(WORD) ?? [];
}

const termWordsCache = new Map<string, string[]>();
export function termWords(term: string): string[] {
  let w = termWordsCache.get(term);
  if (!w) termWordsCache.set(term, (w = words(term)));
  return w;
}

/** All whole-word spans of a term. */
export function findAll(term: string, text: string): [number, number][] {
  if (!term.trim()) return [];
  const re = termRegex(term);
  const spans: [number, number][] = [];
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index;
    const end = start + m[0].length;
    const startsWord = !isWordChar(m[0][0]) || !isWordChar(text[start - 1]);
    const endsWord = !isWordChar(m[0][m[0].length - 1]) || !isWordChar(text[end]);
    if (startsWord && endsWord && end > start) {
      spans.push([start, end]);
      re.lastIndex = end;
    } else {
      re.lastIndex = start + 1; // e.g. "Guinea" inside "Guineans": try again one character later
    }
  }
  return spans;
}

/**
 * Ranges in a text where shorter hits don't count: a country's name ("Papua New Guinea", "South Sudan")
 * blocks hits of other countries' terms inside it ("Guinea", "Sudan"), and the blocking phrases
 * ("non-governmental") block every hit inside them.
 */
export interface Blocker {
  start: number;
  end: number;
  /** Country code, or null for a blocking phrase. */
  country: string | null;
}

export interface IndexedText {
  source: string;
  sourceName: string;
  text: string;
  /** Lowercased words of the text: a term whose words aren't all here can't match. */
  words: Set<string>;
  blockers: Blocker[];
}

/** Precomputes the blockers of every group text once per dataset. */
export function indexTexts(groups: T2aGroup[], countries: Country[]): Map<string, IndexedText[]> {
  const index = new Map<string, IndexedText[]>();
  for (const group of groups) {
    index.set(
      group.id,
      group.texts.map((t) => {
        const blockers: Blocker[] = [];
        const present = new Set(words(t.text));
        const mayContain = (term: string) => termWords(term).every((w) => present.has(w));
        for (const phrase of BLOCKING_PHRASES) {
          if (mayContain(phrase)) for (const [start, end] of findAll(phrase, t.text)) blockers.push({ start, end, country: null });
        }
        for (const country of countries) {
          for (const term of country.terms) {
            if (!term.includes(" ") && !term.includes("-")) continue; // only multi-word names can contain another
            if (mayContain(term)) for (const [start, end] of findAll(term, t.text)) blockers.push({ start, end, country: country.code });
          }
        }
        return { source: t.source, sourceName: t.name, text: t.text, words: present, blockers };
      }),
    );
  }
  return index;
}

/**
 * Spans of a term in an indexed text, minus those inside a blocker. Pass `country` for a country's own
 * terms: those are also blocked inside another country's name. Other terms ("Africa" in "South Africa")
 * are only blocked by the blocking phrases.
 */
export function findTerm(term: string, text: IndexedText, country?: string): [number, number][] {
  if (!termWords(term).every((w) => text.words.has(w))) return [];
  return findAll(term, text.text).filter(
    ([start, end]) =>
      !text.blockers.some(
        (b) =>
          b.start <= start &&
          end <= b.end &&
          b.end - b.start > end - start &&
          (b.country === null || (country !== undefined && b.country !== country)),
      ),
  );
}
