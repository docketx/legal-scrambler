// The leak-rate measurement. Pure functions, so the harness and the tests share one definition of "leaked".
//
// GROUND TRUTH comes from the HLL bank: every item carries a `redaction_map` — placeholder tag -> the REAL name a
// human-audited pipeline replaced when the item was authored — and a `source.docket` pointing at the opinion.
// So for an opinion whose text we hold, the union of its items' redaction_map values is a set of names that
// MUST NOT survive scrambling. That is a real, independently produced ground truth, not one we made up to
// pass our own test.
//
// What it cannot tell us: a per-TYPE breakdown (the map has tags like "[A]" and "[Justice]", not our enum), and
// anything about names the HLL authoring did not redact. So the number this produces is a leak rate against
// the names a human-audited process chose to redact — stated that way, every time.
import { extractCitations } from "./citations";
import { inCaptionAt, flex } from "./apply";

export type GroundTruth = { docket: string; names: string[] };

/** Whole-word, case-insensitive, whitespace-tolerant: the same standard the scrambler's own residual gate uses. */
export function namePresent(text: string, name: string): boolean {
  return occurrences(text, name).length > 0;
}

/** Every whole-word occurrence, split into the ones the scrambler must remove and the ones it leaves BY DESIGN:
 *  a party inside a cited case caption ("Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249") is public
 *  law and stays. Counting those as leaks would punish the pipeline for keeping citations intact (oracle run,
 *  2026-09-15, opinion 24-0883). They are reported under their own heading, never folded into "leaked". */
export function occurrences(text: string, name: string): { index: number; caption: boolean }[] {
  if (!name.trim()) return [];
  const re = new RegExp(`(?<![\\p{L}\\p{N}])${flex(name.trim())}(?![\\p{L}\\p{N}])`, "giu");
  return [...text.matchAll(re)].map((m) => ({ index: m.index!, caption: inCaptionAt(text, m.index!, m.index! + m[0].length) }));
}

/** Names worth measuring: at least two characters, not a bare tag, not something the scrambler is REQUIRED to
 *  leave alone (a citation). "Sullivan" counts; "[Justice]" does not; "725 S.W.2d 705" does not. */
export function usableNames(map: Record<string, string> | undefined): string[] {
  const out = new Set<string>();
  for (const v of Object.values(map ?? {})) {
    const s = String(v ?? "").trim();
    if (s.length < 2 || /^\[.*\]$/.test(s) || extractCitations(s).length) continue;
    out.add(s);
  }
  return [...out];
}

export type LeakReport = {
  docket: string;
  ground_truth: number;
  present_in_input: number;
  leaked: number;
  leaked_names_count: number;   // never the names themselves in any log
  /** names whose only surviving occurrences are inside cited-case captions: intentional, reported separately */
  caption_only: number;
  /** OCCURRENCE level (review 2026-09-15, item 4): the name-level figures weigh a name that appears fifty times
   *  the same as one that appears once. These count every non-caption occurrence of every present ground-truth
   *  name in the input, and how many of those survive in the output. Nested ground-truth names ("Young" inside
   *  "Evan A. Young") are each counted under their own name; the map rarely carries both. */
  occurrences_in_input: number;
  occurrences_leaked: number;
  /** OVER-SCRUB PROXY, not a truth: capitalised multi-word phrases that were in the input and are gone from the
   *  output, after excluding ground-truth names (and phrases sharing a name token with one — the scrambler derives
   *  surname aliases by design), citations, and sentence-initial capitals. Nothing in the redaction_map says which
   *  of these SHOULD have stayed, so this is a count of candidates to look at, never an over-scrub rate. */
  phrases_in_input: number;
  over_scrub_candidates: number;
  citations_in: number;
  citations_out: number;
  citations_lost: number;
  /** The citations themselves: public law, so recording them costs nothing and says which one broke. */
  citations_missing: string[];
  chars: number;
  ms: number;
};

/** Score one opinion: which ground-truth names were in the input at all (a map can name a party the opinion
 *  text never spells out), how many survived, and whether any citation was destroyed. */
export function score(docket: string, input: string, output: string, names: string[], ms: number): LeakReport {
  const present = names.filter((n) => namePresent(input, n));
  const survivors = present.map((n) => occurrences(output, n)).filter((o) => o.length);
  const leaked = survivors.filter((o) => o.some((x) => !x.caption));
  const captionOnly = survivors.filter((o) => o.every((x) => x.caption));
  const nonCaption = (text: string, n: string) => occurrences(text, n).filter((x) => !x.caption).length;
  const occIn = present.reduce((a, n) => a + nonCaption(input, n), 0);
  const occOut = present.reduce((a, n) => a + nonCaption(output, n), 0);
  const cin = new Set(extractCitations(input)); const cout = new Set(extractCitations(output));
  const phrases = capitalisedPhrases(input, names, [...cin]);
  const scrubbed = phrases.filter((p) => !namePresent(output, p));
  const lost = [...cin].filter((c) => !cout.has(c));
  return { docket, ground_truth: names.length, present_in_input: present.length, leaked: leaked.length, leaked_names_count: leaked.length, caption_only: captionOnly.length,
    occurrences_in_input: occIn, occurrences_leaked: Math.min(occOut, occIn), phrases_in_input: phrases.length, over_scrub_candidates: scrubbed.length,
    citations_in: cin.size, citations_out: cout.size, citations_lost: lost.length, citations_missing: lost, chars: input.length, ms };
}

const CAP_TOKEN = /^[A-Z][\p{L}'’.-]+$/u;
/** Abbreviations whose trailing dot does not end a sentence; a single initial ("A.") is handled by shape. */
const NOT_SENTENCE_END = /^(?:Mr|Mrs|Ms|Dr|Hon|Jr|Sr|St|Inc|Co|Corp|Ltd|No|Nos|v|vs|J|JJ|C\.J|Ch|Art|Sec|Fed|Cir|Ct|App|Tex|Cal|Div|Dep't|Dept|Assoc|Bros|Rptr|Supp|Ed|Rev|Ann|Ann\.)\.$/i;
const isSentenceEnd = (prev: string | undefined) => prev === undefined || (/[.!?]["'’”)\]]*$/.test(prev) && !/^[A-Z]\.$/.test(prev) && !NOT_SENTENCE_END.test(prev));

/** The over-scrub proxy's candidate set: distinct runs of 2+ consecutive capitalised tokens in `text`, minus
 *  (a) runs that contain or sit inside a ground-truth name, or share a name-like token (3+ letters, not an
 *  honorific/connective) with one — those vanishing is the scrambler working, (b) runs that parse as a citation,
 *  and (c) the sentence-initial token, which is capitalised by grammar, not by being a name (the run continues
 *  from the next token). A PROXY: "Supreme Court" and "Rules of Civil Procedure" in here are exactly what we
 *  want to catch, but a stray heading or a defined term will also land here. Counts only; never logged. */
export function capitalisedPhrases(text: string, groundTruth: string[] = [], citations: string[] = extractCitations(text)): string[] {
  const raw = [...text.matchAll(/\S+/g)].map((m) => ({ t: m[0], start: m.index!, end: m.index! + m[0].length }));
  const LEAD = /^["'“‘(\[]+/, TRAIL = /[,;:!?"'”’)\]]+$/;
  const strip = (t: string) => t.replace(LEAD, "").replace(TRAIL, "");
  const out = new Set<string>(); let run: typeof raw = [];
  // The phrase is the INPUT'S OWN SLICE from first token to last, edges trimmed — "Facebook, Inc." keeps its comma —
  // so that its presence in the output is tested against what the scrambler actually saw. Rebuilding it from
  // stripped tokens ("DELIVERED May" for "DELIVERED: May") reported untouched text as scrubbed (2026-09-15).
  const flush = () => { if (run.length >= 2) out.add(text.slice(run[0].start, run[run.length - 1].end).replace(LEAD, "").replace(TRAIL, "")); run = []; };
  for (let i = 0; i < raw.length; i++) {
    const tok = strip(raw[i].t);
    const paragraphBreak = i > 0 && /\n\s*\n/.test(text.slice(raw[i - 1].end, raw[i].start));
    const sentenceStart = i === 0 || paragraphBreak || isSentenceEnd(raw[i - 1].t);
    // a run never crosses a sentence or paragraph boundary, and the sentence-initial token itself is not a name token
    if (!CAP_TOKEN.test(tok) || sentenceStart) { flush(); continue; }
    run.push(raw[i]);
    // hard separators end a run (a comma does not: "Smith, Jr.", "Facebook, Inc."); so does a sentence end
    if (/[;:!?)\]”"]$/.test(raw[i].t) || (/\.["'’”)\]]*$/.test(raw[i].t) && !/^[A-Z]\.$/.test(tok) && !NOT_SENTENCE_END.test(tok))) flush();
  }
  flush();
  const gtTokens = new Set<string>();
  for (const n of groundTruth) for (const t of n.split(/\s+/)) { const s = strip(t); if (s.length >= 3 && /^\p{Lu}/u.test(s) && !NAME_CONNECTIVE.test(s)) gtTokens.add(s.toLowerCase()); }
  const inCitation = (p: string) => citations.some((c) => c.includes(p) || p.includes(c));
  return [...out].filter((p) => {
    if (inCitation(p) || extractCitations(p).length) return false;
    if (groundTruth.some((n) => namePresent(p, n) || namePresent(n, p))) return false;
    return !p.split(/\s+/).some((t) => gtTokens.has(strip(t).toLowerCase()));
  });
}
const NAME_CONNECTIVE = /^(?:Mr|Mrs|Ms|Dr|Hon|Jr|Sr|Inc|Co|Corp|Ltd|LLC|LLP|The|And|Of|For|De|La|Del|Van|Von)\.?$/i;

/** Wilson score interval, 95%, for k of n, reported per 1,000 to one decimal; null when n is zero. Chosen over the
 *  normal approximation because the counts here are small and the rates near zero, where Wald gives [<0, x]. */
export function wilson(k: number, n: number, z = 1.96): [number, number] | null {
  if (!n) return null;
  const p = k / n, z2 = z * z, d = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / d;
  const half = (z * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / d;
  const r = (x: number) => Math.round(Math.max(0, Math.min(1, x)) * 1000 * 10) / 10;
  return [r(centre - half), r(centre + half)];
}

/** A degraded chunk whose cause was TRANSPORT — the model was never reached — says nothing about the model. On the
 *  2026-09-15 run the tunnel dropped after the first opinion; the next three went out regex-only in under half a
 *  second each and scored 19 of 19 names "leaked", which would have been reported as a 677-per-1,000 liaison leak
 *  rate. Those opinions are excluded from the rate and counted under their own heading. A MODEL degradation
 *  (unparseable, truncated) stays in the rate: that is the model's failure and the number must carry it. */
export const isTransportFailure = (reason: string) => /fetch failed|timeout|aborted|ECONN|socket|liaison \d{3}/i.test(reason);

export type Summary = {
  opinions: number; entities: number; leaked: number; per_1000: number | null;
  /** Wilson 95% interval on per_1000, as [lo, hi] per 1,000; null when no name was present */
  per_1000_ci: [number, number] | null;
  occurrences: number; leaked_occurrences: number; leaked_occurrences_per_1000: number | null; leaked_occurrences_per_1000_ci: [number, number] | null;
  /** over-scrub PROXY (see LeakReport): candidates out of capitalised phrases seen, summed over opinions */
  phrases: number; over_scrub_candidates: number;
  caption_only: number; citations_in: number; citations_lost: number; refused: number; degraded: number; excluded_transport: number; ms_total: number;
};

const per1000 = (k: number, n: number) => (n ? Math.round((k / n) * 1000 * 10) / 10 : null);

/** Reports resumed from an older JSON may predate the occurrence and over-scrub fields; they count as zero there
 *  and the name-level figures are unaffected. */
export function summarize(reports: LeakReport[], refused: number, degraded: number, excludedTransport = 0): Summary {
  const sum = (f: (r: LeakReport) => number | undefined) => reports.reduce((a, r) => a + (f(r) ?? 0), 0);
  const entities = sum((r) => r.present_in_input), leaked = sum((r) => r.leaked);
  const occurrences = sum((r) => r.occurrences_in_input), leakedOcc = sum((r) => r.occurrences_leaked);
  return { opinions: reports.length, entities, leaked, per_1000: per1000(leaked, entities), per_1000_ci: wilson(leaked, entities),
    occurrences, leaked_occurrences: leakedOcc, leaked_occurrences_per_1000: per1000(leakedOcc, occurrences), leaked_occurrences_per_1000_ci: wilson(leakedOcc, occurrences),
    phrases: sum((r) => r.phrases_in_input), over_scrub_candidates: sum((r) => r.over_scrub_candidates),
    caption_only: sum((r) => r.caption_only), citations_in: sum((r) => r.citations_in), citations_lost: sum((r) => r.citations_lost),
    refused, degraded, excluded_transport: excludedTransport, ms_total: sum((r) => r.ms) };
}

/** Split an opinion into passes of at most `max` chars on paragraph boundaries (node 0: minimize). A single
 *  paragraph longer than `max` is split on sentence ends; nothing is dropped.
 *
 *  `overlap` (review 2026-09-15, item 2 — the chunk-boundary straddle): with overlap > 0 every chunk after the
 *  first is prefixed with the last `overlap` chars of the chunk before it, so a name cut by a boundary is whole in
 *  at least one pass. The base chunks are cut at `max - overlap` so no pass exceeds `max`. The cost is model time
 *  only: MatterGraph.add() returns the existing node when a span it already holds is proposed again (case-,
 *  whitespace- and quote-insensitively), so a name seen in both halves of an overlap gets one placeholder, not
 *  two. Default 0: behaviour unchanged. */
/** A reporter citation wrapped across a blank line -- "Corp., 628 F.3d\n\n731, 737 (5th Cir. 2010)", "Inc., 320\n\nF.3d
 *  838" (double-spaced pdftotext) -- must not become a chunk boundary: the caption grammar then sees no citation
 *  after " v. ", the corporate-suffix rule takes the cited party, and the citation is destroyed. Both of the
 *  reporter citations the fifth proof run listed as lost were this (2026-09-16). A paragraph that ends in a
 *  comma-then-volume or a volume-then-reporter is joined to the next when it opens with a page or a reporter. */
const REPORTER_ALT = String.raw`U\.S\.|S\.\s?Ct\.|L\.\s?Ed\.(?:\s?2d)?|F\.(?:\s?(?:2d|3d|4th))?|F\.\s?Supp\.(?:\s?(?:2d|3d))?|F\.R\.D\.|B\.R\.|S\.W\.(?:\s?(?:2d|3d))?|S\.E\.(?:\s?2d)?|N\.E\.(?:\s?(?:2d|3d))?|N\.W\.(?:\s?2d)?|P\.(?:\s?(?:2d|3d))?|A\.(?:\s?(?:2d|3d))?|So\.(?:\s?(?:2d|3d))?|Cal\.\s?Rptr\.(?:\s?(?:2d|3d))?|WL|Fed\.\s?Appx\.`;
const CITE_HEAD = new RegExp(String.raw`(?:,\s*\d{1,4}|\b\d{1,4}\s+(?:${REPORTER_ALT}))\s*$`);
const CITE_TAIL = new RegExp(String.raw`^\s*(?:\d{1,6}\b|(?:${REPORTER_ALT})\s+\d)`);
/** Sentence breaks for a paragraph over the cap: after ". ! ?" (a closing quote or bracket allowed) and before a
 *  capital, a digit or an opening quote -- but never after an abbreviation: "Inc.", "Co.", "v.", "Cir.", "Sys.",
 *  an initial, or a reporter-style long one ("Constr.", "Supp."); a short lower-case word before the period ("one.", "law.") is a sentence end. A cut after "Inc." put " v. Phoenix Aviation
 *  Managers, Inc." at the head of a chunk with no left party, and the caption grammar could not see the caption. */
const ABBREV_TAIL = /(?:^|[\s(])(?:[A-Z]\.|[A-Z][a-z]{1,3}\.|vs?\.|(?:Ass'n|Assn|Assocs|Constr|Consol|Distrib|Enters|Equip|Hosp|Indus|Int'l|Mfg|Mfrs|Mgmt|Nat'l|Pharm|Prods|Servs|Transp|Univ|Supp|Dept|Auth|Comm'n|Comm'r)\.)["”’)]?$/;
export function sentences(p: string): string[] {
  const out: string[] = []; let last = 0;
  for (const m of p.matchAll(/(?<=[.!?]["”’)]?)\s+(?=["“(]?[A-Z0-9])/g)) { if (ABBREV_TAIL.test(p.slice(Math.max(0, m.index! - 12), m.index!))) continue; out.push(p.slice(last, m.index!)); last = m.index! + m[0].length; }
  out.push(p.slice(last)); return out.filter((x) => x.length);
}
export function paragraphs(text: string, max = 60_000, overlap = 0): string[] {
  const cap = overlap > 0 ? Math.max(1, max - overlap) : max;
  const out: string[] = []; let cur = "";
  const push = () => { if (cur.trim()) out.push(cur); cur = ""; };
  const parts = text.split(/\n\s*\n/);
  for (let i = 0; i + 1 < parts.length; ) { if (CITE_HEAD.test(parts[i]) && CITE_TAIL.test(parts[i + 1])) parts.splice(i, 2, parts[i] + "\n\n" + parts[i + 1]); else i++; }
  for (const p of parts) {
    if (p.length > cap) { push(); for (const s of sentences(p)) { if (cur.length + s.length + 1 > cap) push(); cur += (cur ? " " : "") + s; } push(); continue; }
    if (cur.length + p.length + 2 > cap) push();
    cur += (cur ? "\n\n" : "") + p;
  }
  push();
  if (overlap > 0) for (let i = out.length - 1; i > 0; i--) out[i] = out[i - 1].slice(-overlap) + out[i];
  return out;
}
