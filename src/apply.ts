// Deterministic substitution, both directions. No model here, ever.
//
// INTERVAL-BASED, NOT ITERATIVE — a red-team finding of 2026-09-15. The first version ran one regex replace per
// alias, longest first, each over the output of the previous. A hijacked model then proposed a junk span that
// straddled two real entities ("Salinas of Salinas & Jones"), it substituted first, and afterwards neither real
// alias matched — the gate saw no residual, and the attorney's first name reached the frontier. The same
// mechanism let a later short alias splice INSIDE a placeholder already written ("T_1]" into "[CLIENT_1]").
// Now every alias is matched against the ORIGINAL text, overlapping matches are resolved once (earliest start
// wins, then longest), and the output is spliced in a single pass. Nothing is ever matched against text that
// has already been rewritten, so a substitution can neither eat a neighbour nor corrupt a placeholder.
import type { MatterGraph } from "./graph";
import type { EntityType } from "./types";
import { extractCitations } from "./citations";

const PERSON_TYPES = new Set(["CLIENT", "PERSON", "ATTORNEY", "JUDGE"]);
import { HONORIFIC } from "./names";

/** Is the match at [start,end) a party of a CITED case — sitting on either side of " v. " with a reporter cite
 *  within 120 chars after? A person can be both a party in this matter and a party in a cited caption ("Justice
 *  Young" / "Young v. State", red-team 10e); the caption occurrence is public law and stays, the others go. */
// One name token of a caption. A comma joins tokens only before an organisation suffix: "JPMorgan Chase Bank,
// N.A." and "Acme Widgets, Inc." are one party; "Smith v. Jones, 12 S.W.3d 34" stops at the comma. The live
// battery (2026-09-15) scored ", N.A." parties of cited cases as leaks because the walk stopped at the comma.
const CAPTION_TOK = "(?:[A-Z][\\p{L}\\p{N}.&'’-]*|\\([A-Z][A-Z.]{0,8}\\)|of|the|and|&|for|de|la|del|van|von|d\\/b\\/a|et|al\\.?)";
const CAPTION_SEP = "(?:\\s+|,\\s+(?=(?:N\\.A\\.|Inc\\.?|LLC|L\\.L\\.C\\.|L\\.P\\.|LP|Ltd\\.?|Co\\.|Corp\\.|P\\.C\\.|P\\.A\\.|PLLC|LLP|L\\.L\\.P\\.|S\\.A\\.|N\\.V\\.)))";
const CAPTION_LEFT = new RegExp(`(${CAPTION_TOK}(?:${CAPTION_SEP}${CAPTION_TOK})*)\\s*$`, "u");
const CAPTION_RIGHT = new RegExp(`^(${CAPTION_TOK}(?:${CAPTION_SEP}${CAPTION_TOK})*)`, "u");

/** Reporter abbreviations, for the short-form citation and the volume-and-reporter piece. */
export const REPORTER_ALT = String.raw`U\.\s?S\.|S\.\s?Ct\.|L\.\s?Ed\.(?:\s?2d)?|F\.\s?Supp\.(?:\s?(?:2d|3d))?|F\.(?:\s?(?:2d|3d|4th))?|F\.R\.D\.|B\.R\.|S\.W\.(?:\s?(?:2d|3d))?|S\.E\.(?:\s?2d)?|N\.E\.(?:\s?(?:2d|3d))?|N\.W\.(?:\s?2d)?|P\.(?:\s?(?:2d|3d))?|A\.(?:\s?(?:2d|3d))?|So\.(?:\s?(?:2d|3d))?|Cal\.\s?Rptr\.(?:\s?(?:2d|3d))?|WL|Fed\.\s?App(?:x\.|['’]x)|F\.\s?App['’]x`;
/** "Horowitz, 435 U.S. at 86", "Twombly's, 550 U.S. 544": what follows a case name used as a SHORT-FORM citation. */
const SHORT_FORM_AFTER = new RegExp(String.raw`^(?:['’]s)?,?\s+\d{1,4}\s+(?:${REPORTER_ALT})\s+(?:at\s+)?\d`, "u");

/** A case name used as public law outside a full caption (live model on a real docket, 2026-09-16): the model
 *  proposed "Horowitz" from "(quoting Horowitz, 435 U.S. at 86)" and "the Horowitz Court", the guard accepted it
 *  because not every occurrence sat in a " v. " caption, the substitution scrubbed the case name out of its own
 *  citation, and a later chunk's "435 U.S." proposal destroyed the full cite so the caption lost its exemption and
 *  the gate refused the filing. A short-form cite and "the X Court" are public law when X is a caption party in the
 *  same text (see red-team 12f for why not otherwise). Shared by the guard, the substitution and the gate. */
export function inCaptionAt(text: string, start: number, end: number): boolean {
  if (inFullCaptionAt(text, start, end)) return true;
  // A short form or "the X Court" is public ONLY when the same name is a party of a full " v. " caption with its
  // citation in the same text. Red-team 12f (2026-09-16): with the short form trusted on its own, one planted fake
  // cite ("Jonathan Quill, 12 S.W.3d at 34") made the guard refuse the client's full name as a case party and the
  // name walked out in plain text. Without the caption in view the name is scrubbed -- over-scrub, the safe side.
  const shortForm = SHORT_FORM_AFTER.test(text.slice(end, end + 40)), court = /^\s+Court\b/.test(text.slice(end, end + 8));
  if (!shortForm && !court) return false;
  const name = text.slice(start, end);
  for (const m of text.matchAll(new RegExp(`(?<![\\p{L}\\p{N}])${esc(name)}(?![\\p{L}\\p{N}])`, "gu"))) {
    if (m.index !== start && inFullCaptionAt(text, m.index!, m.index! + m[0].length)) return true;
  }
  return false;
}

function inFullCaptionAt(text: string, start: number, end: number): boolean {
  // The caption is the run of NAME TOKENS on each side of " v. " — capitalised words, abbreviations, "&", "of",
  // "the" — not a punctuation-bounded stretch of prose. Punctuation bounds failed both ways on 2026-09-15: a comma
  // bound reached back across "…lost. See Young v. State" and sheltered "Justice Young"; a sentence bound cut
  // "Daniel Constr. Co." at "Constr." because ". C" looks like a sentence break. Grammar does neither.
  for (const m of text.matchAll(/\s+v(?:s)?\.\s+/g)) {
    const vStart = m.index!, vEnd = vStart + m[0].length;
    const head = text.slice(Math.max(0, vStart - 120), vStart);
    const lm = CAPTION_LEFT.exec(head);
    // The grammar admits "Salinas." as a token, so "counsel is Maria Salinas. See Young v. State" read the
    // attorney as the left party (orchestrator fixture, 2026-09-15). A token ending in a period is a sentence
    // end unless it is an abbreviation the way reporters write them ("Co.", "Constr.", "Assocs."); the caption
    // starts after the last such sentence end, and a leading signal word ("See", "Cf.") is not a party.
    let leftSeg = lm ? Math.max(0, vStart - 120) + lm.index : vStart;
    if (lm) {
      const toks = [...lm[1].matchAll(/\S+/g)];
      for (let i = toks.length - 2; i >= 0; i--) if (sentenceEnd(toks[i][0])) { leftSeg = Math.max(0, vStart - 120) + lm.index + toks[i + 1].index!; toks.splice(0, i + 1); break; }
      while (toks.length > 1 && SIGNAL.has(toks[0][0])) { toks.shift(); leftSeg = Math.max(0, vStart - 120) + lm.index + toks[0].index!; }
    }
    const tail = text.slice(vEnd, vEnd + 120);
    const rm = CAPTION_RIGHT.exec(tail);
    let rightEnd = rm ? vEnd + rm[1].length : vEnd;
    if (rm) for (const t of rm[1].matchAll(/\S+/g)) if (sentenceEnd(t[0])) { rightEnd = vEnd + t.index! + t[0].length; break; }
    if (!(start >= leftSeg && end <= vStart) && !(start >= vEnd && end <= rightEnd)) continue;
    if (extractCitations(text.slice(vEnd, vEnd + 220)).length > 0) return true;
  }
  return false;
}

/** Reporter-style abbreviations that end in a period but do not end a sentence (Bluebook T6, the common ones). */
const ABBREV = new Set(["assn", "assocs", "assoc", "bros", "constr", "consol", "corp", "distrib", "enters", "equip", "hosp", "indus", "ins", "mfg", "mfrs", "mgmt", "pharm", "prods", "servs", "sys", "tech", "transp", "trans", "univ", "auth", "dept", "cnty", "guar", "fid", "mut", "cas", "fin", "inv", "elec", "comm", "sav", "sec"]);
/** "Salinas." ends a sentence; "Co.", "Constr.", "J.R." and "Nat'l." do not. */
function sentenceEnd(tok: string): boolean {
  if (!tok.endsWith(".")) return false;
  const body = tok.slice(0, -1);
  if (/[.'’]/.test(body)) return false;             // "J.R.", "S.W.", "Nat'l."
  if (body.length <= 4) return false;               // "Co.", "Inc.", "Tex.", "Crim."
  return !ABBREV.has(body.toLowerCase());
}
const SIGNAL = new Set(["See", "Cf.", "Accord", "Compare", "Citing", "Contra", "Also", "E.g.", "But"]);

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const wordy = (alias: string) => /^[\p{L}\p{N}]/u.test(alias) && /[\p{L}\p{N}]$/u.test(alias);

/** An alias as a pattern that tolerates the spellings a document actually uses for the same string: any run
 *  of whitespace (a name wrapped across a line break, red-team 2d), and straight or typographic apostrophes and
 *  quotes ("O'Brien" / "O’Brien", red-team 2e). The graph already folds these when RESOLVING an alias; the
 *  substitution has to fold them when MATCHING one, or the variant spelling walks out the door.
 *  A pdftotext caption puts a "§" gutter between the two columns, so a party name wraps as "TWENTIETH CENTURY FOX
 *  §\nFILM CORP."; the gutter is whitespace to the matcher (the guard's in-input check and the substitution both),
 *  and the ledger restores it byte-exact -- proof run 9, 2026-09-16, charged that name as a leak. */
export function flex(alias: string): string {
  return alias.split(/\s+/).map((part) => part.split("").map((ch) => {
    if ("'’‘‚′".includes(ch)) return "['’‘‚′]";
    if ('"“”„″'.includes(ch)) return '["“”„″]';
    return esc(ch);
  }).join("")).join("\\s+(?:§\\s*)?");
}

/** Case-insensitive, unicode-aware, whole-word where the alias is word-like. Case-insensitivity is a red-team
 *  fix: "JOHN DOE" in a caption leaked past a graph that knew "John Doe". The cost is that a client named Bill
 *  scrubs the word "bill" — over-scrubbing, which is the safe direction. Possessive "'s" is left outside the
 *  match so "[CLIENT_1]'s" reads naturally. */
// The LEFT edge of a name, shared by the substitution and the residual gate so they can never disagree (the gate
// refused ten live documents for "exhibitJohn Smith": the gate found the glued name, the substitution could not
// reach it, 2026-09-15). A multi-word name needs no left boundary -- glued is still the name. A single token
// needs one, OR a camel boundary: preceded by a lower-case letter and starting with a capital ("employeeVance",
// "ExhibitBenson"), which never takes "nathan" out of "Jonathan" for a client called Nathan.
export const LEFT_MULTI = "";
export const LEFT_SINGLE = "(?<![\\p{L}\\p{N}])";
/** The camel boundary is a SEPARATE, case-sensitive pattern: under /iu, \p{Lu} matches "c", and one combined
 *  regex took "co" out of "Politico" for an alias "CO" (real docket, 2026-09-15). This one requires a lower-case
 *  letter before and the alias's own capital first letter. */
export function camelRegex(alias: string): RegExp | null {
  if (!wordy(alias) || /\s/.test(alias.trim()) || !/^\p{L}/u.test(alias)) return null;
  // case-insensitive on the body (the alias may be "SPEER", the text "LouSpeer"); callers keep only matches whose
  // first character is a capital in the TEXT -- camelMatches() does that, since \p{Lu} folds under /iu
  return new RegExp(`(?<=\\p{Ll})${flex(alias)}(?![\\p{L}\\p{N}])`, "giu");
}
export function camelMatches(text: string, alias: string): RegExpMatchArray[] {
  const re = camelRegex(alias); if (!re) return [];
  // the lookbehind's \p{Ll} folds under /iu and matched "T" -- "WAY" was taken out of "WESTWAY TERMINAL CO." (proof
  // run 9, 2026-09-16); the letter before must be lower-case in the TEXT, checked without the flag
  return [...text.matchAll(re)].filter((m) => /^\p{Lu}/u.test(m[0]) && /\p{Ll}/u.test(text[m.index! - 1] ?? ""));
}
function aliasRegex(alias: string): RegExp {
  if (!wordy(alias)) return new RegExp(flex(alias), "giu");
  // an identifier (digits, "@") glued to a word is still the identifier -- "Case4:10-cv-04865" -- exactly as the
  // residual gate already counts it; a letters-only single token keeps its word boundary
  const left = /\s/.test(alias.trim()) || /[\p{N}@]/u.test(alias) ? LEFT_MULTI : LEFT_SINGLE;
  return new RegExp(`${left}${flex(alias)}(?![\\p{L}\\p{N}])`, "giu");
}

/** Does `needle` occur in `text` allowing for line-wrapping and quote variants? The guard's in-input check uses
 *  this rather than String.includes: in opinions converted from PDF, a party name is wrapped across lines more
 *  often than not ("Endurance American\n  Specialty Insurance Company"), and a proposal normalised to single
 *  spaces was being refused as not-in-input — measured 2026-09-15 on the oracle run. */
export function inputHas(text: string, needle: string): boolean {
  return new RegExp(flex(needle), "iu").test(text);
}

type Hit = { start: number; end: number; placeholder: string };

/** Words that are capitalised for a reason other than being a given name. A surname match preceded by one of
 *  these is NOT extended over it. */
// (titles and offices that precede a name in a signature block are not given names: "Assistant Attorney General
// LACEY E. MASE" walked left over "General" on a real docket, 2026-09-15)
/** Job-title words. A person-typed span that OPENS with two or more of them is a title and a name ("Education
 *  Coordinator Stevenson", "Associate Residency Director Joanne L. Oakes", "Assistant Attorney General Lacey E.
 *  Mase"): the guard trims the title, and the given-name extension never walks onto one. One title word alone
 *  is left ("Dean Smith" may be a given name). Live model on Shurb v. UT Health, filing 7, 2026-09-16. */
export const TITLE_TOKEN = /^(?:education|coordinator|director|manager|supervisor|administrator|dean|professor|instructor|nurse|physician|doctor|residency|resident|program|programme|human|resources|disability|student|affairs|services|service|department|office|officer|medical|legal|clinical|academic|faculty|staff|case|regional|field|special|acting|interim|associate|assistant|deputy|senior|junior|chief|vice|executive|general|attorney|counsel|president|secretary|treasurer|chair|chairman|chairwoman|chairperson|commissioner|agent|partner|trustee|executor|guardian|liaison|analyst|specialist|technician|engineer|consultant|advisor|adviser|inspector|investigator|examiner|auditor|controller|comptroller|registrar|recorder|sheriff|constable|marshal|warden|captain|lieutenant|sergeant|corporal|detective|principal|superintendent|provost|chancellor|rector|trainer|therapist|counselor|counsellor|paralegal|clerk|bailiff|reporter|interpreter)\.?$/i;
const NOT_A_GIVEN_NAME = /^(?:exhibit|exh|ex|appendix|attachment|tab|see|despite|after|before|since|until|unless|though|once|whereas|whereby|via|regarding|concerning|following|including|notwithstanding|moreover|further|furthermore|additionally|finally|first|second|third|next|last|also|therefore|hence|accordingly|indeed|instead|otherwise|meanwhile|nevertheless|nonetheless|likewise|similarly|specifically|generally|importantly|notably|presumably|apparently|arguably|clearly|plainly|simply|only|even|still|yet|now|today|general|assistant|deputy|chief|senior|junior|counsel|attorney|attorneys|solicitor|clerk|director|secretary|commissioner|officer|agent|president|chairman|chairwoman|chair|manager|partner|associate|trustee|executor|administrator|guardian|esq|esquire|by|dear|see|the|in|on|at|by|for|to|of|and|or|but|under|per|id|cf|contra|accord|but|however|because|although|while|when|whether|if|as|so|then|thus|here|there|this|that|these|those|its|his|her|their|our|my|plaintiff|defendant|petitioner|respondent|appellant|appellee|relator|movant|court|judge|justice|counsel|attorney|officer|detective|dr|mr|mrs|ms|texas|state|county|city|united|states)\.?$/i;

/** Extend a single-token PERSON-type surname match leftward over preceding given-name tokens: "James D. Blacklock"
 *  when only "Blacklock" is an alias. MEASURED 2026-09-15 on the real model: the signature block "James D.
 *  Blacklock / Chief Justice" left "James D. [JUDGE_1]" and the fragment rule refused the opinion. A preceding
 *  token counts as a given name if it is an initial ("D.") or a capitalised word that is not a title, a sentence
 *  opener or a role word, and it does not follow sentence-ending punctuation. At most two tokens (first + middle). */
export function extendOverGivenNames(text: string, start: number): number {
  let s = start;
  for (let i = 0; i < 2; i++) {
    const before = text.slice(Math.max(0, s - 40), s);
    // an ALL-CAPS caption writes the given names in caps too: "ESTATE OF MARY LOUISE HARRIS" (2026-09-15)
    // ...and never across a line: in a signature block the previous line is the previous person ("Mikal C.
    // Watts\n      WATTS, GUERRA CRAFT" walked onto "Watts" and the firm's first word was never substituted,
    // real docket 2026-09-15)
    const m = /(?:^|[^\p{L}\p{N}.!?:;])([A-Z][a-z]{1,14}|[A-Z]{2,15}|[A-Z]\.)[ \t]+$/u.exec(before);
    if (!m) break;
    const tok = m[1];
    if (NOT_A_GIVEN_NAME.test(tok) || NOT_A_GIVEN_NAME.test(tok.toLowerCase()) || HONORIFIC.test(tok) || TITLE_TOKEN.test(tok)) break;
    const tokStart = s - (m[0].length - (m[0].length - m[0].trimStart().length)) ;
    const idx = before.lastIndexOf(tok); if (idx < 0) break;
    s = Math.max(0, s - 40) + idx;
  }
  return s;
}

function hits(text: string, graph: MatterGraph, only?: (type: EntityType) => boolean): Hit[] {
  const all: Hit[] = [];
  // The given-name extension is for SURNAME-only aliases ("Blacklock" -> "James D. Blacklock"). A derived GIVEN
  // name ("Jonathan" from "Jonathan P. Hargrove") must not walk left: it took "Dear Jonathan" as one name
  // (2026-09-15). A single token extends only when its node has no multi-token alias, or when it is the last
  // token of one.
  const subs = only ? graph.substitutions().filter((x) => only(x.type)) : graph.substitutions();
  const lastTokens = new Map<string, Set<string>>(); const multi = new Set<string>();
  const firstTokens = new Map<string, Set<string>>(); const innerTokens = new Map<string, Set<string>>();
  // multi-word tails of a longer alias on the same node ("Al Hardan", "Saeed Al Hardan" of "Omar Faraj Saeed Al
  // Hardan"): a surname of two or more words extends over the given names the way a single one does -- proof run 7
  // (2026-09-16) refused a filing whose signature block read "Faraj [PERSON_1]" after "Al Hardan" was substituted
  const tails = new Map<string, Set<string>>();
  for (const { alias, placeholder } of subs) {
    const toks = alias.trim().split(/\s+/).map((t) => t.replace(/[,.;:()"']/g, "")).filter(Boolean); if (toks.length < 2) continue;
    // a suffix is not the last token: "John C. Spiller, II" and "Michael Theron Smith, Jr" end in a surname (the
    // surname alias then did not extend over the given names, and "John [PERSON_3]" refused the filing, 2026-09-15)
    while (toks.length > 1 && /^(?:Jr|Sr|II|III|IV|Esq|PhD|MD|JD)$/i.test(toks[toks.length - 1])) toks.pop();
    multi.add(placeholder); (lastTokens.get(placeholder) ?? lastTokens.set(placeholder, new Set()).get(placeholder)!).add(toks[toks.length - 1].toLowerCase());
    for (let i = 1; i < toks.length - 1; i++) (tails.get(placeholder) ?? tails.set(placeholder, new Set()).get(placeholder)!).add(toks.slice(i).join(" ").toLowerCase());
    if (!HONORIFIC.test(toks[0]) && toks[0].length >= 3) (firstTokens.get(placeholder) ?? firstTokens.set(placeholder, new Set()).get(placeholder)!).add(toks[0].toLowerCase());
    // every token but the last -- a middle name glued to the surname ("Donnie LouSpeer") is absorbed too
    for (const t of toks.slice(0, -1)) if (t.length >= 2 && !HONORIFIC.test(t)) (innerTokens.get(placeholder) ?? innerTokens.set(placeholder, new Set()).get(placeholder)!).add(t.toLowerCase());
  }
  for (const { alias, placeholder, type } of subs) {
    // pdftotext merges columns: "STATE OF MICHIGANState of Texas", "VestaliaAttorney for Amegy". A name followed
    // directly by a Capital-lower word ends at the case change; found case-insensitively, then the two characters
    // after are checked case-sensitively
    // ...and an identifier glued to the next line's word the same way: "TX 78401You are requested", "75202Phone:"
    const glued = wordy(alias) ? [...text.matchAll(new RegExp(`${/\s/.test(alias.trim()) || /[\p{N}@]/u.test(alias) ? "" : LEFT_SINGLE}${flex(alias)}(?=\\p{L})`, "giu"))].filter((m) => /^\p{Lu}\p{Ll}/u.test(text.slice(m.index! + m[0].length, m.index! + m[0].length + 2)) && /[\p{L}\p{N}]$/u.test(m[0])) : [];
    const matches = [...text.matchAll(aliasRegex(alias)), ...camelMatches(text, alias), ...glued];
    for (const m of matches) {
      let start = m.index!; const end = start + m[0].length;
      if (inCaptionAt(text, start, end)) continue;
      const single = !/\s/.test(alias.trim());
      let right = end;
      const isTail = !single && (tails.get(placeholder)?.has(alias.trim().split(/\s+/).map((t) => t.replace(/[,.;:()"']/g, "")).join(" ").toLowerCase()) ?? false);
      // ...a single alias that is the node's own MIDDLE or FIRST token -- a nickname or a middle name ("Rudy" of
      // "Rodolfo Rudy Delgado") -- extends both ways too, else "Rodolfo [PERSON_1] Delgaldo" is left as a torn name
      const own = single && (innerTokens.get(placeholder)?.has(alias.trim().toLowerCase()) || firstTokens.get(placeholder)?.has(alias.trim().toLowerCase()));
      if (PERSON_TYPES.has(type) && own && !lastTokens.get(placeholder)?.has(alias.trim().toLowerCase())) {
        // a first- or middle-name alias walks only over the node's OWN tokens: left over its first/middle names, right
        // over its middle names and then its surname (exact, or one letter off the way the filing spells it). Never
        // over an arbitrary capitalised word -- the caps-caption extension took "NOW COMES TERRY" as a name.
        const tokOf = (t: string) => t.replace(/[.'’-]/g, "").toLowerCase();
        let ext = start, right = end;
        for (let k = 0; k < 3; k++) { const m = /(\p{L}[\p{L}'’.-]{0,20})[ \t]+$/u.exec(text.slice(Math.max(0, ext - 40), ext)); if (!m) break; const tok = tokOf(m[1]); if (!(firstTokens.get(placeholder)?.has(tok) || innerTokens.get(placeholder)?.has(tok))) break; ext -= m[0].length; }
        for (let k = 0; k < 3; k++) { const m = /^[ \t]+(\p{L}(?:[\p{L}'’-]|\.(?=\p{L}))+)(?![\p{L}])/u.exec(text.slice(right, right + 30)); if (!m) break; const tok = tokOf(m[1]); const inner = innerTokens.get(placeholder)?.has(tok) ?? false; const last = [...(lastTokens.get(placeholder) ?? [])].some((l) => l === tok || (l.length >= 6 && editDistance(l, tok) <= 1)); if (!inner && !last) break; right += m[0].length; if (last) break; }
        if (ext < start || right > end) all.push({ start: ext, end: right, placeholder });
      } else if (PERSON_TYPES.has(type) && (single ? (!multi.has(placeholder) || lastTokens.get(placeholder)?.has(alias.trim().toLowerCase())) : isTail)) {
        let ext = extendOverGivenNames(text, start);
        // a given name GLUED to the surname -- "JamesHunter", "TalalKaissi", "JosephSauder@..." (OCR and merged
        // columns) -- is absorbed when it is the node's own given name
        const before = /(\p{Lu}\p{Ll}{1,20})$/u.exec(text.slice(Math.max(0, start - 24), start));
        if (before && innerTokens.get(placeholder)?.has(before[1].toLowerCase()) && ext === start) ext = extendOverGivenNames(text, start - before[1].length);
        // "Gogineni Srinivasa": the node's own given name written after the surname is part of the same name
        const after = /^[ \t]+([A-Z][\p{L}'’-]{2,20})(?![\p{L}])/u.exec(text.slice(end, end + 30));
        if (after && firstTokens.get(placeholder)?.has(after[1].toLowerCase())) right = end + after[0].length;
        // the extended span is the first choice; if it overlaps a hit kept before it, the bare match still stands
        if (ext < start || right > end) all.push({ start: ext, end: right, placeholder });
      }
      all.push({ start, end, placeholder });
    }
  }
  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Hit[] = []; let cursor = 0;
  for (const h of all) { if (h.start >= cursor) { kept.push(h); cursor = h.end; } }
  return kept;
}

/** Levenshtein distance, for a surname the filing misspells by one letter. */
function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const d: number[] = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) { let prev = d[0]; d[0] = i; for (let j = 1; j <= b.length; j++) { const t = d[j]; d[j] = Math.min(d[j] + 1, d[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = t; } }
  return d[b.length];
}

/** Replace every alias in the graph with its placeholder, in one splice over the original text. */
/** One substitution as it happened: which placeholder replaced which exact original text, and where it sits in
 *  the OUTPUT. The ledger is what makes the document restore byte-exact (founder, 2026-09-15: "the swap back
 *  needs to be clean and seamless"); it is stored sealed with the matter and never enters a prompt. */
export type Occurrence = { placeholder: string; original: string; start: number; end: number };

/** `only` restricts the substitution to some node types: the model's pass-1 view is scrubbed of the regex-class
 *  identifiers alone, with every name left visible (lesson XXIII). */
export function scrambleWithLedger(text: string, graph: MatterGraph, only?: (type: EntityType) => boolean): { text: string; occurrences: Occurrence[] } {
  const h = hits(text, graph, only); if (!h.length) return { text, occurrences: [] };
  let out = ""; let pos = 0; const occurrences: Occurrence[] = [];
  for (const { start, end, placeholder } of h) {
    out += text.slice(pos, start);
    occurrences.push({ placeholder, original: text.slice(start, end), start: out.length, end: out.length + placeholder.length });
    out += placeholder; pos = end;
  }
  return { text: out + text.slice(pos), occurrences };
}
export function scramble(text: string, graph: MatterGraph, only?: (type: EntityType) => boolean): string { return scrambleWithLedger(text, graph, only).text; }

/** The DOCUMENT restore: every placeholder goes back to the exact bytes it replaced, by position. Nothing is
 *  looked up in the graph, nothing is guessed; a ledger that does not fit the text (edited after scrambling, or
 *  the wrong document) is an error, never a partial restore. */
export function restoreDocument(scrambled: string, occurrences: Occurrence[]): string {
  let out = ""; let pos = 0;
  for (const o of [...occurrences].sort((a, b) => a.start - b.start)) {
    if (o.start < pos || scrambled.slice(o.start, o.end) !== o.placeholder) throw new Error(`scrambler: ledger does not fit this text at ${o.start} (expected ${o.placeholder}); the document was edited after scrambling or the ledger is for another document`);
    out += scrambled.slice(pos, o.start) + o.original; pos = o.end;
  }
  return out + scrambled.slice(pos);
}

const HONORIFIC_BEFORE = /(?:^|\s)(?:Mr|Ms|Mrs|Mx|Dr|Prof|Judge|Justice|Hon|Officer|Sgt|Det|Capt|Lt)\.?\s+$/;
const SENTENCE_START = /(?:^|[.!?]\s+|\n\s*)$/;
/** The surname of a person's canonical name: the last capitalised token that is not a suffix or an honorific. */
export function surnameOf(canonical: string): string | null {
  const toks = canonical.replace(/[,;:()"]/g, " ").trim().split(/\s+/).filter((t) => /^\p{Lu}/u.test(t) && !HONORIFIC.test(t.replace(/\.$/, "")) && !/^(?:Jr|Sr|II|III|IV|Esq)\.?$/.test(t));
  return toks.length >= 2 ? toks[toks.length - 1] : null;
}

/** The ANSWER restore: the frontier wrote placeholders it never saw the referents of, and the text must read as
 *  a lawyer would write it. Rules, in order: a placeholder after an honorific renders as the SURNAME ("Mr.
 *  [CLIENT_1]" -> "Mr. Evans", never "Mr. Robert T. Evans"); the first mention of a person is the full canonical
 *  name and later mentions are the surname; an organisation is its canonical name first and its shortest defined
 *  term after ("SGL"); a possessive written by the frontier ("[CLIENT_1]'s") keeps its apostrophe; a sentence
 *  start is capitalised. Anything placeholder-shaped the graph does not know is left as-is and REPORTED, never
 *  guessed (unscramble() is the canonical-only restore and stays for callers that want no rendering). */
export function renderAnswer(answer: string, graph: MatterGraph): { text: string; unknown: string[] } {
  const canon = graph.restorations(); const unknown = new Set<string>();
  const typeOf = new Map<string, string>(); const shortOf = new Map<string, string>();
  for (const s of graph.substitutions()) {
    typeOf.set(s.placeholder, s.type);
    const cur = shortOf.get(s.placeholder); const a = s.alias.trim();
    // the shortest alias of an ORG that is a real name (3+ letters, capitalised, not the canonical) is its short form
    if (!PERSON_TYPES.has(s.type) && a.length >= 3 && /^\p{Lu}/u.test(a) && a !== canon.get(s.placeholder) && (!cur || a.length < cur.length)) shortOf.set(s.placeholder, a);
  }
  const seen = new Set<string>();
  let out = ""; let pos = 0;
  for (const m of answer.matchAll(/\[[A-Z]+_\d+\]/g)) {
    const ph = m[0]; const full = canon.get(ph);
    out += answer.slice(pos, m.index!); pos = m.index! + ph.length;
    if (full === undefined) { unknown.add(ph); out += ph; continue; }
    const person = PERSON_TYPES.has(typeOf.get(ph) ?? ""); const surname = person ? surnameOf(full) : null;
    let r: string;
    if (HONORIFIC_BEFORE.test(out)) r = surname ?? full.replace(/^(?:Mr|Ms|Mrs|Mx|Dr|Prof|Judge|Justice|Hon)\.?\s+/, "");
    else if (!seen.has(ph)) r = full;
    else r = person ? (surname ?? full) : (shortOf.get(ph) ?? full);
    seen.add(ph);
    if (SENTENCE_START.test(out) && /^\p{Ll}/u.test(r)) r = r[0].toUpperCase() + r.slice(1);
    // "Southwest Global Logistics, Inc." at the end of the frontier's sentence: one period, not "Inc.."
    if (r.endsWith(".") && answer[pos] === ".") r = r.slice(0, -1);
    out += r;
  }
  out += answer.slice(pos);
  for (const m of placeholderShapes(out)) if (!canon.has(m)) unknown.add(m);
  return { text: out, unknown: [...unknown] };
}

/** Anything shaped like a placeholder: exact ones and every near-miss an answer or a hostile document could
 *  carry — "[client_1]", "[ CLIENT_1 ]", "[CLIENT_1_2]", "[CLIENT-1]", "[[CLIENT_1]", "CLIENT_1]". */
// Only OUR type names count: a real filing carries "[AOI-1", "[Ex-2]", "[Fig-3]" as ordinary text, and the input gate
// refused three of forty real dockets over them (2026-09-15). A look-alike is a near-miss of a placeholder we mint.
const PH_TYPES = "(?:client|person|attorney|judge|org|address|phone|email|docket|dob|account|ssn|other)";
const FRAG = "[A-Z]{1,9}_\\d+";
export const PLACEHOLDER_LIKE = new RegExp(`\\[+\\s*(?:${FRAG}|${PH_TYPES}[_-]\\d+)(?:[_-]\\d+)*\\s*\\]+|\\[\\s*(?:${FRAG}|${PH_TYPES}[_-]\\d+)\\b(?!\\s*\\])|\\b(?:${FRAG}|${PH_TYPES}[_-]\\d+)\\s*\\]+|\\b${PH_TYPES.toUpperCase()}_\\d+\\b`, "g");
/** The same, case-insensitively for the type names only (the fragment shape is upper-case by definition). */
const PH_LOWER = new RegExp(`\\[+\\s*${PH_TYPES}[_-]\\d+(?:[_-]\\d+)*\\s*\\]+|\\[\\s*${PH_TYPES}[_-]\\d+\\b(?!\\s*\\])|\\b${PH_TYPES}[_-]\\d+\\s*\\]+`, "gi");
export function placeholderShapes(text: string): string[] { return [...new Set([...[...text.matchAll(PLACEHOLDER_LIKE)].map((m) => m[0]), ...[...text.matchAll(PH_LOWER)].map((m) => m[0])])]; }
/** A party role as a token of a name is not a fragment of the name ("Defendant [PERSON_8]" is prose). */
const ROLE_TOKEN = /^(?:Plaintiffs?|Defendants?|Respondents?|Petitioners?|Appellants?|Appellees?|Claimants?|Intervenors?|Movants?|Debtors?|Creditors?|Relators?|Garnishees?|Witness|Deponent|Affiant|Declarant|Applicant|Insureds?|Insurers?|Employers?|Employees?|Decedent|Testator|Trustee|Guardian|Executor|Administrator)$/i;
export const EXACT_PLACEHOLDER = /^\[[A-Z]+_\d+\]$/;
/** Editorial brackets around a placeholder — "[[PERSON_2]]" from a quotation's "[Bryant]" — are ordinary legal
 *  prose and restore cleanly; they are not look-alikes. Footnote markers "[2]" and section pins "§ 2]" are not
 *  either: the first gate refused three real opinions over them (oracle run, 2026-09-15). */
const BRACKETED_EXACT = /\[\[[A-Z]+_\d+\]\]/g;

/** Restore placeholders in a frontier answer from the graph. Exact placeholders the graph knows are restored;
 *  anything placeholder-shaped that is not exactly known — an unknown number, a near-miss spelling, a nested
 *  bracket — is left as-is AND reported. An unknown placeholder in an answer is either a model hallucinating an
 *  entity or an injection trying to mint one; both are defects to count, never to guess at. */
export function unscramble(answer: string, graph: MatterGraph): { text: string; unknown: string[] } {
  const map = graph.restorations(); const unknown = new Set<string>();
  // exact placeholders first, so "[[CLIENT_1]]" restores its inner placeholder and leaves the outer brackets
  // (red-team 8a); only then is whatever is still placeholder-shaped reported as a near-miss.
  let text = answer.replace(/\[[A-Z]+_\d+\]/g, (m) => { const r = map.get(m); if (r === undefined) { unknown.add(m); return m; } return r; });
  for (const m of placeholderShapes(text)) if (!map.has(m)) unknown.add(m);
  return { text, unknown: [...unknown] };
}

/** Accepted aliases still present in the output, case-insensitively and as substrings — stricter than the
 *  substitution itself on purpose: an alias glued to a letter ("exhibitJohn Doe") is not substituted, because the
 *  word boundary says it is not the name, and it is still a leak, so the gate must see it. */
export function residualAliases(scrambled: string, graph: MatterGraph): string[] {
  const out: string[] = [];
  // Placeholders are not text. The alias "Phone" was found inside "[PHONE_1]" and the alias "Client" would be
  // found inside "[CLIENT_1]" (live battery doc 2-3, 2026-09-15): the search is case-insensitive on purpose, so
  // the placeholders are blanked to same-length filler before it runs. Offsets are unchanged.
  const masked = scrambled.replace(/\[[A-Z]+_\d+\]/g, (m) => "\u0001".repeat(m.length));
  const present = (needle: string) => {
    // a multi-word name needs no LEFT boundary (glued "exhibitJohn Doe" is a leak) but always a RIGHT boundary
    // ("Dоeville" is a different word); a single-token alias needs both, or "Town" is found inside "BAYTOWN"
    // ...but an identifier-shaped alias (digits, "@") glued to letters — "SSN123-45-6789" — is still the identifier
    const left = !/\s/.test(needle.trim()) && /^[\p{L}.'’-]+$/u.test(needle.trim()) ? LEFT_SINGLE : LEFT_MULTI;
    const re = new RegExp(`${left}${flex(needle)}(?![\\p{L}\\p{N}])`, "giu");
    for (const m of masked.matchAll(re)) if (!inCaptionAt(scrambled, m.index!, m.index! + m[0].length)) return true;
    for (const m of camelMatches(masked, needle)) if (!inCaptionAt(scrambled, m.index!, m.index! + m[0].length)) return true;
    return false;
  };
  for (const { alias, type, placeholder } of graph.substitutions()) {
    if (present(alias)) { out.push(alias); continue; }
    // A FRAGMENT of a person's name left touching a placeholder is a partial substitution — "Maria [OTHER_1]",
    // "exhibitJohn [CLIENT_1]" — and leaks the rest of the name (red-team 3c, 9b). Only adjacency counts: the same
    // token elsewhere ("John Doeville", "Texas Rules of Civil Procedure") is a different word and stays.
    // ...and only beside the alias's OWN placeholder: "Ted [PERSON_9]" is a fragment of "Ted Hardie" only when
    // [PERSON_9] IS Hardie. On a real docket (2026-09-15) a different Ted next to another person's placeholder
    // refused a filing that had no fragment in it.
    // ...and only for an alias shaped like a person's name (every token capitalised, no digits): "HomeLink mirror"
    // is a defined product term, and its first word next to a placeholder is not a torn name
    if (PERSON_TYPES.has(type) && alias.trim().split(/\s+/).every((w) => /^\p{Lu}/u.test(w) && !/\d/.test(w))) {
      const ph = esc(placeholder);
      for (const tok of alias.replace(/[,.;:()"']/g, " ").split(/\s+/)) {
        if (tok.length < 3 || !/^\p{Lu}/u.test(tok) || HONORIFIC.test(tok) || ROLE_TOKEN.test(tok)) continue;
        const t = esc(tok);
        // same line only: "[ATTORNEY_10]\n      WATTS, GUERRA CRAFT" is the firm on the next line, not a fragment
        // a whole token on the near side: "sold [PERSON_2]" is not the fragment "Old" (2026-09-15)
        if (new RegExp(`(?<![\\p{L}\\p{N}])${t}[ \\t]*${ph}|${ph}[ \\t]*${t}(?![\\p{L}\\p{N}])`, "iu").test(scrambled)) { out.push(alias); break; }
      }
    }
  }
  return out;
}

/** Placeholder-shaped tokens in the output that are NOT exact placeholders. A document that carries "[CLIENT_1]]"
 *  or "CLIENT_1" literally could confuse the frontier or the un-scramble step, so the release gate refuses it. */
export function placeholderLookalikes(scrambled: string): string[] {
  // Editorial brackets are legal-prose punctuation: "[of economic development]" became "[of [OTHER_39]]" on a
  // real opinion (24-0102, 2026-09-15) and the tail "[OTHER_39]]" read as a malformed placeholder. An exact
  // placeholder with extra brackets on either side can only arise from substituting INSIDE brackets, provided the
  // raw input carried no look-alike -- which the input gate in index.ts now guarantees. So on output, strip
  // every exact placeholder together with any brackets hugging it before looking for near-misses.
  const t = scrambled.replace(/\[*\[[A-Z]+_\d+\]\]*/g, " ");
  // bracket-shaped near-misses are found on the text as-is ("[CLIENT_1]]", "[[CLIENT_1]"); bare-token shapes
  // ("CLIENT_1", "T_1]") only once exact placeholders are removed, or every real placeholder would match itself
  // (our type names only -- see PLACEHOLDER_LIKE: "[AOI-1]" is a filing's own text)
  return placeholderShapes(t);
}

/** The INPUT gate: anything placeholder-shaped in the raw document is either an attack on the mapping or a
 *  collision we cannot tell from one, and the document is refused before any model sees it. Every exact
 *  placeholder shape counts here too -- a raw document has no business containing "[CLIENT_1]". */
export function inputLookalikes(raw: string): string[] {
  // the same type-name rule as PLACEHOLDER_LIKE: "[AOI-1]" in a filing is text, "[client-1]" is an attack
  return placeholderShapes(raw);
}
