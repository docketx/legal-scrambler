// Input normalisation — fold the input BEFORE anything else sees it, so a variant spelling of a name cannot
// exist in the document at all. Adopted from the five-model doc review 2026-09-15 (item 3, "New, and adopted"):
// "NFKC-normalise before matching ... fold confusables and zero-width characters on the way in." The red-team
// (`scrambler-redteam` 1a-1d, 2a-2e) already shows the pipeline is SAFE against these variants once they reach
// the model/guard; this module removes the class of variant before that, so the ledger records what was folded
// instead of the guard having to reason about it downstream.
//
// Deliberately narrow, same discipline as patterns.ts: this module changes ONLY characters that are invisible,
// typographically-equivalent, or Latin-look-alike-when-mixed-with-Latin. It must never touch line breaks,
// ordinary punctuation, or genuine non-Latin text — a real Cyrillic or Greek word has no Latin letters in it and
// is left untouched by construction (the homoglyph map only fires token-by-token, and only on a token that also
// contains a plain Latin letter).

/** Zero-width and invisible format characters: word joiners, directional marks, BOM, soft hyphen. These carry no
 *  visible content and exist in a document only to break a naive substring match (red-team 1c). */
const INVISIBLE = /[​-‏⁠-⁤﻿­]/g;

/** Cyrillic and Greek letters that are visually identical (or near-identical) to a Latin letter, keyed by the
 *  confusable -> its Latin target. Deliberately small: only the letters that are actually confusable with a bare
 *  eye, not the full Unicode confusables table. Mixed case, because a caption spells names both ways
 *  (red-team 2b). */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
  // Greek
  "α": "a", "ο": "o", "ρ": "p", "υ": "y", "ι": "i", "ν": "v",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
  "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
};
const HOMOGLYPH_RE = new RegExp(`[${Object.keys(HOMOGLYPHS).join("")}]`, "g");
const HAS_LATIN = /[A-Za-z]/;
const HAS_CONFUSABLE = new RegExp(`[${Object.keys(HOMOGLYPHS).join("")}]`);
/** A "token" for the mixed-script guard: a run of letters (any script) plus the marks/apostrophes that make up a
 *  name, so "Jоhn" and "Dоe" are each examined as a unit rather than the whole document at once. This is what
 *  keeps "Москва" (all Cyrillic, no Latin letter anywhere in the token) untouched while still folding "Jоhn". */
const TOKEN_RE = /[\p{L}\p{M}'’]+/gu;

/** Typographic apostrophes/quotes -> ASCII. NBSP -> ordinary space. Neither is a security fold (nothing here
 *  makes two strings collide that shouldn't); both are display noise the ledger should not have to distinguish
 *  from a real punctuation choice in the document. */
const QUOTES: [RegExp, string][] = [
  [/[‘’‚′]/g, "'"],
  [/[“”„″]/g, '"'],
];
const NBSP = /\u00a0/g;

export type NormalizeResult = { text: string; changed: number; kinds: Record<string, number> };

function bump(kinds: Record<string, number>, kind: string, n = 1): void {
  if (n <= 0) return;
  kinds[kind] = (kinds[kind] ?? 0) + n;
}

/** Fold NBSP + NFKC + strip invisibles + fold mixed-script homoglyphs + straighten quotes. Never touches line
 *  breaks or ordinary punctuation. Returns the folded text and a count of what changed, by kind, so the ledger
 *  can record what was folded on the way in (same spirit as the rejection-reason counts in guard.ts). */
export function normalizeInput(text: string): NormalizeResult {
  const kinds: Record<string, number> = {};
  let changed = 0;

  // 1. NBSP -> ordinary space, BEFORE NFKC: NFKC's own compatibility decomposition already folds U+00A0 to a
  // regular space, so doing this first is what lets the ledger count it under "nbsp" instead of the fold
  // vanishing into the generic "nfkc" count below.
  let out = text.replace(NBSP, () => {
    bump(kinds, "nbsp");
    changed += 1;
    return " ";
  });

  // 2. NFKC: folds fullwidth forms, ligatures (ﬁ -> fi), and other compatibility variants. Does not touch
  // line breaks or ASCII punctuation.
  const nfkc = out.normalize("NFKC");
  if (nfkc !== out) {
    // Count in code-point terms so a multi-char expansion (a ligature -> two letters) is still "one fold".
    const before = Array.from(out), after = Array.from(nfkc);
    const n = before.length === after.length
      ? before.reduce((acc, ch, i) => acc + (ch === after[i] ? 0 : 1), 0)
      : Math.max(1, Math.abs(before.length - after.length));
    bump(kinds, "nfkc", n);
    changed += n;
  }
  out = nfkc;

  // 3. Invisible / zero-width format characters: removed outright.
  out = out.replace(INVISIBLE, () => {
    bump(kinds, "invisible");
    changed += 1;
    return "";
  });

  // 4. Mixed-script homoglyphs, token by token: only fold a confusable letter when its OWN token also contains
  // a plain Latin letter, so a genuine non-Latin word is never touched.
  out = out.replace(TOKEN_RE, (token) => {
    if (!HAS_CONFUSABLE.test(token) || !HAS_LATIN.test(token)) return token;
    const folded = token.replace(HOMOGLYPH_RE, (ch) => {
      bump(kinds, "homoglyph");
      changed += 1;
      return HOMOGLYPHS[ch];
    });
    return folded;
  });

  // 5. Typographic quotes/apostrophes -> ASCII.
  for (const [re, rep] of QUOTES) {
    out = out.replace(re, () => {
      bump(kinds, "quote");
      changed += 1;
      return rep;
    });
  }

  return { text: out, changed, kinds };
}

/** Cheap predicate: does this text contain anything normalizeInput would change? Used to gate the (slightly
 *  more expensive) full fold, or to flag a document for the ledger without folding it. */
export function hasConfusables(text: string): boolean {
  if (text.normalize("NFKC") !== text) return true;
  INVISIBLE.lastIndex = 0;
  const invisible = INVISIBLE.test(text);
  INVISIBLE.lastIndex = 0;
  if (invisible) return true;
  for (const m of text.matchAll(TOKEN_RE)) {
    const token = m[0];
    if (HAS_CONFUSABLE.test(token) && HAS_LATIN.test(token)) return true;
  }
  if (/[‘’‚′“”„″ ]/.test(text)) return true;
  return false;
}
