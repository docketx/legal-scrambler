import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeInput, hasConfusables } from "../src/normalize";

/* Input normalisation — fold confusable spellings on the way IN, before the regex pass, the local model, or the
 * guard ever see the document. Adopted from the five-model doc review 2026-09-15 ("New, and adopted", item 3):
 * NFKC + confusable folding removes the class of variant the red-team (scrambler-redteam 1/2) shows the
 * pipeline is otherwise safe against downstream. This file only exercises normalize.ts in isolation — it is not
 * wired into index.ts here. See docs/SCRAMBLER.md and docs/SCRAMBLER-REVIEW-2026-09-15.md. */

test("Cyrillic homoglyph: 'Jоhn Dоe' (Cyrillic o) folds to plain 'John Doe'", () => {
  const cyr = "Jоhn Dоe"; // Cyrillic о (U+043E) in both words
  const r = normalizeInput(`Plaintiff ${cyr} sued.`);
  assert.ok(r.text.includes("John Doe"), r.text);
  assert.ok(!r.text.includes(cyr), r.text);
  assert.ok(r.changed > 0);
  assert.ok(r.kinds.homoglyph >= 2, JSON.stringify(r.kinds));
});

test("zero-width: 'John\\u200BDoe' becomes 'JohnDoe' — the zero-width char is removed, not preserved as a boundary", () => {
  const doc = "John​Doe";
  const r = normalizeInput(doc);
  assert.equal(r.text, "JohnDoe");
  assert.ok(r.kinds.invisible >= 1);
  // Once folded, this is indistinguishable from a document that always said "JohnDoe" as one word — a
  // downstream in-input check (guard.ts's inputHas) will treat it as a single token, not two names glued
  // together with a hidden separator. That collapse is intended: the alternative is leaving the zero-width
  // character in place, which is exactly the evasion this module exists to remove.
});

test("genuine Cyrillic word is untouched: 'Москва' has no Latin letters in its token, so the homoglyph map never fires", () => {
  const doc = "Москва"; // Москва
  const r = normalizeInput(doc);
  assert.equal(r.text, doc);
  assert.equal(r.changed, 0);
  assert.deepEqual(r.kinds, {});
});

test("typographic apostrophe: \"O\\u2019Brien\" -> \"O'Brien\" (ASCII)", () => {
  const r = normalizeInput("Pat O’Brien filed a reply.");
  assert.ok(r.text.includes("O'Brien"), r.text);
  assert.ok(!r.text.includes("O’Brien"), r.text);
  assert.ok(r.kinds.quote >= 1);
});

test("NBSP collapses to an ordinary space", () => {
  const r = normalizeInput("John Doe");
  assert.equal(r.text, "John Doe");
  assert.ok(r.kinds.nbsp >= 1);
});

test("NFKC folds fullwidth 'Ｊｏｈｎ' to 'John' and the 'ﬁ' ligature to 'fi'", () => {
  const fullwidth = "Ｊｏｈｎ"; // fullwidth J o h n
  const r1 = normalizeInput(fullwidth);
  assert.equal(r1.text, "John");
  assert.ok(r1.kinds.nfkc >= 1);

  const r2 = normalizeInput("a deﬁciency letter"); // "deﬁciency"
  assert.equal(r2.text, "a deficiency letter");
  assert.ok(r2.kinds.nfkc >= 1);
});

test("line breaks are preserved exactly", () => {
  const doc = "Plaintiff John’s counsel appeared.\n\nORDER.\nThe motion is denied.\n";
  const r = normalizeInput(doc);
  assert.equal((r.text.match(/\n/g) ?? []).length, (doc.match(/\n/g) ?? []).length);
  assert.equal(r.text, "Plaintiff John's counsel appeared.\n\nORDER.\nThe motion is denied.\n");
});

test("an all-ASCII document is returned unchanged: changed=0 and the identical string", () => {
  const doc = "Plaintiff John Doe sued Acme Widgets, Inc. Docket No. 24-CV-1234. See Smith v. Jones, 100 S.W.2d 1 (Tex. 1937).";
  const r = normalizeInput(doc);
  assert.equal(r.changed, 0);
  assert.equal(r.text, doc);
  assert.deepEqual(r.kinds, {});
  assert.equal(hasConfusables(doc), false);
});

test("idempotence: normalizing twice equals normalizing once", () => {
  const doc = `Plaintiff Jоhn Dоe (Pat O’Brien counsel) sued Ａcme, and deﬁciency notice ` +
    `was mailed.\nJohn​Doe replied.`;
  const once = normalizeInput(doc);
  const twice = normalizeInput(once.text);
  assert.equal(twice.text, once.text);
  assert.equal(twice.changed, 0);
  assert.deepEqual(twice.kinds, {});
});

test("hasConfusables is true for a document normalizeInput would change, false for an already-clean one", () => {
  assert.equal(hasConfusables("plain ascii text, nothing to fold."), false);
  assert.equal(hasConfusables("Jоhn Doe"), true);
  assert.equal(hasConfusables("John​Doe"), true);
  assert.equal(hasConfusables("Москва"), false);
});
