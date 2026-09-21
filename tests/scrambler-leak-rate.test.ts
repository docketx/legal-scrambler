import { test } from "node:test";
import assert from "node:assert/strict";
import { namePresent, usableNames, score, summarize, paragraphs, isTransportFailure, wilson, capitalisedPhrases } from "../src/measure";

/* The measurement has to be right before the number it produces means anything. These pin the definition of
 * "leaked" (whole word, case-insensitive, whitespace-tolerant — the scrambler's own residual standard), what counts
 * as a ground-truth name (a real name from a human-audited redaction_map, never a tag, never a citation), and that
 * the per-1,000 figure is computed over names actually PRESENT in the input — a map can name a party the opinion
 * text never spells out, and counting those as "not leaked" would flatter the result. */

const MAP = { "[A]": "Texas Department of State Health Services", "[B]": "Dr. Jennifer A. Shuford", "[Justice]": "Evan A. Young", "[X]": "[Non-participating Justice]", "[C]": "725 S.W.2d 705", "[D]": "" };

test("usable ground-truth names exclude tags, citations and empties", () => {
  assert.deepEqual(usableNames(MAP).sort(), ["Dr. Jennifer A. Shuford", "Evan A. Young", "Texas Department of State Health Services"]);
  assert.deepEqual(usableNames(undefined), []);
});

test("namePresent is whole-word, case-insensitive and line-wrap tolerant", () => {
  assert.equal(namePresent("Justice EVAN A. YOUNG delivered", "Evan A. Young"), true);
  assert.equal(namePresent("Justice Evan A.\nYoung delivered", "Evan A. Young"), true);
  assert.equal(namePresent("Youngstown is a city", "Young"), false, "a longer word is not the name");
  assert.equal(namePresent("[JUDGE_1] delivered", "Evan A. Young"), false);
});

test("score counts leaks only among names present in the input, and notices a destroyed citation", () => {
  const input = "Evan A. Young wrote. Shuford appealed. See 725 S.W.2d 705 and 826 S.W.2d 141.";
  const names = ["Evan A. Young", "Dr. Jennifer A. Shuford", "Nobody Named Here"];
  const out = "[JUDGE_1] wrote. Shuford appealed. See 725 S.W.2d 705 and [OTHER_1].";
  const r = score("23-0887", input, out, names, 1200);
  assert.equal(r.ground_truth, 3);
  assert.equal(r.present_in_input, 1, "only the judge's full name occurs verbatim; 'Shuford' alone is not the map's 'Dr. Jennifer A. Shuford'");
  assert.equal(r.leaked, 0);
  assert.equal(r.citations_in, 2); assert.equal(r.citations_lost, 1, "826 S.W.2d 141 was scrubbed — a defect the report must show");
});

test("summarize gives leaked per 1,000 present names, null when nothing was present", () => {
  const a = score("a", "John Doe and Jane Roe.", "[CLIENT_1] and Jane Roe.", ["John Doe", "Jane Roe"], 10);
  const b = score("b", "Ann Lee sued.", "[PERSON_1] sued.", ["Ann Lee"], 10);
  const s = summarize([a, b], 1, 0);
  assert.equal(s.entities, 3); assert.equal(s.leaked, 1); assert.equal(s.per_1000, 333.3); assert.equal(s.refused, 1);
  assert.equal(summarize([], 0, 0).per_1000, null);
});

test("paragraphs splits on blank lines under the cap and never drops text", () => {
  const p = "A".repeat(100) + "\n\n" + "B".repeat(100) + "\n\n" + "C".repeat(100);
  const parts = paragraphs(p, 220);
  assert.equal(parts.length, 2); assert.equal(parts.join("\n\n").replace(/\n/g, ""), p.replace(/\n/g, ""));
  const long = ("Sentence one. ").repeat(50).trim();
  const lp = paragraphs(long, 200);
  assert.ok(lp.length > 1 && lp.every((x) => x.length <= 200)); assert.equal(lp.join(" ").length, long.length);
});

test("a name that survives ONLY inside a cited-case caption is reported as caption_only, not as a leak", () => {
  const input = "Bell Helicopter Textron Inc. made the part. See Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249, 257 (Ct. App. 2003).";
  const out = "[ORG_1] made the part. See Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249, 257 (Ct. App. 2003).";
  const r = score("x", input, out, ["Bell Helicopter Textron Inc."], 5);
  assert.equal(r.leaked, 0); assert.equal(r.caption_only, 1);
  const bad = score("y", input, input, ["Bell Helicopter Textron Inc."], 5);
  assert.equal(bad.leaked, 1, "the body occurrence surviving IS a leak");
});

test("occurrence-level: a name appearing fifty times weighs fifty, not one", () => {
  const input = "Ann Lee sued. " + "Ann Lee lost. ".repeat(49) + "Bob Ray watched.";
  const out = "[PERSON_1] sued. " + "[PERSON_1] lost. ".repeat(47) + "Ann Lee lost. Ann Lee lost. Bob Ray watched.";
  const r = score("o", input, out, ["Ann Lee", "Bob Ray"], 1);
  assert.equal(r.present_in_input, 2); assert.equal(r.leaked, 2, "name-level: both names survive somewhere");
  assert.equal(r.occurrences_in_input, 51, "50 of Ann Lee plus 1 of Bob Ray");
  assert.equal(r.occurrences_leaked, 3, "2 of 50 Ann Lee plus 1 of 1 Bob Ray");
  const s = summarize([r], 0, 0);
  assert.equal(s.per_1000, 1000, "name-level says everything leaked");
  assert.equal(s.leaked_occurrences_per_1000, 58.8, "occurrence-level says 3 of 51");
  assert.equal(s.occurrences, 51); assert.equal(s.leaked_occurrences, 3);
});

test("occurrence-level ignores cited-case captions, as the name-level does", () => {
  const input = "Bell Helicopter Textron Inc. made it. See Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249, 257 (Ct. App. 2003).";
  const out = "[ORG_1] made it. See Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249, 257 (Ct. App. 2003).";
  const r = score("c", input, out, ["Bell Helicopter Textron Inc."], 1);
  assert.equal(r.occurrences_in_input, 1); assert.equal(r.occurrences_leaked, 0);
});

test("wilson 95% interval per 1,000: 2 of 12 by hand, 0 of n has a zero floor, null on an empty denominator", () => {
  // p = 1/6, z = 1.96: centre (p + z^2/2n) / (1 + z^2/n) = 0.2475, half-width 0.2005 -> [0.0470, 0.4480]
  assert.deepEqual(wilson(2, 12), [47.0, 448.0]);
  const zero = wilson(0, 66)!;
  assert.equal(zero[0], 0); assert.equal(zero[1], 55.0, "0 of 66 is not 'zero': the upper bound is what the sample can promise");
  assert.equal(wilson(0, 0), null);
  const s = summarize([score("a", "John Doe and Jane Roe.", "[CLIENT_1] and Jane Roe.", ["John Doe", "Jane Roe"], 1)], 0, 0);
  assert.deepEqual(s.per_1000_ci, wilson(1, 2)); assert.deepEqual(s.leaked_occurrences_per_1000_ci, wilson(1, 2));
  assert.equal(summarize([], 0, 0).per_1000_ci, null); assert.equal(summarize([], 0, 0).leaked_occurrences_per_1000_ci, null);
});

test("over-scrub proxy: capitalised phrases that vanished and were not names, citations or sentence starts", () => {
  const input = "The Supreme Court of Texas heard it. Evan A. Young wrote for the Court. Justice Young cited Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249. The Texas Rules of Civil Procedure apply. Rule 91a governs.";
  const names = ["Evan A. Young"];
  const phrases = capitalisedPhrases(input, names);
  assert.ok(phrases.includes("Supreme Court"), "sentence-initial 'The' is dropped, the run continues");
  assert.ok(phrases.includes("Texas Rules") && phrases.includes("Civil Procedure"), "a lowercase 'of' splits the run: " + JSON.stringify(phrases));
  assert.ok(phrases.includes("Bell Helicopter Textron Inc."), "a cited party is a phrase; it stays in the output by design so it is never a candidate");
  assert.deepEqual(capitalisedPhrases("DELIVERED: May 16, 2025, and Facebook, Inc. v. Smith is cited."), ["Facebook, Inc."], "a phrase is the input's own slice: a colon ends a run, a comma stays inside one");
  assert.ok(!phrases.some((p) => p.includes("Evan")), "the ground-truth name is not a candidate");
  assert.ok(!phrases.some((p) => p.includes("Young")), "a phrase sharing the surname is the scrambler's derived alias, not an over-scrub");
  assert.ok(!phrases.some((p) => /Cal\. Rptr/.test(p)), "a citation is not a candidate");
  // over-scrubbed: "Supreme Court", "Texas Rules" and "Civil Procedure" gone; correctly scrubbed: the judge. Citation intact.
  const over = "[ORG_1] of Texas heard it. [JUDGE_1] wrote for the Court. Justice [JUDGE_1] cited Hiser v. Bell Helicopter Textron Inc., 4 Cal. Rptr. 3d 249. The [ORG_2] apply. Rule 91a governs.";
  const r = score("p", input, over, names, 1);
  assert.equal(r.over_scrub_candidates, 3, JSON.stringify(phrases));
  assert.equal(r.phrases_in_input, phrases.length);
  const clean = score("q", input, input.replace(/Evan A\. Young/g, "[JUDGE_1]").replace(/Justice Young/g, "Justice [JUDGE_1]"), names, 1);
  assert.equal(clean.over_scrub_candidates, 0, "a scrub that only removed the name over-scrubbed nothing");
  assert.equal(clean.citations_lost, 0, "the citation-survival metric is untouched by the proxy");
  assert.equal(summarize([r, clean], 0, 0).over_scrub_candidates, 3);
});

test("paragraphs with overlap: consecutive chunks share exactly `overlap` chars, no text is lost, default unchanged", () => {
  const text = Array.from({ length: 8 }, (_, i) => `Paragraph ${i} ` + "x".repeat(90)).join("\n\n");
  const plain = paragraphs(text, 250);
  assert.deepEqual(paragraphs(text, 250, 0), plain, "overlap 0 is the old behaviour");
  const parts = paragraphs(text, 250, 50);
  assert.ok(parts.length > 2);
  for (const p of parts) assert.ok(p.length <= 250, "no chunk exceeds max, overlap included");
  const bases = parts.map((p, i) => (i === 0 ? p : p.slice(50)));
  for (let i = 1; i < parts.length; i++) assert.equal(parts[i].slice(0, 50), bases[i - 1].slice(-50), `chunk ${i} starts with the last 50 chars of the chunk before it`);
  assert.equal(bases.join("\n\n"), text, "stripping the shared prefixes reproduces the input exactly");
});

test("a transport failure is not a model failure: it is classified so the harness can exclude the opinion from the rate", () => {
  for (const r of ["pass1 attempt 1: fetch failed", "pass1 attempt 2: The operation was aborted due to timeout", "pass1 attempt 1: liaison 502"])
    assert.equal(isTransportFailure(r), true, r);
  for (const r of ["pass1 attempt 1: unparseable proposal (11995 chars)", "pass1: output truncated at 11995 chars, 30 complete span(s) salvaged", "no local model: regex-only"])
    assert.equal(isTransportFailure(r), false, r);
  assert.equal(summarize([], 0, 0, 3).excluded_transport, 3);
});

test("paragraphs never cuts a reporter citation wrapped across a blank line (the fifth proof run's two lost citations, 2026-09-16)", () => {
  const a = "A para.\n\nSee Rodriguez v. Christus Spohn Health Sys. Corp., 628 F.3d\n\n731, 737 (5th Cir. 2010).\n\nNext para.";
  assert.ok(paragraphs(a, 40).some((c) => c.includes("628 F.3d\n\n731, 737")), JSON.stringify(paragraphs(a, 40)));
  const b = "S. Pine Helicopters, Inc. v. Phoenix Aviation Managers, Inc., 320\n\nF.3d 838, 841 (8th Cir. 2003).";
  assert.ok(paragraphs(b, 40).some((c) => c.includes("320\n\nF.3d 838")), JSON.stringify(paragraphs(b, 40)));
  // a page number before a numbered heading is not a citation and still splits
  assert.deepEqual(paragraphs("Page 1 of 6\n\n1. Intro.", 12), ["Page 1 of 6", "1. Intro."]);
});
