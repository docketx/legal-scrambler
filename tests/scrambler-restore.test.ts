import { test } from "node:test";
import assert from "node:assert/strict";
import { MatterGraph, scrambleDocument, finalizeChunksWithLedger, restoreDocument, renderAnswer, unscramble } from "../src";
import { loadBattery, asType } from "../src/battery";
import { paragraphs } from "../src/measure";

/* THE SWAP-BACK (founder, 2026-09-15: "the swap back needs to be clean and seamless"). Two restores, two proofs:
 *   the DOCUMENT restores BYTE-EXACT from the ledger -- "Bob", "Mr. Evans", "EVANS", "employeeVance's", a name
 *   wrapped across a line, editorial brackets, a glued name -- every surface form comes back as it was;
 *   the frontier's ANSWER renders the way a lawyer writes: full name on first mention, surname after, surname
 *   after an honorific, the frontier's own possessive kept, a sentence start capitalised, an unknown placeholder
 *   reported and never guessed. */

const DOC = "Plaintiff Robert T. Evans (“Bob” or “Mr. Evans”) sued Southwest Global Logistics, Inc. (“SGL” or the “Company”).\nEVANS objected; Bob left. Mr. Evans's counsel, Maria\nSalinas, filed. The memo references employeeEvans's bonus. [Salinas] testified. See Young v. State, 725 S.W.2d 705 (Tex. Crim. App. 1987).";
const model = async (p: string) => p.includes("auditing") ? JSON.stringify({ leaks: [], inconsistent: [] })
  : JSON.stringify({ spans: [{ text: "Robert T. Evans", type: "CLIENT" }, { text: "Southwest Global Logistics, Inc.", type: "ORG" }, { text: "Maria Salinas", type: "ATTORNEY" }], coref: {} });

test("the document restores byte-exact from the ledger: every surface form, wrapped names, brackets, glued names", async () => {
  const g = new MatterGraph("m");
  const r = await scrambleDocument(DOC, g, model);
  for (const s of ["Evans", "Bob", "SGL", "Salinas", "EVANS"]) assert.ok(!new RegExp(`(?<![A-Za-z_])${s}(?![A-Za-z_])`).test(r.scrambled), `${s} survived:\n${r.scrambled}`);
  assert.ok(r.occurrences.length >= 8, `ledger has ${r.occurrences.length} entries`);
  for (const o of r.occurrences) assert.equal(r.scrambled.slice(o.start, o.end), o.placeholder, "every ledger entry points at its placeholder");
  assert.equal(r.restore_basis, "raw", "typographic quotes alone keep the raw basis");
  assert.equal(restoreDocument(r.scrambled, r.occurrences), DOC, "byte-exact");
  // the canonical restore is NOT byte-exact, by design -- that is what the ledger is for
  assert.notEqual(unscramble(r.scrambled, g).text, DOC);
});

test("a ledger that does not fit the text is an error, never a partial or guessed restore", async () => {
  const g = new MatterGraph("m");
  const r = await scrambleDocument(DOC, g, model);
  const edited = r.scrambled.replace("[CLIENT_1]", "[CLIENT_1] (edited)");
  assert.throws(() => restoreDocument(edited, r.occurrences), /ledger does not fit/);
  assert.throws(() => restoreDocument("some other text entirely", r.occurrences), /ledger does not fit/);
});

test("the answer renders the way a lawyer writes it: full name first, surname after, surname after an honorific, possessive kept, sentence start capitalised", async () => {
  const g = new MatterGraph("m");
  await scrambleDocument(DOC, g, model);
  const answer = "[CLIENT_1] moved to dismiss; Mr. [CLIENT_1]'s motion cites [ORG_1]. [CLIENT_1] argued that [ORG_1] and [ORG_1]'s parent are one. Dr. [ATTORNEY_1] disagreed. [PERSON_9] is not in the record. [CLIENT_1] prevailed.";
  const r = renderAnswer(answer, g);
  assert.equal(r.text, "Robert T. Evans moved to dismiss; Mr. Evans's motion cites Southwest Global Logistics, Inc. Evans argued that SGL and SGL's parent are one. Dr. Salinas disagreed. [PERSON_9] is not in the record. Evans prevailed.");
  assert.deepEqual(r.unknown, ["[PERSON_9]"]);
  // a near-miss the frontier mangled is reported too, and left alone
  const r2 = renderAnswer("[client_1] and [CLIENT_1_2] and CLIENT_1] appear", g);
  assert.ok(r2.unknown.length >= 2, JSON.stringify(r2.unknown)); assert.ok(r2.text.includes("[client_1]"));
});

test("the whole battery restores byte-exact through chunking and the cross-chunk final pass (oracle spans)", async () => {
  const docs = loadBattery().slice(0, Number(process.env.SCRAMBLER_RESTORE_DOCS ?? 60));
  let checked = 0; let normalizedBasis = 0;
  for (const d of docs) {
    const g = new MatterGraph(`restore-${d.id}`); const text = d.text.slice(0, 60_000); const chunks = paragraphs(text, 4000, 200);
    const oracle = async (p: string) => p.includes("auditing") ? JSON.stringify({ leaks: [], inconsistent: [] }) : JSON.stringify({ spans: d.secrets.map((s) => ({ text: s.text, type: asType(s.type) })), coref: {} });
    try { for (const c of chunks) await scrambleDocument(c, g, oracle); } catch { continue; }
    const finals = finalizeChunksWithLedger(chunks, g);
    for (let i = 0; i < chunks.length; i++) {
      // raw basis: the chunk's own bytes. normalized basis (invisible or confusable characters in the input):
      // exact to the folded text, and the result says so
      const { normalizeInput } = await import("../src/normalize");
      const expected = finals[i].basis === "raw" ? chunks[i] : normalizeInput(chunks[i]).text;
      assert.equal(restoreDocument(finals[i].text, finals[i].occurrences), expected, `${d.id} chunk ${i} not byte-exact (${finals[i].basis})`);
      if (finals[i].basis === "normalized") normalizedBasis++;
    }
    checked++;
  }
  assert.ok(checked > 0);
  console.log(`  restore byte-exact on ${checked} battery documents (${normalizedBasis} chunk(s) on the normalized basis)`);
});
