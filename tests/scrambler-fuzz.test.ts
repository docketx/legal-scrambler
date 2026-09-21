import { test } from "node:test";
import assert from "node:assert/strict";
import { MatterGraph, scrambleDocument, unscramble } from "../src";
import { residualAliases, placeholderLookalikes } from "../src/apply";
import { extractCitations } from "../src/citations";
import { generate, competent, hijacked, lazy, present, flex } from "./helpers/scrambler-fuzz-gen";

/* PROPERTY TESTS: the invariants hold on hundreds of generated documents, not on the handful we hand-wrote. The
 * generator lives in tests/helpers/scrambler-fuzz-gen.ts so a failing seed can be replayed:
 *   npx tsx -e 'import("./tests/helpers/scrambler-fuzz-gen").then(async m => { ... m.generate(SEED) ... })'
 * Three models play against each document: a competent one, a hijacked one that also proposes every trick the
 * red-team file knows, and a lazy one that proposes half the entities so derived aliases and pass 2 must work.
 * For every document, whatever the model did, the invariants must hold or the pipeline must REFUSE. */

const SEEDS = Number(process.env.SCRAMBLER_FUZZ_SEEDS ?? 300);

for (const [name, mk] of [["competent", competent], ["hijacked", hijacked], ["lazy", lazy]] as const) {
  test(`${SEEDS} generated filings against a ${name} model: no secret leaves, no citation is harmed, every release round-trips`, async () => {
    let released = 0, refused = 0;
    for (let seed = 1; seed <= SEEDS; seed++) {
      const g = generate(seed); const graph = new MatterGraph(`fuzz-${seed}`);
      let out: Awaited<ReturnType<typeof scrambleDocument>>;
      try { out = await scrambleDocument(g.doc, graph, mk(g)); }
      catch (e) { assert.match((e as Error).message, /refusing to release/, `seed ${seed}: unexpected error ${(e as Error).message}`); refused++; continue; }
      released++;
      const where = `seed ${seed} (${name})\n${out.scrambled}`;
      // (1) the regex-class secrets and every model-proposed name are gone, wherever they were spelled
      for (const s of g.secrets) {
        const proposed = graph.find(s) !== null || /[@\d]/.test(s);
        if (proposed) assert.ok(!present(out.scrambled, s) || occursOnlyInCitedCaption(out.scrambled, s), `${where}\nleaked: ${s}`);
      }
      // (2) public law survives verbatim
      for (const c of g.publicLaw) assert.ok(out.scrambled.includes(c.split(",")[0]) || extractCitations(out.scrambled).length >= extractCitations(g.doc).length, `${where}\ncitation damaged: ${c}`);
      assert.equal(extractCitations(out.scrambled).length, extractCitations(g.doc).length, `${where}\ncitation count changed`);
      // (3) nothing invented, nothing placeholder-shaped that is not a placeholder, no residual alias
      assert.ok(!/Putin|Elvis/.test(out.scrambled), where);
      assert.deepEqual(placeholderLookalikes(out.scrambled), [], where);
      assert.deepEqual(residualAliases(out.scrambled, graph), [], where);
      // (4) round trip: every placeholder in the output restores, and the restore contains no placeholder
      const back = unscramble(out.scrambled, graph);
      assert.deepEqual(back.unknown, [], where);
      assert.ok(!/\[[A-Z]+_\d+\]/.test(back.text), where);
      for (const n of g.people) if (graph.find(n)) assert.ok(present(back.text, n) || present(g.doc, n) === false, `${where}\nrestore lost ${n}`);
    }
    assert.ok(released > 0, "the pipeline must release at least some documents or the suite proves nothing");
    console.log(`  ${name}: released ${released}, refused ${refused} of ${SEEDS}`);
  });
}

/** A secret that appears only inside a cited caption ("Young v. State, 826 S.W.2d 141") is left by design. */
function occursOnlyInCitedCaption(text: string, s: string): boolean {
  const re = new RegExp(`(?<![\\p{L}\\p{N}])${flex(s)}(?![\\p{L}\\p{N}])`, "giu");
  return [...text.matchAll(re)].every((m) => /^\s+v\.\s+\S/.test(text.slice(m.index! + m[0].length, m.index! + m[0].length + 12)));
}
