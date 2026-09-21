/* Measure the scrambler's leak rate against the HLL bank's human-audited redaction maps.
 *
 *   npx tsx scripts/scrambler-leak-rate.ts --opinions <jsonl> [--items data/hll/items] [--limit 25] [--chunk 4000] [--overlap 200] [--resume prior.json] [--fake] [--json out.json]
 *
 * --chunk    : characters per model pass. The pipeline's own cap is 60k, which is sized for the release gate, not
 *              for an 8B model's output: on the first live run qwen3:8b DEGRADED on a 23k-char chunk after 169s
 *              (2026-09-15), and at 6k its span list overran the output budget. Default 4000 for the liaison; the
 *              oracle ignores it and uses the 60k cap.
 * --overlap  : chars shared between consecutive chunks, so a name straddling a boundary is whole in one pass
 *              (review 2026-09-15, item 2). Default 200 for the liaison, 0 for --fake (the oracle sees the whole
 *              opinion in one pass). The graph de-duplicates aliases, so the cost is model time only. One
 *              measurement caveat: the scored output is the chunk outputs joined, so each overlap region appears
 *              in it twice; a leak sitting inside an overlap can be counted twice at OCCURRENCE level (the safe
 *              direction). Name-level, citation and over-scrub figures are set-based and unaffected.
 *
 * --opinions : JSONL, one opinion per line, the same shape scripts/hll-author-plan.ts reads
 *              ({ sourceId | docketNumber, text, ... }). Text with REAL names in it.
 * --items    : directory of HLL item JSON files; each item's source.docket links it to an opinion and its
 *              redaction_map supplies the names that must not survive.
 * --fake     : an oracle model that proposes every ground-truth name it can find. Proves the plumbing and gives
 *              the ceiling; it is NOT a measurement of the liaison.
 * Without --fake the private liaison is used, and ONLY the private liaison: localScrambler() refuses any model id
 * that is not local/*, and this script exits non-zero rather than fall back. Set LIAISON_MODEL and
 * LOCAL_LLM_BASE_URL (through the prod tunnel, see the scrambler memory note). No upstream model is ever called.
 *
 * The number printed is "leaked per 1,000 ground-truth names present in the input", against the names a
 * human-audited authoring process chose to redact. Nothing else. Values are never printed — counts only. */
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { MatterGraph, scrambleDocument, finalizeChunks, type LocalModel } from "../src";
import { localScrambler } from "../src/liaison";
import { usableNames, score, summarize, paragraphs, isTransportFailure, type LeakReport } from "../src/measure";
import { flex } from "../src/apply";

const argv = process.argv.slice(2);
const arg = (k: string, d?: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const has = (k: string) => argv.includes(`--${k}`);

const OPINIONS = arg("opinions"); const ITEMS = arg("items", "data/hll/items")!; const LIMIT = Number(arg("limit", "25"));
const CHUNK = has("fake") ? 60_000 : Number(arg("chunk", "4000"));
const OVERLAP = has("overlap") ? Number(arg("overlap")) : has("fake") ? 0 : 200;
const ONLY = arg("docket");  // measure one opinion, for diagnosing a refusal
if (!OPINIONS) { console.error("usage: --opinions <jsonl> [--items dir] [--limit n] [--fake] [--json out]"); process.exit(2); }

/** docket -> ground-truth names, from every item that cites that docket. */
function groundTruth(dir: string): Map<string, string[]> {
  const m = new Map<string, Set<string>>();
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    let j: { source?: { docket?: string }; redaction_map?: Record<string, string> };
    try { j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); } catch { continue; }
    const d = j.source?.docket; if (!d) continue;
    const set = m.get(d) ?? new Set<string>(); for (const n of usableNames(j.redaction_map)) set.add(n); m.set(d, set);
  }
  return new Map([...m].map(([k, v]) => [k, [...v]]));
}

/** The oracle: proposes every ground-truth name that occurs in the text, typed PERSON/ORG by a crude heuristic.
 *  It is deliberately NOT a good model — it is the ceiling of what the pipeline does with perfect spans. */
const oracle = (names: string[]): LocalModel => async (prompt) => {
  const m = /<<<DOCUMENT \w+>>>\n([\s\S]*)\n<<<END DOCUMENT/.exec(prompt); const doc = m ? m[1] : prompt;
  if (prompt.includes("auditing")) return JSON.stringify({ leaks: [], inconsistent: [] });
  const spans: { text: string; type: string }[] = [];
  for (const n of names) {
    const m = new RegExp(flex(n), "iu").exec(doc); if (!m) continue;   // the spelling the document actually uses, wrapped or not
    spans.push({ text: m[0], type: /\b(Inc|LLC|LLP|PLLC|P\.C\.|Corp|Co\.|Ltd|Department|Board|Company|Association|Associates|City|County|Insurance|Authority|Firm|Partnership|Group|Holdings|Enterprises|Industries|Services|Systems|Bank|Trust|University|Hospital|Church|Agency|Commission|District)\b/i.test(n) ? "ORG" : "PERSON" });
  }
  return JSON.stringify({ spans, coref: {} });
};

(async () => {
  const gt = groundTruth(ITEMS);
  const model: ((names: string[]) => LocalModel) = has("fake") ? oracle : (() => { const m = localScrambler(); return () => m; })();
  console.log(`ground truth: ${gt.size} dockets with redaction maps; model: ${has("fake") ? "ORACLE (plumbing/ceiling only)" : `private liaison ${process.env.LIAISON_MODEL}`}; chunk ${CHUNK} chars, overlap ${OVERLAP}`);
  const reports: LeakReport[] = []; const refusals: { docket: string; where: string; message: string }[] = []; let refused = 0, degraded = 0, seen = 0, excluded = 0;
  // --resume: dockets already scored in an earlier JSON are carried forward, so a dropped tunnel costs the chunk
  // it dropped, not the hour before it
  const prior = arg("resume") && fs.existsSync(arg("resume")!) ? (JSON.parse(fs.readFileSync(arg("resume")!, "utf8")) as { reports?: LeakReport[] }).reports ?? [] : [];
  for (const r of prior) reports.push(r);
  if (prior.length) console.log(`resumed ${prior.length} scored opinion(s) from ${arg("resume")}`);
  const done = new Set(prior.map((r) => r.docket));
  // Streamed, never slurped: opinions-ramp-all.jsonl is 239 MB, and reading it whole got this process killed on a
  // low-memory workstation mid-run (2026-09-15). The model runs on the corpus host; only the client is here.
  const rl = readline.createInterface({ input: fs.createReadStream(OPINIONS, "utf8"), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    if (reports.length + refused >= LIMIT) break;
    let op: { sourceId?: string; docketNumber?: string; text?: string };
    try { op = JSON.parse(line); } catch { continue; }
    const docket = op.docketNumber ?? op.sourceId ?? ""; const names = gt.get(docket); if (!names || !op.text || done.has(docket) || (ONLY && docket !== ONLY)) continue;
    seen++;
    const t0 = Date.now(); const graph = new MatterGraph(`leak-rate:${docket}`); const outs: string[] = []; let deg = 0, transport = false;
    try {
      for (const chunk of paragraphs(op.text, CHUNK, OVERLAP)) {
        const r = await scrambleDocument(chunk, graph, model(names)); outs.push(r.scrambled);
        if (r.degraded.length) { deg++; if (r.degraded.some(isTransportFailure)) transport = true; console.log(`${docket.padEnd(14)} degraded: ${r.degraded.join("; ").slice(0, 100)}`); }
      }
    } catch (e) { refused++; refusals.push({ docket, where: "chunk", message: (e as Error).message.slice(0, 300) }); console.log(`${docket.padEnd(14)} REFUSED  ${(e as Error).message.slice(0, 160)}`); continue; }
    if (transport) { excluded++; console.log(`${docket.padEnd(14)} EXCLUDED: the model was not reached on at least one chunk (transport), so this opinion says nothing about the model`); continue; }
    if (deg) degraded++;
    // the final pass: every chunk re-substituted with the graph as it stands after the last chunk
    let finalOuts: string[];
    try { finalOuts = finalizeChunks(paragraphs(op.text, CHUNK, OVERLAP), graph); }
    catch (e) { refused++; refusals.push({ docket, where: "final pass", message: (e as Error).message.slice(0, 300) }); console.log(`${docket.padEnd(14)} REFUSED (final pass)  ${(e as Error).message.slice(0, 140)}`); continue; }
    const rep = score(docket, op.text, finalOuts.join("\n\n"), names, Date.now() - t0); reports.push(rep);
    // written after EVERY opinion, not at the end: the run before this one was killed for memory on the
    // workstation with one opinion scored and nothing on disk to --resume from (2026-09-15)
    if (arg("json")) fs.writeFileSync(arg("json")!, JSON.stringify({ summary: summarize(reports, refused, degraded, excluded), reports, refusals, partial: true, mode: has("fake") ? "oracle" : "liaison", model: has("fake") ? "oracle" : process.env.LIAISON_MODEL, chunk: CHUNK, overlap: OVERLAP, at: new Date().toISOString() }, null, 2) + "\n");
    console.log(`${docket.padEnd(14)} names=${String(rep.present_in_input).padStart(3)}/${String(rep.ground_truth).padEnd(3)} leaked=${String(rep.leaked).padStart(3)}${rep.caption_only ? ` caption-only=${rep.caption_only}` : ""}  cites ${rep.citations_in}->${rep.citations_out} lost=${rep.citations_lost}${rep.citations_lost ? ` (${rep.citations_missing.join("; ")})` : ""}  ${(rep.chars / 1000).toFixed(0)}k chars  ${(rep.ms / 1000).toFixed(1)}s${deg ? "  DEGRADED" : ""}  occ=${rep.occurrences_leaked}/${rep.occurrences_in_input} over-scrub=${rep.over_scrub_candidates}/${rep.phrases_in_input}`);
  }
  const s = summarize(reports, refused, degraded, excluded);
  console.log(`\nopinions scored ${s.opinions} (refused ${s.refused}, degraded-by-model ${s.degraded}, EXCLUDED for transport failure ${s.excluded_transport}, matched ${seen})`);
  console.log(`ground-truth names present in input: ${s.entities}   leaked: ${s.leaked}   => ${s.per_1000 === null ? "n/a" : s.per_1000 + " per 1,000"}   (left in cited-case captions by design: ${s.caption_only})`);
  const ci = (c: [number, number] | null) => (c ? `[${c[0]}, ${c[1]}] per 1,000` : "n/a");
  console.log(`name-level 95% Wilson CI: ${ci(s.per_1000_ci)}`);
  console.log(`occurrences of those names in input (non-caption): ${s.occurrences}   leaked: ${s.leaked_occurrences}   => ${s.leaked_occurrences_per_1000 === null ? "n/a" : s.leaked_occurrences_per_1000 + " per 1,000"}   95% Wilson CI: ${ci(s.leaked_occurrences_per_1000_ci)}`);
  console.log(`over-scrub PROXY: ${s.over_scrub_candidates} capitalised phrase(s) scrubbed that were not ground-truth names, of ${s.phrases} seen — candidates to inspect, not a rate`);
  console.log(`citations in input: ${s.citations_in}   destroyed by scrambling: ${s.citations_lost}`);
  console.log(`model time: ${(s.ms_total / 1000).toFixed(0)}s   mode: ${has("fake") ? "ORACLE — not a liaison measurement" : "private liaison"}`);
  if (arg("json")) fs.writeFileSync(arg("json")!, JSON.stringify({ summary: s, reports, refusals, mode: has("fake") ? "oracle" : "liaison", model: has("fake") ? "oracle" : process.env.LIAISON_MODEL, chunk: CHUNK, overlap: OVERLAP, at: new Date().toISOString() }, null, 2) + "\n");
})().catch((e) => { console.error(`leak-rate: ${(e as Error).message}`); process.exit(1); });
