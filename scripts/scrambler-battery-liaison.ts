/* The battery against the REAL private liaison: a leak rate per 1,000 secrets, BY TYPE, with intervals.
 *
 *   LOCAL_LLM_BASE_URL=http://127.0.0.1:11437/v1 LIAISON_MODEL=local/qwen3:8b \
 *     npx tsx scripts/scrambler-battery-liaison.ts [--limit N] [--doc 12-3] [--chunk 4000] [--overlap 200] [--json out.json] [--resume out.json]
 *
 * tests/scrambler-battery.test.ts runs the same 167 documents against fake models and proves the PIPELINE: with
 * perfect spans nothing leaks. This runs them through the private liaison (local/* only; liaison.ts refuses an
 * upstream id) and measures the MODEL: which of the planted secrets, by type, come out the other side. The ground
 * truth is the generator's own list, verified verbatim at generation time and cleaned by battery.ts. The JSON is
 * checkpointed after every document, so a killed run resumes with --resume and loses at most one document.
 * Documents on which the model was never reached (transport) are excluded from the rate under their own heading,
 * as scrambler-leak-rate.ts does; a model failure (unparseable, truncated) stays in the rate. */
import fs from "node:fs";
import { MatterGraph, scrambleDocument, finalizeChunks, type LocalModel } from "../src";
import { localScrambler } from "../src/liaison";
import { loadBattery, asType } from "../src/battery";
import { occurrences, wilson, isTransportFailure, paragraphs } from "../src/measure";
import { extractCitations } from "../src/citations";

const argv = process.argv.slice(2);
const arg = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const LIMIT = Number(arg("limit") ?? Infinity), ONLY = arg("doc") ?? null;
const CHUNK = Number(arg("chunk") ?? 4000), OVERLAP = Number(arg("overlap") ?? 200);

type DocReport = {
  id: string; seed: number; title: string; chars: number; ms: number;
  secrets: number; leaked: number; caption_only: number;
  by_type: Record<string, { secrets: number; leaked: number; leaked_texts?: string[] }>;
  citations_in: number; citations_out: number; citations_lost: number; citations_missing: string[];
  degraded: string[]; injection_present: boolean;
  /** what the model's second (audit) pass caught, and how many pass-1 rounds a chunk took: the speed question */
  verdict_leaks: number; pass1_rounds_max: number; chunks: number;
};
type Out = { summary: unknown; reports: DocReport[]; refusals: { id: string; message: string }[]; excluded_transport: string[]; partial: boolean; model: string | undefined; chunk: number; overlap: number; at: string };

function summarize(reports: DocReport[], refusals: Out["refusals"], excluded: string[]) {
  const by: Record<string, { secrets: number; leaked: number; per_1000: number | null; ci: [number, number] | null }> = {};
  let secrets = 0, leaked = 0, cin = 0, lost = 0, ms = 0, degraded = 0, verdict = 0, chunks = 0, multiRound = 0, chars = 0;
  for (const r of reports) {
    secrets += r.secrets; leaked += r.leaked; cin += r.citations_in; lost += r.citations_lost; ms += r.ms; if (r.degraded.length) degraded++;
    verdict += r.verdict_leaks ?? 0; chunks += r.chunks ?? 0; if ((r.pass1_rounds_max ?? 1) > 1) multiRound++; chars += r.chars;
    for (const [t, v] of Object.entries(r.by_type)) { const b = by[t] ??= { secrets: 0, leaked: 0, per_1000: null, ci: null }; b.secrets += v.secrets; b.leaked += v.leaked; }
  }
  for (const b of Object.values(by)) { b.per_1000 = b.secrets ? Math.round((b.leaked / b.secrets) * 10000) / 10 : null; b.ci = wilson(b.leaked, b.secrets); }
  return { documents: reports.length, refused: refusals.length, excluded_transport: excluded.length, degraded_by_model: degraded, secrets, leaked, per_1000: secrets ? Math.round((leaked / secrets) * 10000) / 10 : null, per_1000_ci: wilson(leaked, secrets), by_type: by, citations_in: cin, citations_lost: lost, ms_total: ms,
    // the speed question: what pass 2 caught in all, chunks and characters per second of model time, documents that needed more than one pass-1 round
    pass2_catches: verdict, chunks, ms_per_chunk: chunks ? Math.round(ms / chunks) : null, chars_per_second: ms ? Math.round(chars / (ms / 1000)) : null, docs_multi_round: multiRound };
}

(async () => {
  const docs = loadBattery();
  if (!docs.length) { console.error("no battery under data/battery"); process.exit(2); }
  const m = localScrambler(); const model: LocalModel = m;
  const jsonPath = arg("json");
  const prior: Partial<Out> = arg("resume") && fs.existsSync(arg("resume")!) ? JSON.parse(fs.readFileSync(arg("resume")!, "utf8")) : {};
  // --retry-excluded: documents excluded for transport on an earlier run (the tunnel dropped) are attempted again
  const reports: DocReport[] = prior.reports ?? []; const refusals = prior.refusals ?? []; const excluded = argv.includes("--retry-excluded") ? [] : (prior.excluded_transport ?? []);
  const done = new Set([...reports.map((r) => r.id), ...refusals.map((r) => r.id), ...excluded]);
  if (done.size) console.log(`resumed ${reports.length} scored, ${refusals.length} refused, ${excluded.length} excluded`);
  console.log(`battery: ${docs.length} documents; model: private liaison ${process.env.LIAISON_MODEL}; chunk ${CHUNK} chars, overlap ${OVERLAP}`);
  const save = (partial: boolean) => { if (jsonPath) fs.writeFileSync(jsonPath, JSON.stringify({ summary: summarize(reports, refusals, excluded), reports, refusals, excluded_transport: excluded, partial, model: process.env.LIAISON_MODEL, chunk: CHUNK, overlap: OVERLAP, at: new Date().toISOString() } satisfies Out, null, 2) + "\n"); };

  let n = 0;
  for (const d of docs) {
    if (n >= LIMIT) break;
    if (done.has(d.id) || (ONLY !== null && d.id !== ONLY)) continue;
    n++;
    const text = d.text.slice(0, 60_000); const t0 = Date.now();
    const graph = new MatterGraph(`battery-liaison:${d.seed}`); const degraded: string[] = []; let transport = false;
    let verdictLeaks = 0, roundsMax = 1, nChunks = 0;
    try {
      for (const chunk of paragraphs(text, CHUNK, OVERLAP)) {
        nChunks++;
        let r = await scrambleDocument(chunk, graph, model);
        for (let attempt = 1; attempt <= 3 && r.degraded.some(isTransportFailure); attempt++) { await new Promise((res) => setTimeout(res, 15_000 * attempt)); r = await scrambleDocument(chunk, graph, model); }
        for (const g of r.degraded) { degraded.push(g); if (isTransportFailure(g)) transport = true; }
        verdictLeaks += r.verdict_leaks; roundsMax = Math.max(roundsMax, r.pass1_rounds);
      }
    } catch (e) { refusals.push({ id: d.id, message: (e as Error).message.slice(0, 300) }); console.log(`doc ${d.id.padEnd(5)}  REFUSED  ${(e as Error).message.slice(0, 140)}`); save(true); continue; }
    if (transport) { excluded.push(d.id); console.log(`doc ${d.id.padEnd(5)}  EXCLUDED (transport): ${degraded.join("; ").slice(0, 120)}`); save(true); continue; }
    let out: string;
    try { out = finalizeChunks(paragraphs(text, CHUNK, OVERLAP), graph).join("\n\n"); }
    catch (e) { refusals.push({ id: d.id, message: `final pass: ${(e as Error).message.slice(0, 280)}` }); console.log(`doc ${d.id.padEnd(5)}  REFUSED (final pass)  ${(e as Error).message.slice(0, 120)}`); save(true); continue; }

    const by: DocReport["by_type"] = {}; let leaked = 0, captionOnly = 0;
    for (const s of d.secrets) {
      const t = asType(s.type); const b = by[t] ??= { secrets: 0, leaked: 0 }; b.secrets++;
      const all = occurrences(out, s.text);
      if (!all.length) continue;
      if (all.every((o) => o.caption)) { captionOnly++; continue; }
      b.leaked++; leaked++; (b.leaked_texts ??= []).push(s.text); // synthetic, invented by the generator: safe to record
    }
    const cin = new Set(extractCitations(text)), cout = new Set(extractCitations(out));
    const missing = [...cin].filter((c) => !cout.has(c));
    const rep: DocReport = { id: d.id, seed: d.seed, title: d.title.slice(0, 80), chars: text.length, ms: Date.now() - t0, secrets: d.secrets.length, leaked, caption_only: captionOnly, by_type: by, citations_in: cin.size, citations_out: cout.size, citations_lost: missing.length, citations_missing: missing, degraded, injection_present: !!(d.injection && text.includes(d.injection)), verdict_leaks: verdictLeaks, pass1_rounds_max: roundsMax, chunks: nChunks };
    reports.push(rep); save(true);
    const leakStr = Object.entries(by).filter(([, v]) => v.leaked).map(([t, v]) => `${t} ${v.leaked}/${v.secrets}`).join(" ");
    console.log(`doc ${d.id.padEnd(5)}  secrets=${String(rep.secrets).padStart(3)} leaked=${String(leaked).padStart(3)}${captionOnly ? ` caption-only=${captionOnly}` : ""}  cites ${cin.size}->${cout.size}${missing.length ? ` LOST ${missing.join("; ")}` : ""}  ${(rep.chars / 1000).toFixed(1)}k  ${(rep.ms / 1000).toFixed(0)}s${degraded.length ? "  DEGRADED" : ""}  ${leakStr}`);
  }
  const s = summarize(reports, refusals, excluded);
  console.log(`\ndocuments scored ${s.documents} (refused ${s.refused}, excluded for transport ${s.excluded_transport}, degraded-by-model ${s.degraded_by_model})`);
  console.log(`secrets ${s.secrets}   leaked ${s.leaked}   => ${s.per_1000 ?? "n/a"} per 1,000   95% Wilson ${s.per_1000_ci ? `[${s.per_1000_ci[0]}, ${s.per_1000_ci[1]}]` : "n/a"}`);
  for (const [t, b] of Object.entries(s.by_type).sort((a, b) => (b[1].per_1000 ?? 0) - (a[1].per_1000 ?? 0))) console.log(`  ${t.padEnd(9)} ${String(b.leaked).padStart(4)} / ${String(b.secrets).padEnd(5)} => ${String(b.per_1000 ?? "n/a").padStart(6)} per 1,000   ${b.ci ? `[${b.ci[0]}, ${b.ci[1]}]` : ""}`);
  console.log(`citations in input ${s.citations_in}   destroyed ${s.citations_lost}   model time ${(s.ms_total / 1000).toFixed(0)}s`);
  console.log(`pass 2 caught ${s.pass2_catches} span(s) in all; ${s.chunks} chunks at ${s.ms_per_chunk ?? "?"} ms each, ${s.chars_per_second ?? "?"} chars/s; ${s.docs_multi_round} document(s) needed more than one pass-1 round`);
  save(false);
})().catch((e) => { console.error(`battery-liaison: ${(e as Error).message}`); process.exit(1); });
