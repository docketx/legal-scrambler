#!/usr/bin/env -S npx tsx
// Scramble one document for a matter, on this machine, and print only the scrambled text.
//
//   LIAISON_MODEL=local/qwen3:8b SCRAMBLER_MASTER_KEY=<32 bytes b64|hex> \
//     npx tsx bin/scramble.ts --matter smith-v-smith < petition.txt > petition.scrambled.txt
//
// Options
//   --matter <id>     required; letters, digits, dot, dash, underscore. The same matter keeps the same placeholders
//                     across every document, so [PERSON_1] in the petition is [PERSON_1] in the decree.
//   --owner <id>      namespace for the sealed store (default "local"). The graph is encrypted under owner+matter.
//   --regex-only      no model: patterns only (SSNs, phones, emails, accounts, dates of birth, addresses by shape).
//                     Names are NOT found without a model. Printed as a warning on stderr; refuse to pretend otherwise.
//   --stats           print the release stats as JSON on stderr (counts and reasons, never values).
//
// What is written: data/store/ (or SCRAMBLER_DATA_DIR) holds the sealed matter graph, the content-addressed cache and
// the restore ledger. Nothing else. Nothing leaves the machine.
import fs from "node:fs";
import { scrambleDocument, MAX_DOC_CHARS, type LocalModel } from "../src/index";
import { localScrambler } from "../src/liaison";
import { loadGraph, saveGraph, cacheGet, cachePut, ledgerPut, ScramblerConfigError } from "../src/store";

const argv = process.argv.slice(2);
const flag = (k: string) => argv.includes(`--${k}`);
const arg = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const die = (m: string, code = 2): never => { console.error(`scramble: ${m}`); process.exit(code); };

const matter = arg("matter") ?? die("--matter <id> is required");
if (!/^[A-Za-z0-9_.-]{1,64}$/.test(matter)) die("--matter: letters, digits, dot, dash, underscore; at most 64");
const owner = arg("owner") ?? "local";
const text = fs.readFileSync(0, "utf8");
if (!text.trim()) die("empty input on stdin");
if (text.length > MAX_DOC_CHARS) die(`input is ${text.length} chars; the ceiling is ${MAX_DOC_CHARS}. Split the document.`);

let model: LocalModel | null = null;
if (flag("regex-only")) console.error("scramble: --regex-only — patterns only; NAMES ARE NOT FOUND without a local model");
else { try { model = localScrambler(); } catch (e) { die(`${(e as Error).message}\n  set LIAISON_MODEL=local/<ollama model> (e.g. local/qwen3:8b) or pass --regex-only`); } }

try {
  const hit = cacheGet(owner, matter, text);
  if (hit) { process.stdout.write(hit.scrambled); if (flag("stats")) console.error(JSON.stringify({ cached: true, stats: hit.stats, rejected: hit.rejected, degraded: hit.degraded })); process.exit(0); }
  const { graph } = loadGraph(owner, matter);
  const r = await scrambleDocument(text, graph, model);
  saveGraph(owner, matter, graph);
  const rejected: Record<string, number> = {}; for (const x of r.rejected) rejected[x.reason] = (rejected[x.reason] ?? 0) + 1;
  const at = new Date().toISOString();
  cachePut(owner, matter, text, { scrambled: r.scrambled, stats: r.stats, rejected, degraded: r.degraded, at, restore_basis: r.restore_basis });
  ledgerPut(owner, matter, r.scrambled, { occurrences: r.occurrences, restore_basis: r.restore_basis, at });
  process.stdout.write(r.scrambled);
  if (flag("stats")) console.error(JSON.stringify({ cached: false, stats: r.stats, rejected, degraded: r.degraded, restore_basis: r.restore_basis }));
} catch (e) {
  if (e instanceof ScramblerConfigError) die(e.message, 3);
  // the release gate refuses on purpose: nothing is printed, the reason is, and the exit code says so
  if (/^refusing to release/.test((e as Error).message)) die((e as Error).message, 4);
  throw e;
}
