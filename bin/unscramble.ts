#!/usr/bin/env -S npx tsx
// Put the real names back into text that came back from a frontier model, or restore a scrambled document byte-exact.
//
//   SCRAMBLER_MASTER_KEY=... npx tsx bin/unscramble.ts --matter smith-v-smith < answer.txt > answer.restored.txt
//
// Options
//   --matter <id>            required; the matter the text was scrambled for.
//   --owner <id>             default "local"; must match the --owner used to scramble.
//   --mode answer|document|canonical
//       answer     (default) natural rendering of a model answer: placeholders become the names, possessives and
//                  articles read naturally. Placeholders the matter does not know are REPORTED on stderr, never guessed.
//       canonical  plain placeholder-for-alias substitution, no rendering.
//       document   byte-exact restore of a document this tool scrambled, from its sealed ledger. Fails (exit 4) if the
//                  scrambled text was edited after scrambling — it must be the bytes this tool printed.
// Code does every substitution. No model is involved in this direction.
import fs from "node:fs";
import { renderAnswer, restoreDocument, unscramble } from "../src/apply";
import { loadGraph, ledgerGet, ScramblerConfigError } from "../src/store";

const argv = process.argv.slice(2);
const arg = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const die = (m: string, code = 2): never => { console.error(`unscramble: ${m}`); process.exit(code); };

const matter = arg("matter") ?? die("--matter <id> is required");
if (!/^[A-Za-z0-9_.-]{1,64}$/.test(matter)) die("--matter: letters, digits, dot, dash, underscore; at most 64");
const owner = arg("owner") ?? "local";
const mode = arg("mode") ?? "answer";
if (!["answer", "document", "canonical"].includes(mode)) die("--mode must be answer, document or canonical");
const text = fs.readFileSync(0, "utf8");
if (!text) die("empty input on stdin");

try {
  if (mode === "document") {
    const led = ledgerGet(owner, matter, text);
    if (!led) die("no ledger for this text: it was not scrambled for this matter as given, or it was edited after scrambling", 4);
    try { process.stdout.write(restoreDocument(text, led.occurrences)); } catch (e) { die((e as Error).message.replace(/^scrambler: /, ""), 4); }
    process.exit(0);
  }
  const { graph, existed } = loadGraph(owner, matter);
  if (!existed) console.error(`unscramble: matter "${matter}" has no graph under owner "${owner}" — nothing will be restored`);
  const r = mode === "canonical" ? unscramble(text, graph) : renderAnswer(text, graph);
  process.stdout.write(r.text);
  if (r.unknown.length) { console.error(`unscramble: ${r.unknown.length} placeholder(s) this matter does not know were left as-is: ${r.unknown.join(" ")}`); process.exit(5); }
} catch (e) {
  if (e instanceof ScramblerConfigError) die(e.message, 3);
  throw e;
}
