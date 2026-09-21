/* THE PROOF RUN: every scrambler suite at full scale, one command, one artefact.
 *
 *   npx tsx scripts/scrambler-prove.ts [--fuzz 1000] [--dockets 40] [--restore-docs 167] [--out docs/SCRAMBLER-PROOF.md]
 *
 * Runs, in order: the unit suite, the 56-attack red-team, the property fuzz (N seeds x competent/hijacked/lazy
 * models), the normaliser and pattern suites, the routes end to end, the orchestrator, the 167-document battery
 * (oracle / hijacked / lazy), the byte-exact restore over every battery document, and the proof invariants
 * (P1-P7, including all real dockets under perfect spans). Nothing here calls a model: the proof is of the
 * PIPELINE; the local model's readings are measurements and live in docs/SCRAMBLER.md. Every suite's pass/fail
 * counts and the numbers each prints are captured into docs/SCRAMBLER-PROOF.md with the commit hash, the date, the
 * machine and the wall time, so the claim and its evidence are one file. A single failing test fails the run. */
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

const argv = process.argv.slice(2);
const arg = (k: string, d: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const FUZZ = arg("fuzz", "1000"), DOCKETS = arg("dockets", "40"), RESTORE_DOCS = arg("restore-docs", "167"), OUT = arg("out", "docs/SCRAMBLER-PROOF.md");

type Suite = { name: string; claim: string; files: string[]; env?: Record<string, string> };
const SUITES: Suite[] = [
  { name: "unit", claim: "graph, guard, substitution, derived aliases, defined terms, restore, and every rule real filings taught", files: ["tests/scrambler.test.ts"] },
  { name: "red-team", claim: "56 attacks on the guard: injection, look-alikes, coref cycles, citation components, glued names, public matter, the joins -- none leak", files: ["tests/scrambler-redteam.test.ts"] },
  { name: "fuzz", claim: `${FUZZ} generated filings x 3 adversarial models: no secret leaves, no citation harmed, every release round-trips`, files: ["tests/scrambler-fuzz.test.ts"], env: { SCRAMBLER_FUZZ_SEEDS: FUZZ } },
  { name: "normalize", claim: "confusables, zero-width and quote folds happen before any model reads the text", files: ["tests/scrambler-normalize.test.ts"] },
  { name: "patterns", claim: "every regex class with a positive and a public-law negative", files: ["tests/scrambler-patterns.test.ts"] },
  { name: "orchestrator", claim: "the frontier never sees a client fact in any message or tool argument; unknown placeholders reported", files: ["tests/scrambler-orchestrate.test.ts"] },
  { name: "battery", claim: "167 DeepSeek-generated adversarial filings with typed ground truth: 0 leaks under oracle and hijacked models", files: ["tests/scrambler-battery.test.ts"] },
  { name: "restore", claim: `byte-exact document restore through 4k chunks and the cross-chunk pass on ${RESTORE_DOCS} battery documents; natural answer rendering`, files: ["tests/scrambler-restore.test.ts"], env: { SCRAMBLER_RESTORE_DOCS: RESTORE_DOCS } },
  { name: "leak-rate harness", claim: "the measurement itself: name- and occurrence-level rates, Wilson intervals, transport exclusion", files: ["tests/scrambler-leak-rate.test.ts"] },
  { name: "proof", claim: `P1 no egress; P5 refuse never partial; P6 unknown never guessed; P3+P4 real case files under perfect spans (${DOCKETS} dockets): byte-exact, zero leaks, one placeholder per entity`, files: ["tests/scrambler-proof.test.ts"], env: { SCRAMBLER_PROOF_DOCKETS: DOCKETS } },
];

const commit = execFileSync("git", ["rev-parse", "--short", "HEAD"]).toString().trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--", "src", "tests", "scripts"]).toString().trim() ? " (scrambler sources or tests modified since)" : "";
const t0 = Date.now(); const rows: string[] = []; let allPass = true; let totalPass = 0, totalFail = 0;
console.log(`proof run at ${commit}${dirty}: fuzz ${FUZZ}, dockets ${DOCKETS}, restore docs ${RESTORE_DOCS}`);
for (const s of SUITES) {
  const t = Date.now();
  const r = spawnSync("npx", ["tsx", "--test", ...s.files], { env: { ...process.env, ...(s.env ?? {}) }, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 3 * 60 * 60_000 });
  const outText = (r.stdout ?? "") + (r.stderr ?? "");
  const pass = Number(/^ℹ pass (\d+)/m.exec(outText)?.[1] ?? 0), fail = Number(/^ℹ fail (\d+)/m.exec(outText)?.[1] ?? 0), skipped = Number(/^ℹ skipped (\d+)/m.exec(outText)?.[1] ?? 0);
  const ok = r.status === 0 && fail === 0; if (!ok) allPass = false; totalPass += pass; totalFail += fail;
  // the numbers each suite prints for itself (released/leaked/exact counts) are the evidence; keep them verbatim
  const numbers = outText.split("\n").filter((l) => /^\s{2}(?:oracle|hijacked|lazy|competent|restore byte-exact|real dockets|injection documents):/.test(l)).map((l) => l.trim());
  const secs = ((Date.now() - t) / 1000).toFixed(0);
  console.log(`${ok ? "PASS" : "FAIL"}  ${s.name.padEnd(18)} pass ${pass} fail ${fail}${skipped ? ` skipped ${skipped}` : ""}  ${secs}s`);
  for (const n of numbers) console.log(`      ${n}`);
  if (!ok) console.log(outText.split("\n").filter((l) => /^✖|AssertionError|Error:/.test(l)).slice(0, 12).map((l) => "      " + l.slice(0, 200)).join("\n"));
  rows.push(`| ${ok ? "**PASS**" : "**FAIL**"} | ${s.name} | ${s.claim} | ${pass} / ${fail}${skipped ? ` (${skipped} skipped)` : ""} | ${secs}s |${numbers.length ? "\n" + numbers.map((n) => `|  |  | ↳ ${n.replace(/\|/g, "\\|")} |  |  |`).join("\n") : ""}`);
}
const wall = ((Date.now() - t0) / 1000 / 60).toFixed(1);
const md = [`# Scrambler proof run — ${new Date().toISOString().slice(0, 10)}`, ``,
  `**${allPass ? "ALL CLAIMS HOLD" : "A CLAIM FAILED"}** at commit \`${commit}\`${dirty} — ${totalPass} tests passed, ${totalFail} failed, ${wall} min wall on ${os.hostname()} (${os.cpus()[0]?.model ?? "?"}). Parameters: fuzz seeds ${FUZZ}, real dockets ${DOCKETS}, restore documents ${RESTORE_DOCS}. Produced by \`scripts/scrambler-prove.ts\`; no model was called -- this is the proof of the pipeline. The local model's measured leak rates are in docs/SCRAMBLER.md and are not claims.`, ``,
  `| | suite | claim | pass / fail | time |`, `|---|---|---|---|---|`, ...rows, ``,
  `## What the claims mean`, ``,
  `- **No egress** (P1): with fetch replaced by a tripwire, a document is scrambled, restored and answered with fake models and not one network call happens; the liaison builder refuses any model id that is not \`local/\`; node 5 cannot be constructed without \`SCRAMBLER_FRONTIER_LIVE=1\`.`,
  `- **Perfect spans, zero leaks** (P2): with the planted secrets proposed exactly -- and with every red-team trick added on top -- no secret of any of 12 types survives the 167-document battery outside a cited caption. The model's own misses are measured separately.`,
  `- **Byte-exact** (P3): every scrambled document restores to its own bytes from its sealed ledger; every chunk of every real docket held.`,
  `- **Real case files** (P4): the docket's own party, attorney and judge list, proposed exactly, leaks nothing, and each entity maps to one placeholder across every filing of the file (shared surnames get their own node by design and are listed).`,
  `- **Refuse, never partially release** (P5); **unknown is reported, never guessed** (P6); **the frontier never sees a fact** (P7, the orchestrator suite).`, ``].join("\n");
fs.writeFileSync(OUT, md + "\n");
console.log(`\n${allPass ? "ALL CLAIMS HOLD" : "A CLAIM FAILED"} -- ${totalPass} passed, ${totalFail} failed, ${wall} min -> ${OUT}`);
process.exit(allPass ? 0 : 1);
