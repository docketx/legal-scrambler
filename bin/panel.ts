#!/usr/bin/env -S npx tsx
// A second opinion from a panel of frontier models, none of which ever sees a fact of the matter.
//
//   SCRAMBLER_FRONTIER_LIVE=1 OPENROUTER_API_KEY=... SCRAMBLER_MASTER_KEY=... \
//     npx tsx bin/panel.ts --matter smith-v-smith --models deepseek/deepseek-v4-flash,qwen/qwen3-235b-a22b \
//       --question "Is the spousal maintenance cap likely to apply on these facts?" < petition.scrambled.txt > panel.json
//
// What happens: the question is scrambled with the matter's graph (it may name the client outright); the context on
// stdin must ALREADY be scrambled (bin/scramble.ts) — the egress sweep proves it and refuses otherwise; every model
// on the panel answers the same question in parallel under the same guard (orchestrate.ts); each answer is restored
// by code; the output is one JSON document with every answer side by side and, from code alone, which reporter
// citations each model relied on and how many models cited each. No model summarises the panel — that is the
// caller's job, with the answers in front of it.
//
// Options
//   --matter <id>      required.            --owner <id>   default "local".
//   --models a,b,c     OpenRouter ids; default deepseek/deepseek-v4-flash. GPT/OpenAI ids are refused (llm.ts).
//   --question "..."   required.
//   --tools none|docketrouter   default: docketrouter if DOCKETROUTER_API_KEY is set, else none. With tools the panel
//                      can search public law and check citations through DocketRouter; without, it answers from the
//                      context and its own knowledge and says so.
//   --max-steps N      tool rounds per model (default 6).   --timeout-ms N   per model call (default 120000).
// Disarmed until SCRAMBLER_FRONTIER_LIVE=1: this is the one step that spends money and talks to a third party.
import fs from "node:fs";
import { answerScrambled, deepseekFlash, httpTools, FRONTIER_MODEL_ID, ScramblerEgressError, type OrchestrateResult } from "../src/orchestrate";
import { loadGraph, ScramblerConfigError } from "../src/store";
import { residualAliases } from "../src/apply";
import { extractCitations } from "../src/citations";

const argv = process.argv.slice(2);
const arg = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const die = (m: string, code = 2): never => { console.error(`panel: ${m}`); process.exit(code); };

const matter = arg("matter") ?? die("--matter <id> is required");
if (!/^[A-Za-z0-9_.-]{1,64}$/.test(matter)) die("--matter: letters, digits, dot, dash, underscore; at most 64");
const owner = arg("owner") ?? "local";
const question = arg("question") ?? die("--question is required");
const models = (arg("models") ?? FRONTIER_MODEL_ID).split(",").map((s) => s.trim()).filter(Boolean);
if (!models.length) die("--models: at least one id");
const toolsMode = arg("tools") ?? (process.env.DOCKETROUTER_API_KEY ? "docketrouter" : "none");
if (!["none", "docketrouter"].includes(toolsMode)) die("--tools must be none or docketrouter");
const maxSteps = Number(arg("max-steps") ?? 6), timeoutMs = Number(arg("timeout-ms") ?? 120_000);
const scrambled = fs.readFileSync(0, "utf8");
if (!scrambled.trim()) die("empty context on stdin; scramble the document first (bin/scramble.ts)");
if (process.env.SCRAMBLER_FRONTIER_LIVE !== "1") die("disarmed: set SCRAMBLER_FRONTIER_LIVE=1 to let the panel spend OpenRouter credit", 6);

try {
  const { graph, existed } = loadGraph(owner, matter);
  if (!existed) die(`matter "${matter}" has no graph under owner "${owner}"; scramble the document for it first`, 4);
  // The context must be scrambled already. This is the same containment check the orchestrator applies to every
  // outbound message; failing it here gives a clear reason instead of an egress error mid-run.
  const residual = residualAliases(scrambled, graph).length;
  if (residual) die(`the context on stdin still contains ${residual} matter alias(es); it is not the scrambled text. Refusing.`, 4);
  const tools = toolsMode === "docketrouter" ? httpTools({ timeoutMs }) : {};

  const results = await Promise.all(models.map(async (id) => {
    const t0 = Date.now();
    try {
      const r: OrchestrateResult = await answerScrambled({ question, scrambled, graph, model: deepseekFlash({ modelId: id, timeoutMs }), tools, maxSteps });
      return { model: id, ok: true as const, answer: r.answer, unknown_placeholders: r.unknown_placeholders, steps: r.steps, tool_calls: r.tool_calls_made.map((c) => ({ name: c.name, ok: c.ok })), tool_results_scrubbed: r.tool_results_scrubbed, citations: [...new Set(extractCitations(r.answer))], ms: Date.now() - t0 };
    } catch (e) {
      // An egress refusal is reported as such and stops nothing else on the panel; the alias never left.
      const kind = e instanceof ScramblerEgressError ? "egress-refused" : "error";
      return { model: id, ok: false as const, kind, error: (e as Error).message.slice(0, 400), ms: Date.now() - t0 };
    }
  }));

  // Agreement, from code only: which citations appear in how many answers. Nothing here judges the answers.
  const byCite: Record<string, string[]> = {};
  for (const r of results) if (r.ok) for (const c of r.citations) (byCite[c] ??= []).push(r.model);
  const answered = results.filter((r) => r.ok).length;
  const out = {
    matter, question, tools: toolsMode, models: results,
    citations: Object.fromEntries(Object.entries(byCite).sort((a, b) => b[1].length - a[1].length)),
    agreement: { models_answered: answered, models_failed: results.length - answered, citations_by_all: Object.entries(byCite).filter(([, m]) => m.length === answered && answered > 1).map(([c]) => c), citations_by_one: Object.entries(byCite).filter(([, m]) => m.length === 1).map(([c]) => c) },
    note: "Answers were restored by code from the sealed matter graph; every model saw placeholders only. Citations listed are strings the models wrote and are UNVERIFIED until checked (DocketRouter POST /api/public/citation-check is keyless).",
    at: new Date().toISOString(),
  };
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  if (!answered) process.exit(1);
} catch (e) {
  if (e instanceof ScramblerConfigError) die(e.message, 3);
  throw e;
}
