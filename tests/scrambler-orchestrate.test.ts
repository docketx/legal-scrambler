import { test } from "node:test";
import assert from "node:assert/strict";
import { MatterGraph, scrambleDocument } from "../src";
import { answerScrambled, assertNoAliases, deepseekFlash, httpTools, toModelMessages, ScramblerEgressError, PUBLIC_LAW_SOURCES, type FrontierMessage, type FrontierModel } from "../src/orchestrate";
import { MAX_K } from "../src/limits";

/* NODE 5, THE FRONTIER ORCHESTRATOR, WITHOUT A FRONTIER. The only step that leaves our hardware is driven here
 * by a fake model that records every message it is shown, so the contract can be asserted from the outside:
 * the frontier never sees a client fact in any message, in either direction; a tool call carrying one never
 * runs; public law coming back that happens to contain an alias is scrubbed before the model sees it; the answer
 * is restored by code; and the paid model cannot even be constructed without the arming flag. */

const DOC = "Plaintiff John Doe (SSN 123-45-6789) sued Acme Widgets, Inc. Mr. Doe's counsel is Maria Salinas. See Young v. State, 725 S.W.2d 705 (Tex. Crim. App. 1987).";
const SECRETS = ["John Doe", "Doe", "Acme", "Salinas", "123-45-6789"];
const local = async (p: string) => p.includes("auditing") ? JSON.stringify({ leaks: [], inconsistent: [] })
  : JSON.stringify({ spans: [{ text: "John Doe", type: "CLIENT" }, { text: "Acme Widgets, Inc.", type: "ORG" }, { text: "Maria Salinas", type: "ATTORNEY" }], coref: {} });

async function matter() {
  const graph = new MatterGraph("m-orch");
  const out = await scrambleDocument(DOC, graph, local);
  for (const s of SECRETS) assert.ok(!out.scrambled.includes(s), `fixture: ${s} survived scrambling`);
  return { graph, scrambled: out.scrambled };
}
const seen = (log: FrontierMessage[][]) => log.flat().flatMap((m) => m.role === "assistant" ? [m.content, JSON.stringify(m.toolCalls ?? [])] : [m.content]).join("\n");

test("the answer comes back with the names restored, the question was scrambled on the way out, and the frontier never saw a fact", async () => {
  const { graph, scrambled } = await matter();
  const log: FrontierMessage[][] = [];
  const model: FrontierModel = async (messages, tools) => {
    log.push(structuredClone(messages));
    if (messages.length === 2) { assert.equal(tools.length, 1); return { toolCalls: [{ name: "rag_query", args: { q: "limitations for breach of contract", k: 3 } }] }; }
    return { text: "[CLIENT_1] may sue [ORG_1]; [ATTORNEY_1] should plead limitations under Tex. Civ. Prac. & Rem. Code § 16.051. [PERSON_9] is not in the record." };
  };
  const calls: unknown[] = [];
  const r = await answerScrambled({ question: "Should John Doe sue Acme Widgets, Inc.?", scrambled, graph, model, tools: { rag_query: async (a) => { calls.push(a); return { hits: [{ text: "four-year residual statute", citation: "§ 16.051" }] }; } } });
  assert.equal(r.answer, "John Doe may sue Acme Widgets, Inc.; Maria Salinas should plead limitations under Tex. Civ. Prac. & Rem. Code § 16.051. [PERSON_9] is not in the record.");
  assert.deepEqual(r.unknown_placeholders, ["[PERSON_9]"]);
  assert.equal(r.steps, 2); assert.equal(r.tool_calls_made.length, 1); assert.equal(r.tool_calls_made[0].ok, true); assert.equal(calls.length, 1);
  const shown = seen(log);
  for (const s of SECRETS) assert.ok(!shown.includes(s), `the frontier was shown: ${s}`);
  assert.ok(shown.includes("[CLIENT_1]") && shown.includes("[ORG_1]"), "the question reached the frontier as placeholders");
  assert.ok(shown.includes("725 S.W.2d 705"), "public law reached the frontier verbatim");
});

test("a tool call whose arguments carry a client name never runs: egress refused, the count reported, the value not", async () => {
  const { graph, scrambled } = await matter();
  let ran = 0;
  const model: FrontierModel = async () => ({ toolCalls: [{ name: "rag_query", args: { q: "cases about John Doe and Acme Widgets, Inc." } }] });
  await assert.rejects(answerScrambled({ question: "advise", scrambled, graph, model, tools: { rag_query: async () => { ran++; return {}; } } }),
    (e: unknown) => { assert.ok(e instanceof ScramblerEgressError); assert.match(e.message, /tool call rag_query arguments/); assert.ok(!e.message.includes("Doe") && !e.message.includes("Acme")); assert.ok(e.count >= 2); return true; });
  assert.equal(ran, 0, "the tool ran on a leaking call");
});

test("an alias hidden in a nested tool argument, an array item or an object KEY is still caught", async () => {
  const { graph } = await matter();
  assert.throws(() => assertNoAliases({ filters: [{ party: "Salinas" }] }, graph, "x"), ScramblerEgressError);
  assert.throws(() => assertNoAliases({ "Acme Widgets, Inc.": 1 }, graph, "x"), ScramblerEgressError);
  assert.throws(() => assertNoAliases(["fine", ["deeper", "John Doe"]], graph, "x"), ScramblerEgressError);
  assert.doesNotThrow(() => assertNoAliases({ q: "[CLIENT_1] v. [ORG_1] limitations", k: 3 }, graph, "x"));
});

test("public law coming back that contains an alias is scrubbed before the frontier sees it, and only the count is recorded", async () => {
  const { graph, scrambled } = await matter();
  const log: FrontierMessage[][] = [];
  const model: FrontierModel = async (messages) => { log.push(structuredClone(messages)); return messages.length === 2 ? { toolCalls: [{ name: "rag_query", args: { q: "res judicata" } }] } : { text: "Done, [CLIENT_1]." }; };
  // "Doe" and "Salinas" as parties of a published, cited case are public law and stay (the same caption rule
  // the document gets); the same strings in the passage's prose are the client's aliases and are replaced.
  const r = await answerScrambled({ question: "advise", scrambled, graph, model, tools: { rag_query: async () => ({ hits: [{ name: "Doe v. Salinas, 12 S.W.3d 34 (Tex. 1999)", text: "The court held that Salinas owed no duty to Doe as a matter of law." }] }) } });
  assert.equal(r.tool_results_scrubbed, 1);
  const toolMsg = log[1].find((m) => m.role === "tool")!;
  assert.ok(toolMsg.content.includes("Doe v. Salinas, 12 S.W.3d 34"), `the cited caption is public law and survives: ${toolMsg.content}`);
  assert.ok(toolMsg.content.includes("[ATTORNEY_1] owed no duty to [CLIENT_1]"), `prose mentions are scrubbed: ${toolMsg.content}`);
  assert.equal(r.answer, "Done, John Doe.");
});

test("context that was NOT scrambled is refused before the first turn: the belt catches what the brace missed", async () => {
  const { graph } = await matter();
  let turns = 0;
  const model: FrontierModel = async () => { turns++; return { text: "x" }; };
  await assert.rejects(answerScrambled({ question: "advise", scrambled: DOC, graph, model, tools: {} }), (e: unknown) => e instanceof ScramblerEgressError && /initial messages/.test(e.message));
  assert.equal(turns, 0);
});

test("the step bound is a bound: tools are withheld on the last turn and a model that still wants one gets no answer", async () => {
  const { graph, scrambled } = await matter();
  const offered: number[] = [];
  const model: FrontierModel = async (_m, tools) => { offered.push(tools.length); return { toolCalls: [{ name: "rag_query", args: { q: "anything" } }] }; };
  await assert.rejects(answerScrambled({ question: "advise", scrambled, graph, model, tools: { rag_query: async () => ({}) }, maxSteps: 3 }), /maxSteps \(3\) exhausted/);
  assert.deepEqual(offered, [1, 1, 0]);
});

test("an unknown tool and a throwing tool are reported to the model as errors, not raised, and their text is scrubbed too", async () => {
  const { graph, scrambled } = await matter();
  const log: FrontierMessage[][] = [];
  const model: FrontierModel = async (messages) => { log.push(structuredClone(messages)); return messages.length === 2 ? { toolCalls: [{ name: "nope", args: {} }, { name: "citations_check", args: { citations: ["1 S.W. 1"] } }] } : { text: "ok" }; };
  const r = await answerScrambled({ question: "advise", scrambled, graph, model, tools: { citations_check: async () => { throw new Error("backend down, per John Doe"); } } });
  assert.deepEqual(r.tool_calls_made.map((c) => c.ok), [false, false]);
  const tools = log[1].filter((m) => m.role === "tool");
  assert.equal(tools.length, 2);
  assert.ok(!seen(log).includes("John Doe"), "an error message carried a name to the frontier");
  assert.equal(r.tool_results_scrubbed, 1);
});

test("the paid frontier cannot be constructed without SCRAMBLER_FRONTIER_LIVE=1", () => {
  const saved = process.env.SCRAMBLER_FRONTIER_LIVE; delete process.env.SCRAMBLER_FRONTIER_LIVE;
  try { assert.throws(() => deepseekFlash(), /disarmed/); } finally { if (saved !== undefined) process.env.SCRAMBLER_FRONTIER_LIVE = saved; }
});

test("httpTools pins retrieval to public law, clamps k, and never fetches for an empty citation list", async () => {
  const posted: { url: string; body: Record<string, unknown> }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => { posted.push({ url, body: JSON.parse(String(init.body)) }); return new Response(JSON.stringify({ ok: 1 }), { status: 200, headers: { "content-type": "application/json" } }); }) as unknown as typeof fetch;
  const t = httpTools({ baseUrl: "http://x/", apiKey: "k", fetchFn });
  await t.rag_query({ q: "limitations", k: 999, sources: ["private-matter-store"] });
  assert.equal(posted[0].url, "http://x/api/v1/rag/query");
  assert.deepEqual(posted[0].body.sources, [...PUBLIC_LAW_SOURCES]); assert.equal(posted[0].body.k, MAX_K);
  assert.deepEqual(await t.citations_check({ citations: [] }), { error: "citations must be a non-empty array of strings" });
  assert.equal(posted.length, 1, "an empty citation list must not make a request");
  const err = await t.rag_query({ q: "x" }) as { error?: string };
  assert.equal(err.error, undefined);
});

test("toModelMessages carries tool calls and tool results in the AI SDK shape, with results as text", () => {
  const m = toModelMessages([
    { role: "system", content: "s" }, { role: "user", content: "u" },
    { role: "assistant", content: "thinking", toolCalls: [{ id: "c1", name: "rag_query", args: { q: "q" } }] },
    { role: "tool", toolCallId: "c1", name: "rag_query", content: "{\"hits\":[]}" },
  ]);
  assert.equal(m.length, 4);
  const a = m[2].content as { type: string }[]; assert.deepEqual(a.map((p) => p.type), ["text", "tool-call"]);
  const t = m[3].content as { type: string; output: { type: string; value: string } }[]; assert.equal(t[0].type, "tool-result"); assert.equal(t[0].output.value, "{\"hits\":[]}");
});
