// Node 5 of the scrambler graph: the frontier orchestrator. See docs/SCRAMBLER.md.
//
// This is the ONLY step that leaves our hardware, and it leaves with placeholders. The contract is the mirror
// image of the local model's: the local model sees the client's facts and may write nothing anyone reads; the
// frontier model writes the answer and may see nothing that is a fact. Two egress paths exist here and both are
// guarded by the same check, because a tool call is just a message with a different envelope:
//
//   1. every message we send — system, question, scrambled context, tool results — is swept for every alias the
//      matter graph knows, and the request is refused (thrown) if one is present. `scramble()` already ran on the
//      document; this is the belt to that brace, and it uses plain substring containment (as the release gate in
//      index.ts does) rather than the word-bounded substitution regex, so a boundary the scrambler missed throws
//      rather than leaks;
//   2. every tool call's arguments get the identical sweep BEFORE the tool runs. The tools operate on public law
//      only (statutes, Texas opinions, the citation table), so there is no legitimate reason for a client name to
//      appear in one; if it does, the model has either guessed a real name or something upstream leaked, and
//      either way the answer stops there.
//
// Tool RESULTS are public law coming back in, and public law can coincidentally contain a string the graph holds
// as an alias ("Doe" in a published caption). Rather than throw on our own retrieval, results are run through the
// same deterministic `scramble()` before they are appended, so the frontier's view stays placeholders-only in
// both directions and the count is recorded. Code does the substitution; no model text is ever used as a mapping.
//
// The model is injected as a function so every test runs against a fake. `deepseekFlash()` builds the real one
// over the repo's OpenRouter path and is DISARMED until SCRAMBLER_FRONTIER_LIVE=1: node 5 is the one paid step
// and the one that talks to a third party, and neither happens by accident.
import { resolveModel } from "./llm";
import { MAX_CITATIONS, MAX_K } from "./limits";
import type { MatterGraph } from "./graph";
import { scramble, unscramble, residualAliases } from "./apply";

export type ToolCall = { name: string; args: Record<string, unknown>; id?: string };
export type FrontierMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string; toolCalls?: ToolCall[] }
  | { role: "tool"; toolCallId: string; name: string; content: string };
export type ToolSchema = { name: string; description: string; inputSchema: Record<string, unknown> };
/** The frontier model, as a function: one turn in, text or tool calls out. Stateless — the orchestrator owns the
 *  transcript, so nothing the model is shown can be anything the orchestrator did not sweep first. */
export type FrontierModel = (messages: FrontierMessage[], toolSchemas: ToolSchema[]) => Promise<{ text?: string; toolCalls?: ToolCall[] }>;
export type ToolFn = (args: Record<string, unknown>) => Promise<unknown>;
export type ToolSet = Record<string, ToolFn>;

export type OrchestrateResult = {
  answer: string;
  /** Placeholders in the answer the graph does not know: reported, never guessed at (apply.ts). */
  unknown_placeholders: string[];
  /** Model turns taken, including the answering turn. */
  steps: number;
  tool_calls_made: { name: string; args: Record<string, unknown>; ok: boolean }[];
  /** Tool results in which `scramble()` replaced at least one alias before the frontier saw them. A count, never a value. */
  tool_results_scrubbed: number;
};

export const DEFAULT_MAX_STEPS = 6;
export const FRONTIER_MODEL_ID = "deepseek/deepseek-v4-flash";
/** The only sources the frontier's retrieval tool may search: public law. Pinned here, not chosen by the model. */
export const PUBLIC_LAW_SOURCES = ["statutes", "tx"] as const;

/** Thrown when a message or a tool argument bound for the frontier contains a matter alias. The message carries
 *  the count and the location, never the alias — the ledger records values nowhere, and an error string is a log. */
export class ScramblerEgressError extends Error {
  constructor(readonly where: string, readonly count: number) {
    super(`scrambler: refusing egress at ${where}: ${count} matter alias(es) present in outbound content`);
    this.name = "ScramblerEgressError";
  }
}

/** Every string reachable inside a value: strings, array items, object keys and values, recursively. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v as Record<string, unknown>)) { out.push(k); strings(x, out); }
  return out;
}

/** The egress check. Throws if any alias the graph holds appears anywhere in `value`. */
export function assertNoAliases(value: unknown, graph: MatterGraph, where: string): void {
  let n = 0;
  for (const s of strings(value)) n += residualAliases(s, graph).length;
  if (n) throw new ScramblerEgressError(where, n);
}

export const TOOL_SCHEMAS: Record<string, ToolSchema> = {
  rag_query: {
    name: "rag_query",
    description: "Search public Texas law — statutes and Texas appellate opinions — and return the top passages with their citations. Use it to ground any legal proposition before you state it. This searches published law only; it knows nothing about the parties in this matter.",
    inputSchema: { type: "object", properties: { q: { type: "string", description: "The legal question or proposition to search for, in plain words. Do not include placeholders like [CLIENT_1]; describe the issue generically." }, k: { type: "integer", minimum: 1, maximum: MAX_K, description: "How many passages to return (default 5)." } }, required: ["q"], additionalProperties: false },
  },
  citations_check: {
    name: "citations_check",
    description: "Verify that reporter citations (e.g. '725 S.W.2d 705') exist in the DocketRouter library. A citation not found comes back 'unverified', never 'fabricated'. Check every citation before it appears in your answer.",
    inputSchema: { type: "object", properties: { citations: { type: "array", items: { type: "string" }, minItems: 1, maxItems: MAX_CITATIONS } }, required: ["citations"], additionalProperties: false },
  },
};

const GENERIC_SCHEMA = (name: string): ToolSchema => ({ name, description: `Tool ${name}.`, inputSchema: { type: "object", properties: {}, additionalProperties: true } });
export const schemasFor = (tools: ToolSet): ToolSchema[] => Object.keys(tools).map((n) => TOOL_SCHEMAS[n] ?? GENERIC_SCHEMA(n));

export const FRONTIER_SYSTEM_PROMPT = `You are a legal research assistant answering a question about a matter whose participants have been pseudonymised. Tokens like [CLIENT_1], [ORG_2] or [ATTORNEY_1] stand for specific people and organisations; treat each as a proper name, keep every one EXACTLY as written, and never invent a new one. Nobody will tell you who they are and you must not guess.

Ground every legal proposition in public law using the tools, cite statutes and cases exactly as the tools return them, and say plainly when the library did not support a point. Tool inputs must describe the legal issue generically; never put a placeholder or a party description into a search. Answer in plain prose.`;

/** Run one question through the frontier with tools, under the egress guard, and restore the names. */
export async function answerScrambled(opts: { question: string; scrambled: string; graph: MatterGraph; model: FrontierModel; tools: ToolSet; maxSteps?: number }): Promise<OrchestrateResult> {
  const { graph, model, tools } = opts;
  const maxSteps = Math.max(1, Math.floor(opts.maxSteps ?? DEFAULT_MAX_STEPS));
  // The question is the caller's text and may name the client outright; it goes through the same deterministic
  // substitution as the document. The context is expected to be scrambled already; the sweep below proves it.
  const question = scramble(opts.question, graph);
  const messages: FrontierMessage[] = [
    { role: "system", content: FRONTIER_SYSTEM_PROMPT },
    { role: "user", content: `${question}\n\n<<<MATTER CONTEXT (pseudonymised)>>>\n${opts.scrambled}\n<<<END MATTER CONTEXT>>>` },
  ];
  assertNoAliases(messages, graph, "initial messages");

  const schemas = schemasFor(tools);
  const tool_calls_made: OrchestrateResult["tool_calls_made"] = [];
  let tool_results_scrubbed = 0;
  let steps = 0;

  while (steps < maxSteps) {
    steps++;
    // On the final permitted turn the tools are withheld, so the model must answer with what it has gathered
    // rather than spend the last step on a call whose result nobody would read.
    const offered = steps === maxSteps ? [] : schemas;
    assertNoAliases(messages, graph, `step ${steps} outbound messages`);
    const r = await model(messages, offered);

    if (r.toolCalls && r.toolCalls.length) {
      if (!offered.length) break; // the bound is spent and the model still wants a tool: refuse below
      const calls = r.toolCalls.map((c, i) => ({ ...c, id: c.id ?? `call_${steps}_${i}`, args: (c.args && typeof c.args === "object" ? c.args : {}) as Record<string, unknown> }));
      messages.push({ role: "assistant", content: r.text ?? "", toolCalls: calls });
      for (const call of calls) {
        // The second egress path, guarded identically to the first. This throws; a tool never runs on a leak.
        assertNoAliases(call.args, graph, `tool call ${call.name} arguments`);
        let result: unknown; let ok = true;
        const fn = tools[call.name];
        if (!fn) { result = { error: `unknown tool ${call.name}` }; ok = false; }
        else { try { result = await fn(call.args); } catch (e) { result = { error: (e as Error).message.slice(0, 300) }; ok = false; } }
        tool_calls_made.push({ name: call.name, args: call.args, ok });
        // Public law coming back in: any alias it happens to contain is replaced by its placeholder, deterministically.
        const raw = typeof result === "string" ? result : JSON.stringify(result ?? null);
        const scrubbed = scramble(raw, graph);
        if (scrubbed !== raw) tool_results_scrubbed++;
        messages.push({ role: "tool", toolCallId: call.id, name: call.name, content: scrubbed });
      }
      continue;
    }

    if (typeof r.text === "string") {
      const back = unscramble(r.text, graph);
      return { answer: back.text, unknown_placeholders: back.unknown, steps, tool_calls_made, tool_results_scrubbed };
    }
    throw new Error(`scrambler: frontier returned neither text nor tool calls at step ${steps}`);
  }
  throw new Error(`scrambler: maxSteps (${maxSteps}) exhausted without an answer; ${tool_calls_made.length} tool call(s) made`);
}

/* ── Default tools: the two public-law endpoints over HTTP ──────────────────────────────────────────────────────
 * Both wrap routes that themselves wrap library calls, so a tool call and the matching REST call return the same
 * answer. Sources for retrieval are pinned to PUBLIC_LAW_SOURCES here and are not an argument the model can set. */
export function httpTools(opts: { baseUrl?: string; apiKey?: string; timeoutMs?: number; fetchFn?: typeof fetch } = {}): ToolSet {
  const base = (opts.baseUrl ?? process.env.DOCKETROUTER_BASE_URL ?? "https://docketrouter.ai").replace(/\/+$/, "");
  const key = opts.apiKey ?? process.env.DOCKETROUTER_API_KEY;
  const f = opts.fetchFn ?? fetch;
  const post = async (path: string, body: unknown): Promise<unknown> => {
    const r = await f(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000) });
    const j: unknown = await r.json().catch(() => ({}));
    if (!r.ok) return { error: `${path} returned ${r.status}`, detail: (j as { error?: unknown })?.error ?? null };
    return j;
  };
  const clampInt = (v: unknown, lo: number, hi: number, dflt: number) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt; };
  return {
    rag_query: (a) => post("/api/v1/rag/query", { q: String(a.q ?? "").slice(0, 600), k: clampInt(a.k, 1, MAX_K, 5), sources: [...PUBLIC_LAW_SOURCES] }),
    citations_check: (a) => {
      const cites = (Array.isArray(a.citations) ? a.citations : [a.citations]).filter((c): c is string => typeof c === "string" && c.trim().length > 0).slice(0, MAX_CITATIONS);
      return cites.length ? post("/api/v1/citations/check", { citations: cites }) : Promise.resolve({ error: "citations must be a non-empty array of strings" });
    },
  };
}

/* ── The real frontier: DeepSeek V4 Flash over OpenRouter ───────────────────────────────────────────────────────
 * Same resolveModel() path as every other upstream call, so attribution, usage accounting and key handling are
 * the repo's, not this file's. Reasoning is switched off explicitly: llm.ts records that on this model id
 * enabled:false is the one lever that reliably yields visible text on every upstream route. data_collection:
 * "deny" asks OpenRouter for a no-retention route (docs/OPENROUTER-STUDY.md), which SCRAMBLER.md requires of node 5.
 *
 * DISARMED BY DEFAULT. Constructing this without SCRAMBLER_FRONTIER_LIVE=1 throws before `ai` is even imported,
 * so a test, a script or a misrouted call cannot spend credit or send a placeholder transcript off the box. */
export function deepseekFlash(opts: { apiKey?: string | null; timeoutMs?: number; maxOutputTokens?: number; modelId?: string } = {}): FrontierModel {
  if (process.env.SCRAMBLER_FRONTIER_LIVE !== "1") throw new Error("scrambler: the frontier model is disarmed; set SCRAMBLER_FRONTIER_LIVE=1 to allow node 5 to spend OpenRouter credit");
  const id = opts.modelId ?? FRONTIER_MODEL_ID;
  return async (messages, toolSchemas) => {
    const { generateText, tool, jsonSchema } = await import("ai");
    type Schema = Parameters<typeof jsonSchema>[0];
    const tools = Object.fromEntries(toolSchemas.map((s) => [s.name, tool({ description: s.description, inputSchema: jsonSchema(s.inputSchema as Schema) })]));
    // ai v7: a system message may not travel in `messages`; it goes in `instructions`. Measured 2026-09-21 on the
    // first live run: "System messages are not allowed in the prompt or messages fields. Use the instructions option".
    const instructions = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const r = await generateText({
      model: resolveModel(id, opts.apiKey, { title: "DocketRouter Scrambler" }),
      ...(instructions ? { instructions } : {}),
      messages: toModelMessages(messages.filter((m) => m.role !== "system")),
      ...(toolSchemas.length ? { tools } : {}),
      temperature: 0,
      maxOutputTokens: opts.maxOutputTokens ?? 1_500,
      abortSignal: AbortSignal.timeout(opts.timeoutMs ?? 120_000),
      providerOptions: { openrouter: { reasoning: { enabled: false }, provider: { data_collection: "deny" } } },
    });
    const toolCalls: ToolCall[] = r.toolCalls.map((c) => ({ id: c.toolCallId, name: c.toolName, args: (c.input && typeof c.input === "object" ? c.input : {}) as Record<string, unknown> }));
    return toolCalls.length ? { text: r.text || undefined, toolCalls } : { text: r.text };
  };
}

/** Our transcript shape → the AI SDK's. Tool results travel as text so no provider re-serialises them. */
export function toModelMessages(messages: FrontierMessage[]): import("ai").ModelMessage[] {
  return messages.map((m): import("ai").ModelMessage => {
    if (m.role === "tool") return { role: "tool", content: [{ type: "tool-result", toolCallId: m.toolCallId, toolName: m.name, output: { type: "text", value: m.content } }] };
    if (m.role === "system" || m.role === "user") return { role: m.role, content: m.content };
    {
      const a = m as Extract<FrontierMessage, { role: "assistant" }>;
      const parts: import("ai").AssistantContent = [];
      if (a.content) parts.push({ type: "text", text: a.content });
      for (const c of a.toolCalls ?? []) parts.push({ type: "tool-call", toolCallId: c.id ?? c.name, toolName: c.name, input: c.args });
      return { role: "assistant", content: parts.length ? parts : "" };
    }
  });
}
