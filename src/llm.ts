// The two model paths the scrambler may use, and the wall between them.
//
//   LOCAL   `local/<ollama model>` — the private liaison on your own hardware. It is the ONLY model that ever sees a
//           client document (liaison.ts refuses anything else). Reached through Ollama's native chat API with
//           think:false: via the OpenAI-compatible path a Qwen3-class model spends its whole output budget on hidden
//           thinking and returns an empty string (observed: 600 tokens, finish=length, text "").
//   FRONTIER any "provider/model" id over OpenRouter — used by node 5 (orchestrate.ts) and it sees placeholders only.
//           Disarmed until SCRAMBLER_FRONTIER_LIVE=1. Never a GPT/OpenAI model (house rule, enforced in resolveModel).
//
// This file is the standalone edition of DocketRouter's src/lib/llm.ts, cut down to what the scrambler needs.
import type { LanguageModel } from "ai";

export const LIAISON_MODEL = process.env.LIAISON_MODEL || null;
export const isLocalModel = (id: string) => id.startsWith("local/");
/** Qwen3-class local models emit a <think> block first; strip it before parsing any structured output. */
export const stripThink = (t: string) => t.replace(/<think>[\s\S]*?<\/think>/g, "").trim();

const LIAISON_TIMEOUT_MS = () => Number(process.env.LIAISON_TIMEOUT_MS ?? 120_000);
const localBase = () => (process.env.LOCAL_LLM_BASE_URL ?? "http://127.0.0.1:11434").replace(/\/v1\/?$/, "");

/** "provider/model" → an AI SDK model. Local ids go to your Ollama; everything else goes through OpenRouter. */
export function resolveModel(id: string, apiKey?: string | null, opts?: { title?: string }): LanguageModel {
  if (isLocalModel(id)) {
    const { createOpenAI } = requireSync<typeof import("@ai-sdk/openai")>("@ai-sdk/openai");
    return createOpenAI({ baseURL: `${localBase()}/v1`, apiKey: process.env.LOCAL_LLM_API_KEY ?? "local" }).chat(id.slice(6));
  }
  if (/^(openai|gpt)[/-]/i.test(id)) throw new Error(`refusing ${id}: GPT/OpenAI models are not used by this project`);
  const key = apiKey ?? process.env.OPENROUTER_API_KEY;
  if (!key) throw new Error("OPENROUTER_API_KEY is required for a frontier model (or pass apiKey)");
  const { createOpenRouter } = requireSync<typeof import("@openrouter/ai-sdk-provider")>("@openrouter/ai-sdk-provider");
  const title = opts?.title ?? process.env.LEGAL_SCRAMBLER_APP_TITLE ?? "legal-scrambler";
  return createOpenRouter({ apiKey: key, headers: { "HTTP-Referer": "https://github.com/docketx/legal-scrambler", "X-Title": title } })(id, { usage: { include: true } });
}

/** Plain-text completion. Local models use Ollama's native chat API (think:false, temperature 0); frontier models go
 *  through the AI SDK with reasoning disabled. `format` is Ollama's JSON-schema constrained decoding. */
export async function liaisonText(modelId: string, prompt: string, opts: { maxTokens?: number; timeoutMs?: number; format?: unknown } = {}): Promise<string> {
  if (isLocalModel(modelId)) {
    const r = await fetch(`${localBase()}/api/chat`, { method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(opts.timeoutMs ?? LIAISON_TIMEOUT_MS()),
      body: JSON.stringify({ model: modelId.slice(6), messages: [{ role: "user", content: prompt }], stream: false, think: false, ...(opts.format ? { format: opts.format } : {}), options: { temperature: 0, num_predict: opts.maxTokens ?? 200 } }) });
    if (!r.ok) throw new Error(`liaison ${r.status}`);
    const j = (await r.json()) as { message?: { content?: string } };
    return stripThink(j.message?.content ?? "");
  }
  const { generateText } = await import("ai");
  const r = await generateText({ model: resolveModel(modelId), temperature: 0, maxOutputTokens: opts.maxTokens ?? 200, abortSignal: AbortSignal.timeout(opts.timeoutMs ?? LIAISON_TIMEOUT_MS()), providerOptions: { openrouter: { reasoning: { enabled: false } } }, prompt });
  return r.text;
}

// The provider packages are optional peers: the library, its tests and the proof run need neither. They are
// loaded only when a model is actually resolved, so a checkout without them still type-checks and tests.
import { createRequire } from "node:module";
function requireSync<T>(name: string): T {
  try { return createRequire(import.meta.url)(name) as T; }
  catch { throw new Error(`${name} is not installed; it is only needed to call a model (npm i ${name})`); }
}
