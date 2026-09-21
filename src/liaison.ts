// The only model the scrambler may ever call: the private liaison on our own hardware.
//
// Founder 2026-09-15: "we use private inference, untraceable, to do our scrambling." That is a code invariant
// here, not a configuration hope. `localScrambler()` refuses to construct a model function for anything that is
// not a local Ollama id (`local/...`), so a misconfigured LIAISON_MODEL pointing at OpenRouter can never receive
// a client document. Untraceable means: the document goes to one process on one box we own, over the tunnel we
// already run for retrieval; the model gets no tools and no network; the ledger records counts and reasons, never
// values; and nothing is retained on the model side because Ollama retains nothing between calls.
//
// The FRONTIER step (node 5) is a different function with a different contract: it sees placeholders only and
// may use tools, because tools there operate on public law, not on the client's facts. See orchestrate.ts.
import { LIAISON_MODEL, isLocalModel, liaisonText } from "./llm";
import type { LocalModel } from "./index";

export function localScrambler(modelId: string | null = LIAISON_MODEL): LocalModel {
  if (!modelId) throw new Error("scrambler: no LIAISON_MODEL configured; scrambling requires the private liaison and will not fall back to an upstream model");
  if (!isLocalModel(modelId)) throw new Error(`scrambler: refusing ${modelId} — client documents go to the private liaison only (local/*), never to an upstream provider`);
  // 8,000 output tokens, not 4,000: a 6k-char chunk of an appellate opinion produced a span list that was cut at
  // ~12k chars on the first measured run (2026-09-15). The salvage path in parseProposal is the backstop; this is
  // the budget that keeps it from being needed.
  return (prompt, format) => liaisonText(modelId, prompt, { format, maxTokens: Number(process.env.SCRAMBLER_MAX_TOKENS ?? 8000), timeoutMs: Number(process.env.SCRAMBLER_TIMEOUT_MS ?? 300_000) });
}
