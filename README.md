# legal-scrambler

Pseudonymise a legal case file **on your own hardware** before a frontier model sees it, get the answer back,
and un-scramble it — with the client's names, numbers and addresses never leaving your box.

This is the **lite edition** — the Weenie Hut Jr. version. The library, its proof harness and a 167-document
adversarial battery are here in full. The hosted service around it (encrypted per-caller matter store behind API
keys, the verified public-law tools the frontier step is allowed to call, live-model monitoring, the forty real
court dockets the proof runs over) lives in DocketRouter. What is here is enough to run the pipeline end to end
on a laptop with Ollama, and to measure it.

Made by [DocketX](https://huggingface.co/docketx). Apache-2.0.

## The one rule

**The local model never writes text that anyone reads.** It proposes *spans* — "these characters of the input
are a PERSON" — and code does every substitution, in both directions. A prompt injection hidden in a client
document can therefore achieve, at worst, a bad span proposal, and every proposal is checked against the input
before the matter graph will hold it. The frontier model (the one paid, third-party step) sees placeholders
only, and every message and every tool argument bound for it is swept for every alias the matter knows; a hit
throws rather than leaks.

```
client document ──► normalise ──► regex spans ──► local model proposes spans ──► guard validates
                                                                                        │
      answer ◄── un-scramble ◄── frontier model (placeholders only, tools swept) ◄── scramble (code)
```

The pipeline **refuses rather than degrades**: a document it cannot release cleanly is not released partially,
and a placeholder in an answer that the graph does not know is reported, never guessed at.

## Measured, not claimed

Two different kinds of number, kept apart on purpose.

**The proof** (`npm run prove`, no model in the loop — this is a proof of the *pipeline*, run 2026-09-20 at
DocketRouter commit `96fed4da2`, 242 tests, 0 failures):

- 1,000 fuzz-generated filings × 3 adversarial fake models (competent, hijacked, lazy): no secret leaves, no
  citation harmed, every release round-trips.
- 167-document battery, planted secrets proposed exactly: **0 leaks** of 3,214 secrets across 12 types under
  the oracle and the hijacked model.
- Byte-exact restore of every battery document through 4k chunks and the cross-chunk pass.
- 40 real federal dockets (public RECAP filings) under perfect spans: 1,984 entities present, **0 leaked**,
  1,960 of 1,960 on one placeholder each, 6,200 of 6,200 chunks byte-exact, 3,994 reporter citations in and
  0 lost, 0 filings refused.
- 56 red-team attacks on the guard (injection, look-alikes, coref cycles, citation components, glued names) —
  none leak.

The table is in [docs/SCRAMBLER-PROOF.md](docs/SCRAMBLER-PROOF.md).

**The local model's leak rate** (a *measurement* of `qwen3:8b`, not a claim about the pipeline): on the same
167 documents, 4,000-char chunks, fourth reading 2026-09-20 — **25 of 3,191 secret occurrences leaked, 7.8 per
1,000, Wilson 95% [5.3, 11.5]**, 0 citations destroyed. That number is what the 8B model misses; a bigger local
model will do better, and the harness (`npm run battery`) will tell you by how much. The whole history of
readings, including the ones that went wrong and why, is in [docs/SCRAMBLER.md](docs/SCRAMBLER.md).

## Run it

Needs Node 22+ and, to scramble anything real, an [Ollama](https://ollama.com) model on your own machine.

```sh
npm install
npm test            # ~2.5 min: unit, red-team, fuzz (300 seeds), battery, restore, orchestrator — no model needed
npm run prove       # the full proof at proof scale (1,000 seeds, all 167 documents); ~15 min
```

```sh
ollama pull qwen3:8b
LIAISON_MODEL=local/qwen3:8b npm run battery     # measure the model's own leak rate on the battery
```

`LIAISON_MODEL` must be `local/<ollama model>`; `liaison.ts` refuses anything else, so a misconfiguration
cannot send a client document to an upstream provider. `LOCAL_LLM_BASE_URL` defaults to
`http://127.0.0.1:11434`.

## Use it as a library

```ts
import { MatterGraph, scrambleDocument, restoreDocument, unscramble } from "@docketx/legal-scrambler";
import { localScrambler } from "@docketx/legal-scrambler/liaison";

const graph = new MatterGraph();                       // one graph per matter: the same client is the same placeholder in every filing
const model = localScrambler("local/qwen3:8b");        // refuses any non-local id
const r = await scrambleDocument(text, graph, model);  // { scrambled, stats, rejected, degraded, occurrences, restore_basis }

// ... send r.scrambled to whatever you like; it holds placeholders, not facts ...

const answer = unscramble(frontierAnswer, graph);      // unknown placeholders are reported in the result, never guessed
```

`restoreDocument` gives the original bytes back from the scramble ledger; `store.ts` seals graphs and a
content-addressed cache with AES-256-GCM under `SCRAMBLER_MASTER_KEY` (32 bytes), keyed per owner and matter.
The frontier step is `orchestrate.ts` and is **disarmed** until `SCRAMBLER_FRONTIER_LIVE=1`: it is the one paid
step and the one that talks to a third party, and neither happens by accident. It never uses a GPT/OpenAI model.

## What is in the box

| path | what |
|---|---|
| `src/` | the pipeline: `normalize` → `patterns` → `guard` → `apply` → `graph`, `index.ts` executes it; `orchestrate.ts` is the frontier step; `store.ts` the sealed store; `measure.ts` the leak-rate harness |
| `tests/` | 230 tests, all offline. `scrambler-redteam.test.ts` is the attacker; `scrambler-proof.test.ts` states the invariants P1–P7 |
| `data/battery/` | 167 synthetic adversarial filings with typed ground truth (generated by DeepSeek; every planted secret verified verbatim in the text before it counts). No real person is in it |
| `scripts/` | `scrambler-prove.ts` (the proof), `scrambler-battery-liaison.ts` (measure a local model), `scrambler-leak-rate.ts`, `scrambler-casefile.ts` (real dockets), `scrambler-battery-gen.ts` (regenerate the battery; spends OpenRouter credit) |
| `docs/` | the design and its full measurement history, the proof table, a landscape review, and two architecture reviews |

Not in the box: the forty real dockets (public filings, but real people — fetch RECAP dockets yourself and
`scrambler-proof.test.ts` picks them up under `data/dockets/`), and the HTTP layer.

## Threat model in one paragraph

The client document is hostile: it may contain instructions aimed at the model, look-alike characters, zero-width
joins, names glued to line breaks, defined terms ("the Company"), and citations whose party names must *not*
be scrambled because public law is public. The local model is untrusted: it may be lazy, wrong, or hijacked by
the document. The frontier model is untrusted with facts and trusted with nothing else. The code is the only
thing that writes. Every invariant above is a test that plays one of those attackers.

## Open law to go with it

The frontier step is only worth taking if the model can ground its answer in real law. DocketX publishes
public-domain legal corpora on Hugging Face — [huggingface.co/docketx](https://huggingface.co/docketx) — and a
free, keyless citation-existence check at `POST https://docketrouter.ai/api/public/citation-check`.
