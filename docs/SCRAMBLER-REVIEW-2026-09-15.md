# Five-model adversarial review of the scrambler — 2026-09-15

Founder asked for five OpenRouter models to review the whole plan. **Six upstream calls were made** (one
DeepSeek call returned empty content under reasoning mode and crashed the script; all five were re-run with
reasoning disabled). **Total cost: $0.018.** Models: DeepSeek V4 Flash, Gemini 2.5 Flash, Qwen3-235B,
Mistral Medium 3, Kimi K2. No GPT. Raw reviews kept in the session scratchpad; this is the digest, sorted by
what we did with each point — and every "already covered" claim below names the test that covers it, because
a review that says "you might be vulnerable to X" is only worth something once X has been tried.

## Already covered — the reviewers could not see the test file

| raised by | attack | covered by |
|---|---|---|
| all five | Unicode homoglyphs / zero-width characters | `scrambler-redteam` 1b–1d: a confusable proposed verbatim is substituted with unicode-aware boundaries; a confusable *evasion* is caught |
| Qwen, Mistral | straddling / overlapping spans | 3a–3d; interval-based substitution over the original text |
| Qwen, Mistral, DeepSeek | placeholder look-alikes, fragments spliced into placeholders | 4 (seven variants), 9a; refused as spans and at the release gate |
| Kimi, Mistral | coref merging judge into client, coref cycles | 7a–7c; `link()` requires type compatibility, runs after all spans, is a no-op on cycles |
| Qwen, Mistral | span flood pushing a real name past the cap | 6c–6d; proposals past 500 are ledgered `over-limit`, never dropped |
| Qwen | case / whitespace / apostrophe variants | 2a–2e; matching is case-insensitive and tolerant of line-wraps and typographic quotes |
| Kimi | cited-caption exclusion "understates" the rate | it is reported under its own `caption_only` heading, not hidden; leaving cited captions intact is a design choice the citation gate depends on |

## New, and adopted as the next build items

1. **Identifier classes the regex pass does not cover** (Kimi, Mistral, Qwen): bar numbers, Bates numbers,
   internal matter/claim numbers, TINs/EINs, passport numbers, VINs, licence plates, medical record numbers.
   Cheap, high precision. → `patterns.ts`.
2. **Chunk-boundary straddle** (Kimi): a name split across two passes is missed by both. Split on paragraph
   boundaries already makes this rare; a 200-char overlap with de-duplication in the graph closes it. → harness
   and `paragraphs()`.
3. **NFKC-normalise before matching** (Mistral, Qwen): fold confusables and zero-width characters on the way
   *in*, so a variant spelling cannot exist in the input at all. The red-team shows variants are handled; folding
   them removes the class. Cost: one line, plus a test that the *output* preserves the original bytes elsewhere.
4. **Measurement gaps** (Gemini, Kimi, Qwen, Mistral — the strongest section across all five):
   occurrence-level rate alongside name-level (a name appearing fifty times weighs the same as once today);
   a confidence interval on any published number; an **over-scrubbing** rate (citations destroyed is the only
   utility metric now); cross-document consistency measured on a multi-document matter; and leak classes beyond
   names, which needs ground truth we do not have from `redaction_map`. → `measure.ts`.
5. **Whole-document metadata** (Mistral): PDF/DOCX author, comments, tracked changes and hidden text layers
   bypass a text-only pipeline. Belongs to the document-layer node already named in `SCRAMBLER.md`.
6. **Residual re-identification is unmeasured** (DeepSeek, Kimi): true, stated in the design as a limit, and
   no reviewer proposed a measurable metric. Stays a stated limit until one exists.

## Rejected, with the reason

- **Differential privacy on span "confidence scores"** (Kimi): there are no confidence scores; the model emits
  spans, and the guard is the control. Noise would add nothing but recall loss.
- **HMAC blind alias hints** (Kimi): the hints go to the *local* model on our hardware. The frontier never sees
  them. There is no search-query leakage path to close.
- **Timing side-channel on the cache** (Kimi): cache keys include owner and matter; document equality is only
  observable within a caller's own matter, where the caller already knows the document.
- **Cryptographic checksums on span proposals** (Qwen): the local model is not the trust boundary — the guard is.
  A signed bad proposal is still a bad proposal; the guard rejects it either way.
- **"Restore-direction sanitizer" for instructions around placeholders** (DeepSeek, Gemini): un-scramble is a
  deterministic string map; it does not execute anything. Instructions in a frontier answer are the frontier
  layer's problem and the existing citation gate's, not the scrambler's.
- **Fuzzy / phonetic name matching** (Mistral): would over-scrub common words at scale; the derived-alias and
  variant rules already cover the observed cases, and every new one is added when measured, not guessed.

## Open source (section E, all five)

Four of five said yes for the library, no for the service, on the same reasoning we already hold: audits from
people who attack redaction for a living harden the guard faster than we can alone, and the proprietary value
is the private model, the encrypted per-matter store, the cache and the measured leak rate — none of which
ship with the library. The strongest argument against, from two reviewers: publishing the exact guard rules
hands an attacker the spec to craft around. That is real, and the answer to it is the measured leak rate on
adversarial documents, which an attacker can read but cannot lower. **Decision is the founder's.**

---

# Round two: ten models on the CODE, not the doc

Same day, after the fuzz suite landed. Ten OpenRouter calls, **$0.061**; nine returned (Gemini 2.5 Pro
rejected the reasoning-off flag with a 400). Each reviewer got `guard.ts`, `apply.ts`, `graph.ts`, `index.ts`
and `patterns.ts` and was told to demonstrate a bug with a concrete input or say nothing. The rule for this
round: **every claim with an input becomes a test.** A claim that survives its test is real and gets fixed; one
that does not is pinned as a passing test so it stays refuted.

| claim | from | held? | outcome |
|---|---|---|---|
| a complete proposal followed by trailing prose is salvaged | Mistral | **yes** | salvage now requires the array to never have been closed — `11a` |
| a caption party proposed as separate tokens is half-scrubbed ("[PERSON_1] Doe v. …") | Llama 4 | **yes** | caption segments are now bounded by name-token grammar — `11b` (two punctuation-based attempts failed first, both recorded) |
| a name near a citation is refused as a citation component | DeepSeek | no | pinned — `11c` |
| regex metacharacters in a span escape the matcher | DeepSeek | no | pinned — `11d` |
| an alias ending in punctuation mis-overlaps its shorter form | Gemini | no | pinned — `11e` |
| shared surname mis-attributed on restore | Qwen, Qwen-Coder, DeepSeek-chat, Mistral | already fixed | found by the fuzz suite one commit earlier; the reviewers reading the code independently arrived at the same defect, which is the best evidence the fix was needed |
| "John" and "Doe" accepted as two entities | Llama 3.3, Qwen-Coder | not a bug | separate proposals are separate spans by contract; the graph's coref and derived-alias rules are what join them |
| bare "CLIENT_1" in the input is refused / should be accepted | Mistral, Qwen (they disagree with each other) | not a bug | refusing to release is the intended outcome — red-team 4 |
| Kimi K2 | — | — | returned fragments of its own reasoning, no findings |

Net: two real defects from ten models at six cents. The doc-level round found design gaps; the code-level
round found bugs. Both are cheaper than one leak.
