# The scrambler landscape — what else exists, and how we compare

Research pass for the design in `docs/SCRAMBLER.md` (local model proposes spans, code substitutes,
guard validates against input, per-matter entity graph). Every factual claim below has a source URL
and the access date (all accessed 2026-09-15 unless noted). Where a number could not be found, this
says so explicitly rather than estimating.

## 0. The headline finding

**Our "model proposes spans, code substitutes" pattern is not novel — it is how Presidio itself is
built**, and it is how the strongest commercial results (Tonic Textual) work too. Presidio's Analyzer
returns recognized entities as typed spans (start/end offsets + confidence), and a separate
Anonymizer engine deterministically applies operators (replace/redact/hash/encrypt) — the model/NER
layer never writes the output text
([microsoft/presidio](https://github.com/microsoft/presidio), accessed 2026-09-15). Tonic Textual
uses the same split — proprietary NER models detect PII spans, a separate step substitutes
synthetic values — and their own benchmark shows detect-then-substitute beating "let the LLM do the
whole job" by a measured 4.3 points end-to-end (87.7% → 92.0%) with better recall (88.8% → 95.0%)
([tonic.ai/ai-model-benchmarks/privacy-bench](https://www.tonic.ai/ai-model-benchmarks/privacy-bench),
accessed 2026-09-15). What our design adds on top of that established pattern: the guard validates
every proposed span against the literal input text (defeating fabrication/injection), a persisted
per-matter entity graph (not a flat table) for cross-document consistency, and a release gate that
re-sweeps output before anything leaves the machine. See §5.

## 1. Open-source tools

### Microsoft Presidio
- **What it catches:** a configurable pipeline of regex/rule recognizers (structured PII — SSN,
  credit card, email, phone) plus a spaCy NLP model for contextual entities like person names
  ([microsoft.github.io/presidio](https://github.com/microsoft/presidio), accessed 2026-09-15).
- **Published precision/recall:** an independent evaluation reported baseline Presidio precision of
  0.254–0.230 and recall of 0.747–0.781 (F1 0.355–0.379) for the "Large"/"Transformer" spaCy
  variants — i.e., low precision (many false positives) out of the box, improved substantially by
  adding domain-specific recognizers
  ([Medium: How to evaluate PII Detection output with Presidio Evaluator](https://medium.com/@tranguyen221/how-to-evaluate-pii-detection-output-with-presidio-evaluator-3f2684ba3091),
  accessed 2026-09-15). Presidio's own evaluation docs recommend teams run `presidio-research` against
  their own corpus rather than trust a single published number
  ([microsoft/presidio-research](https://github.com/microsoft/presidio-research), accessed 2026-09-15).
- **License:** MIT, free for commercial use, no publish-your-code obligation. Presidio is mid-transition
  from a Microsoft-owned repo to a community-governed one at `data-privacy-stack/presidio`, staying MIT
  ([github.com/microsoft/presidio/blob/main/LICENSE](https://github.com/microsoft/presidio/blob/main/LICENSE);
  [presidio.dataprivacystack.org/project_transition](https://presidio.dataprivacystack.org/project_transition/),
  accessed 2026-09-15).
- **Offline:** yes — it's a local Python library; no network call is required for the core
  analyzer/anonymizer.
- **Architecture note:** this is the same detect-then-substitute split our design uses, just with a
  weaker detector (spaCy NER / regex instead of an LLM) and no guard against a hostile input document.

### spaCy NER
- **What it is:** a general-purpose NLP/NER library, not a PII product. Presidio uses it as one
  recognizer among several; on its own it recognizes generic entity types (PERSON, ORG, GPE, DATE)
  with no PII-specific tuning or leak-rate publication. No PII-specific precision/recall figure is
  published by spaCy itself — not published.
- **License:** MIT. **Offline:** yes.

### GLiNER / GLiNER-PII
- **What it catches:** GLiNER is a zero-shot NER model (bidirectional transformer) that takes
  arbitrary entity-type labels at inference time rather than being retrained per label set
  ([arxiv.org/pdf/2311.08526](https://arxiv.org/pdf/2311.08526), accessed 2026-09-15). The
  Knowledgator/Wordcab GLiNER-PII fine-tunes span the range small→large; GLiNER can also plug into
  Presidio as a recognizer ([presidio.dataprivacystack.org/samples/python/gliner](https://presidio.dataprivacystack.org/samples/python/gliner/),
  accessed 2026-09-15).
- **Published precision/recall:** the `gliner-pii-base-v1.0` model card reports Precision 79.28%,
  Recall 82.78%, F1 80.99% on the `synthetic-multi-pii-ner-v1` benchmark
  ([huggingface.co/knowledgator/gliner-pii-base-v1.0](https://huggingface.co/knowledgator/gliner-pii-base-v1.0),
  accessed 2026-09-15) — a synthetic benchmark, so treat as an upper bound versus real documents.
- **License:** Apache 2.0 for the mainline GLiNER and GLiNER-PII variants
  ([huggingface.co/knowledgator/gliner-pii-base-v1.0](https://huggingface.co/knowledgator/gliner-pii-base-v1.0);
  general GLiNER release notes, accessed 2026-09-15).
- **Offline:** yes, explicitly marketed as "process sensitive data locally without API calls"
  ([huggingface.co/knowledgator/gliner-pii-base-v1.0](https://huggingface.co/knowledgator/gliner-pii-base-v1.0),
  accessed 2026-09-15).

### Philter (UCSF)
- **What it catches:** free-text clinical PHI (names, dates, locations, MRNs, etc.) via regex +
  statistical language models + white/blacklists, explicitly tuned to prioritize recall over
  precision ([nature.com/articles/s41746-020-0258-y](https://www.nature.com/articles/s41746-020-0258-y),
  accessed 2026-09-15).
- **Published precision/recall:** 99.46% recall / ~78% precision on a 2,000-note UCSF corpus; a
  separate neurosurgical-document evaluation found precision 0.35 / recall 0.79 — precision varies a
  lot by corpus ([JMIR extensible evaluation framework study](https://www.jmir.org/2024/1/e55676/),
  accessed 2026-09-15; [nature.com/articles/s41746-020-0258-y](https://www.nature.com/articles/s41746-020-0258-y)).
- **License:** the Nature paper states MIT; the GitHub repo (`BCHSI/philter-ucsf`) is the canonical
  source — some secondary sources say BSD-3, so verify at the repo before redistributing
  ([github.com/BCHSI/philter-ucsf](https://github.com/BCHSI/philter-ucsf), accessed 2026-09-15).
- **Offline:** yes, runs as a local Python tool over plain-text files. Domain is clinical, not legal;
  no legal-document evaluation was found — not published.

### PhysioNet `deid` / `pyDeid`
- **What it catches:** rule-based removal of PHI from clinical free text (names → fictitious names,
  MRNs, dates, locations), built for the MIMIC project at MIT's Lab for Computational Physiology
  ([physionet.org/physiotools/deid](https://www.physionet.org/physiotools/deid/), accessed
  2026-09-15). `pyDeid` is a Python port of the original Perl tool
  ([github.com/GEMINI-Medicine/pyDeid](https://github.com/GEMINI-Medicine/pyDeid), accessed
  2026-09-15).
- **Published precision/recall:** not published in the material found here; a 2025 medRxiv preprint
  benchmarks it and other clinical deid tools but a specific figure for `deid`/`pyDeid` was not
  extracted — not published
  ([medrxiv.org/content/10.1101/2025.03.21.25323520](https://www.medrxiv.org/content/10.1101/2025.03.21.25323520.full.pdf),
  accessed 2026-09-15).
- **License:** GPL-2.0. **Offline:** yes. Domain is clinical, not legal.

### LLM-based redactors (general pattern)
- Two competing designs exist in the wild: (a) **detect-and-tag**, where a model/NER labels spans
  and a separate step masks them (Presidio, GLiNER, Tonic Textual, our design); (b) **rewrite-in-place**,
  where an LLM directly rewrites the document, swapping PII for "realistic but fictitious"
  same-type values in one pass with no separate substitution ledger — this is the approach evaluated
  in "Locale-Conditioned Few-Shot Prompting ... On-Device PII Substitution with Small Language Models"
  ([arxiv.org/pdf/2605.13538](https://arxiv.org/pdf/2605.13538), accessed 2026-09-15) and in
  "Anonymous-by-Construction," whose abstract confirms the LLM performs the substitution itself
  rather than handing off to deterministic code
  ([arxiv.org/html/2603.17217v1](https://arxiv.org/html/2603.17217v1), accessed 2026-09-15) — this
  design has no equivalent of our guard step, because there's no discrete span list to check before
  it's used. Rewrite-in-place is strictly weaker against a hostile document: there is no artifact to
  validate before the model's words become the output.
- A 2025 hybrid pattern combines LLM-detected spans with regex-detected spans and deduplicates
  overlaps — closer to our design, though the source discussing it does not describe a per-matter
  graph or an against-input guard
  ([Medium: Redacting PII Before It Hits the LLM](https://nirajranasinghe.medium.com/redacting-pii-before-it-hits-the-llm-0fe9507f05e0),
  accessed 2026-09-15).

## 2. Commercial legal-AI / privacy vendors — claims, quoted, with leak-rate status

| Vendor | Quoted claim | Published leak rate |
|---|---|---|
| **Harvey** | "Harvey contractually prohibits model providers from training on customer data" and "requires Zero Data Retention (ZDR) by model providers"; "No human has access to or reviews customer data" ([harvey.ai/security](https://www.harvey.ai/security), [harvey.ai/legal/harvey-privacy-center](https://www.harvey.ai/legal/harvey-privacy-center), accessed 2026-09-15). | Not published. Harvey's claims are about retention/training contracts with model providers, not about any anonymization accuracy — they do not claim to scramble text at all. |
| **CoCounsel (Thomson Reuters)** | "CoCounsel user content and prompts are not used to train or improve CoCounsel ... or stored by OpenAI or Google"; "Thomson Reuters AI third-party partners ... are contractually prohibited from using any customer data to train their models" ([legal.thomsonreuters.com blog](https://legal.thomsonreuters.com/blog/the-consumer-vs-professional-ai-privacy-standards-for-legal-work/), accessed 2026-09-15). | Not published. Same pattern as Harvey: a no-training/zero-retention contractual claim, not a measured anonymization/leak figure. |
| **Lexis+ AI (LexisNexis)** | "LexisNexis claims it never uses customer data to train their AI models" and "opted out of certain Microsoft AI monitoring features to ensure OpenAI cannot access or retain confidential customer data" ([lexisnexis.com blog, "7 Key Facts"](https://www.lexisnexis.com/blogs/my/b/ai/posts/seven-key-facts-about-legal-ai-security-and-privacy-with-lexisnexis), accessed 2026-09-15). | Not published. A third-party commentary explicitly flags this: "'We do not train on your data' ... the slogan is verifiable and almost nobody verifies it" — the claim leaves open sub-processor routing and retrieval-pattern leakage ([vaquill.ai: "We Do Not Train on Your Data"](https://www.vaquill.ai/blog/we-do-not-train-on-your-data-legal-ai-verification), accessed 2026-09-15). |
| **Private AI** | Claims to "detect, anonymize, and replace 50+ personal information entities with higher than human accuracy" ([private-ai.com](https://www.private-ai.com/en/blog/pii-review-data), accessed 2026-09-15). | Not published as an independently verifiable number in the sources found — no specific precision/recall/leak figure was located. |
| **Tonic (Textual)** | Publishes its own benchmark, PrivacyBench: "Textual + Opus" reaches 95.0% NER recall / 92.0% combined detect+synthesize score, vs. 88.8% recall / 87.7% combined for Opus alone ([tonic.ai/ai-model-benchmarks/privacy-bench](https://www.tonic.ai/ai-model-benchmarks/privacy-bench), accessed 2026-09-15). | **Published** — the only vendor in this list with a self-reported, numeric, head-to-head benchmark. No independent third-party replication was found. |
| **Gretel (acquired by NVIDIA, March 2025)** | Platform "integrates differential privacy, PII redaction, and GDPR/HIPAA-compliant data generation," with "automatic PII detection and redaction based on GDPR and HIPAA definitions" ([geo.sig.ai/brands/gretel](https://geo.sig.ai/brands/gretel); [github.com/gretelai/gretel-synthetics](https://github.com/gretelai/gretel-synthetics), accessed 2026-09-15). | Not published as a leak-rate figure in the material found; Gretel does publish a `gretel-pii-masking-en-v1` dataset for training/eval but not a headline accuracy number for the product. |
| **Skyflow** | "De-identification locates sensitive information like PII, PHI, and PCI from text, PDFs, images, and audio files and then redacts that information with tokens" and provides "attestation of the de-identified data" ([skyflow.com/product/pii-data-privacy-vault](https://www.skyflow.com/product/pii-data-privacy-vault), [skyflow.com LLM Privacy Vault post](https://www.skyflow.com/post/generative-ai-data-privacy-skyflow-llm-privacy-vault), accessed 2026-09-15). | Not published. Skyflow's tokenize-then-detokenize architecture is conceptually close to our placeholder/entity-graph model, but no measured detection accuracy or leak rate was found. |
| **Protecto** | ">99.9% detection accuracy across 200+ PHI and PII entity types," claiming to outperform Presidio and AWS Comprehend on a proprietary "RARI" metric ([protecto.ai blog: Comparing Best NER Models](https://www.protecto.ai/blog/best-ner-models-for-pii-identification/), accessed 2026-09-15). | Self-published only — the underlying comparison study is Protecto's own ("BENCHMARKING PII IDENTIFICATION IN UNSTRUCTURED TEXT," [protecto.ai PDF](https://protecto.ai/wp-content/uploads/2024/07/6646f1564c513545cbf9d2f9_Quantitative-Benchmark-Study-PII-Identification-1.pdf), accessed 2026-09-15) — no independent replication found. Treat the 99.9% figure as a vendor claim, not an audited result. |

**Pattern across the table:** every "no-training / zero-retention" legal-AI vendor claim (Harvey,
CoCounsel, Lexis+) is a *contractual/retention* promise about what the frontier model provider does
with data after receipt — none of them claim to scramble or anonymize the document text itself before
it reaches the model, and none publishes a measured leak rate for anything. Only the anonymization
*product* vendors (Tonic, Protecto) publish a number at all, and only Tonic's is benchmarked against
a named alternative (LLM-alone) rather than only against itself.

## 3. Academic results (2023–2026)

- **Re-identification from pseudonymized demographics (general, not legal-specific):** a widely cited
  finding is that 99.98% of individuals in a dataset can be re-identified using 15 demographic
  attributes even after pseudonymization — cited in the context of a February 2026 JAMIA study
  describing a practical re-identification attack that "exploits repeated tokens and auxiliary
  demographic details, such as year of birth, gender, or the first 3 digits of a ZIP code" against
  pseudonymized patient-matching data
  ([academic.oup.com/jamia/.../ocaf183](https://academic.oup.com/jamia/advance-article/doi/10.1093/jamia/ocaf183/8292788),
  accessed 2026-09-15). This is the core structural risk our own doc already states plainly:
  "residual facts re-identify people regardless of the scrubber" (`docs/SCRAMBLER.md`).
- **Re-identification risk methodology:** a 2025 *Scientific Reports* paper proposes a "practical and
  ready-to-use methodology to assess the re-identification risk in anonymized datasets"
  ([nature.com/articles/s41598-025-04907-3](https://www.nature.com/articles/s41598-025-04907-3),
  accessed 2026-09-15) — a scoring method, not a single number that transfers to legal text.
- **Effect of pseudonymization on downstream reliability:** a study using 3,950,145 hospitalization
  records from Greater Paris University Hospitals (Aug 2017–Apr 2024) simulated re-identification
  attempts against several pseudonymization algorithms to quantify the privacy/reliability tradeoff
  ([pubmed.ncbi.nlm.nih.gov/41715132](https://pubmed.ncbi.nlm.nih.gov/41715132/); companion paper
  [link.springer.com/article/10.1186/s12911-026-03360-0](https://link.springer.com/article/10.1186/s12911-026-03360-0),
  accessed 2026-09-15) — healthcare domain, not legal, but directly on-point methodologically.
- **Detect-then-substitute vs. LLM-alone (Tonic PrivacyBench):** already covered in §0/§2 — the only
  study found with a clean, named, numeric comparison of our architecture family against a raw-LLM
  baseline: 92.0% vs. 87.7% combined score, 95.0% vs. 88.8% recall
  ([tonic.ai/ai-model-benchmarks/privacy-bench](https://www.tonic.ai/ai-model-benchmarks/privacy-bench),
  accessed 2026-09-15).
- **PAPILLON (local+cloud ensemble, NAACL 2025):** a closely related architecture family — chain a
  local model with a cloud API model rather than send raw text to the cloud model directly. On their
  PUPA benchmark: "maintains high response quality for 85.5% of user queries" while "restricting
  privacy leakage to only 7.5%" ([arxiv.org/pdf/2410.17127](https://arxiv.org/pdf/2410.17127),
  accessed 2026-09-15). Architecturally different from ours — PAPILLON uses prompt-optimization
  pipelines rather than a deterministic substitution/guard/graph — but it is the clearest academic
  precedent for "keep a local model in the loop, only send a filtered version to the frontier model,"
  and its 7.5% residual leakage is a useful reference point for how hard zero-leak is even with a
  local gate in place.
- **RedactionBench (2026):** benchmarks Presidio, transformer NER (BERT/RoBERTa/DeBERTa variants),
  GLiNER, B2NER, and frontier LLMs (Claude Opus, GPT-5, Llama 3) plus commercial filters against each
  other on detection and leak rate; the paper's own numeric tables were not extractable from the
  fetch performed here — **not published** in this document because the exact figures could not be
  confirmed, though the benchmark and its participant list are real
  ([arxiv.org/pdf/2606.18782](https://arxiv.org/pdf/2606.18782), accessed 2026-09-15).
- **PRvL (2025), "Not What the Doctor Ordered" (2025):** both directly evaluate LLM-based PII
  redaction (PRvL: "a range of LLM architectures and training strategies," measuring "redaction
  performance, semantic preservation, and PII leakage"; the clinical paper: a survey "highlighting
  the heterogeneity in reporting standards" in LLM-based de-identification, finding existing
  automatic metrics show "poor performance" at detecting clinically significant information loss).
  Neither abstract disclosed extractable numeric results in this pass — **not published** here for
  the same reason ([arxiv.org/abs/2508.05545](https://arxiv.org/abs/2508.05545);
  [arxiv.org/abs/2509.14464](https://arxiv.org/abs/2509.14464), both accessed 2026-09-15). Flagging
  both as worth a deeper read before the leak-rate measurement work in our own repo, since "reporting
  heterogeneity" is exactly the trap we should avoid when we publish our own number.
- **Prompt injection against PII/privacy pipelines:** VortexPIA (2026) is an indirect prompt-injection
  attack purpose-built "for Efficient Extraction of User Privacy," tested against six LLMs, four
  benchmarks, and real LLM-integrated apps, claiming SOTA attack performance and "enhanced robustness
  against defense mechanisms" — exact success-rate numbers were not extractable from the abstract
  fetch, so **not published** here, but the paper is directly relevant to the threat model in
  `docs/SCRAMBLER.md` §"Threat graph" ([arxiv.org/pdf/2510.04261](https://arxiv.org/pdf/2510.04261),
  accessed 2026-09-15). A real-world example in the same space: a demonstrated KYC pipeline attack
  where malicious instructions hidden in a passport image's OCR text caused an extraction agent to
  leak 20 other customers' PII into the attacker's own record — cited via a 2026 conference recap,
  not itself a formal paper ([futureagi.com/blog/llm-prompt-injection-2025](https://futureagi.com/blog/llm-prompt-injection-2025/),
  accessed 2026-09-15).

## 4. Bar / regulatory guidance touching AI + client confidentiality

- **ABA Formal Opinion 512** (July 29, 2024) — first ABA guidance on generative AI; requires lawyers
  to understand a tool's capabilities/limitations, protect client confidentiality, and consider
  client communication about AI use, tied to Model Rules on competence (1.1) and confidentiality
  (1.6) ([americanbar.org PDF](https://www.americanbar.org/content/dam/aba/administrative/professional_responsibility/ethics-opinions/aba-formal-opinion-512.pdf), accessed 2026-09-15).
- **Florida Bar Ethics Opinion 24-1** (Jan 19, 2024) — lawyers may use generative AI but must research
  a tool's data retention/sharing/self-learning policies before inputting client information; Florida
  later amended Rule 4-1.6 (effective July 1, 2025) to require affirmative written disclosure to
  clients when AI processes their confidential information ([floridabar.org/etopinions/opinion-24-1](https://www.floridabar.org/etopinions/opinion-24-1/), accessed 2026-09-15).
- **California — Practical Guidance (Nov 2023) + Formal Opinion 2024-01** — covers competence (Rule
  1.1), confidentiality (Rule 1.6), and supervision (Rules 5.1/5.3) for generative AI use; California's
  ethics committee approved proposed rule amendments in March 2026 that, unlike advisory opinions in
  other states, would carry disciplinary authority ([summarized via americanbar.org/esquiresolutions coverage](https://www.esquiresolutions.com/california-ethics-panel-turns-up-the-heat-on-artificial-intelligence/), accessed 2026-09-15).
- **New York — Task Force on AI report (adopted April 6, 2024) + Formal Opinion 2025-6** — the 85-page
  Task Force report addresses confidentiality complexity when third-party AI systems are involved;
  Opinion 2025-6 specifically covers AI recording/transcription of client meetings and consent
  ([lawnext.com compendium](https://www.lawnext.com/2025/02/a-compendium-of-legal-ethics-opinions-on-gen-ai-as-compiled-by-you-guessed-it-gen-ai.html), accessed 2026-09-15).
- **Texas — Professional Ethics Committee Opinion No. 705** (Feb 2025) — lawyers must be cautious
  about inputting confidential information into AI tools that might store/expose client data, must
  understand the technology "to a reasonable degree," and cannot bill clients for AI-saved time
  ([summarized via paxton.ai/lawnext coverage](https://www.paxton.ai/post/2025-state-bar-guidance-on-legal-ai), accessed 2026-09-15).

## 5. Final comparison table

| Approach | Runs offline | Structural defense against prompt injection | Consistency across documents | Published leak rate |
|---|---|---|---|---|
| **Our design** (local Qwen proposes spans → guard validates in-input/closed-enum/no-injection-marker → code substitutes → per-matter entity graph → release gate re-sweeps output) — `docs/SCRAMBLER.md` | Yes — every step but the final frontier call runs on the corpus host. | Yes, by construction: the model's text is never used as output; every span is checked against the literal input before acceptance; injection markers are rejected even when the string is genuinely present. This is a designed property, not a measured one, until the leak-rate work runs. | Yes, by construction: a persisted per-matter entity graph gives one placeholder per entity across all documents in a matter, restored via alias edges. | **Not measured yet** — `docs/SCRAMBLER.md` states this explicitly: "the naive single-prompt figure in the source thread (~70–80%) is someone else's; ours does not exist until it is measured." |
| **Microsoft Presidio** | Yes | No — Presidio has no defense against an input document instructing the *reading* pipeline (it's regex/NER, not an LLM, so classic prompt injection doesn't apply the same way, but there is also no guard concept at all — a crafted string that looks like a name is just treated as a name). | No native cross-document identity graph — same string is tagged the same way, but no alias/coref resolution across spelling variants unless built by the caller. | Not published as a single trustworthy number — reported precision as low as 0.23–0.25 out of the box in one independent eval; recommends self-evaluation on your own corpus. |
| **GLiNER / GLiNER-PII** | Yes | No structural guard; zero-shot label list is configurable but nothing checks proposed spans against the input the way our guard does. | No built-in cross-document graph. | 79.28% / 82.78% / 80.99% (P/R/F1) on a synthetic benchmark — not real-document, not legal-domain. |
| **Philter / PhysioNet deid** | Yes | No — rule/whitelist-based, no adversarial-input concept. | No cross-document graph; clinical-note-scoped. | 99.46% recall / ~78% precision (UCSF corpus) for Philter; not published for deid/pyDeid. |
| **LLM rewrite-in-place (no span/substitute split)** | Depends on model (local or cloud) | No — the model's own generated text *is* the output; nothing validates it against the input before release. | No inherent mechanism; would need external bookkeeping. | Not published by the two papers found (PRvL, "Not What the Doctor Ordered") in this pass. |
| **Tonic Textual (detect NER → code substitutes)** | Unclear — appears to be a SaaS/API product; not confirmed as locally runnable. | Not described — no published guard against a hostile document instructing the detector. | Not described in material found. | **Published**, the strongest in this survey: 95.0% recall / 92.0% combined score with Opus as the synthesis step, vs. 88.8%/87.7% for Opus alone. |
| **Skyflow (tokenize/detokenize vault)** | No — vault is a hosted service. | Not described. | Vault-level tokens persist, so plausibly consistent across calls, but not documented as an entity graph with alias resolution. | Not published. |
| **Harvey / CoCounsel / Lexis+ (contractual no-train / zero-retention)** | No — cloud-hosted frontier models by design. | Not applicable — these vendors do not claim to scramble text at all; their promise is about what happens to the raw document *after* it reaches the model. | Not applicable. | Not published — and structurally can't be, since there's no anonymization step to measure. |
| **PAPILLON (local+cloud ensemble)** | Partially — local model stays local, but the architecture assumes a cloud call for the harder generation step. | Weak — relies on prompt optimization rather than a deterministic guard; no explicit defense against the local model itself being hijacked by document content. | Not designed for multi-document matter consistency. | **Published**: 7.5% residual privacy leakage at 85.5% utility on the PUPA benchmark — the most directly comparable "how hard is zero-leak" data point found. |

## Sources not cross-checked further

Several figures above are vendor- or single-study-published and have no independent replication in
the material gathered (Protecto's 99.9%, Private AI's "higher than human accuracy," Tonic's own
PrivacyBench). Treat all of them as vendor-reported until an independent benchmark corroborates them.
No number in this document was invented; every "not published" line reflects an actual failed or
inconclusive search/fetch, not an assumption.
