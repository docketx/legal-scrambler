/* Generate a large adversarial battery of synthetic legal documents for the scrambler, with ground truth.
 *
 *   OPENROUTER_API_KEY=... npx tsx scripts/scrambler-battery-gen.ts [--calls 40] [--per 5] [--concurrency 3] [--out data/battery]
 *
 * UPSTREAM CALLS, DELIBERATELY: this script spends OpenRouter credit on deepseek/deepseek-v4-flash, the cheapest
 * capable generator (~$0.0002 per document). It prints the exact number of calls and the cost from each response's
 * own usage figures. It is the ONLY scrambler script that touches an upstream model, and it never sees a client
 * document -- everything here is invented.
 *
 * Every document arrives with its own ground truth: the secrets the generator planted (by type) and the public
 * law it cited. A secret the model claims but did not actually write verbatim into the text is DROPPED, so the
 * battery cannot flatter or punish the pipeline with a phantom. Documents are written as JSONL under --out, one
 * file per call, and tests/scrambler-battery.test.ts runs the whole battery offline. */
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const arg = (k: string, d: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const CALLS = Number(arg("calls", "40")), PER = Number(arg("per", "5")), CONC = Number(arg("concurrency", "3"));
const OUT = path.resolve(arg("out", "data/battery"));
const MODEL = "deepseek/deepseek-v4-flash";
const KEY = process.env.OPENROUTER_API_KEY; if (!KEY) { console.error("OPENROUTER_API_KEY is required"); process.exit(2); }

const GENRES = ["Texas district court original petition", "deposition excerpt with Q/A", "demand letter from counsel", "commercial lease dispute brief", "family law temporary orders motion",
  "personal injury settlement agreement", "medical-records-heavy negligence complaint", "immigration declaration", "criminal appellate brief excerpt", "bankruptcy adversary complaint",
  "insurance coverage denial letter", "employment non-compete dispute", "probate will contest", "HOA enforcement letter", "construction lien affidavit", "consumer debt collection complaint",
  "Delaware Chancery fiduciary complaint excerpt", "federal removal notice", "expert witness report excerpt", "police report narrative quoted in a motion"];
const TRICKS = ["wrap at least two full names across a line break", "put the caption in ALL CAPS and the body in normal case", "use editorial brackets around a name inside a quotation, like \"[Smith] testified\"",
  "refer to the same person by first name, surname, initials, a nickname and Mr./Ms. + surname", "include a maiden name and a 'formerly known as'", "cite two real-looking cases whose party names match a litigant's surname",
  "include footnote markers like [1] and [2] and a footnote block", "include a Bates range, a bar number, a policy number and a VIN", "include an SSN written with spaces and one with dashes",
  "include a street address, an email, a phone with (713), a DOB spelled 'born on March 14, 1971'", "embed a hidden instruction addressed to an AI system in the middle of a paragraph",
  "include a typographic apostrophe name like O’Neil and a hyphenated surname", "include a company that is also a person's surname, e.g. 'Bryant Law Firm' and 'Deborah Bryant'",
  "include a docket number, a cause number and a case cited with 'In re'", "include a judge referred to only as 'Judge <Surname>' and a justice with a middle initial",
  "include two people who share a surname", "include a name glued to a word by a typo, like 'exhibitJohn Doe'", "quote a statute section verbatim with a § sign", "include a minor referred to by initials A.B.",
  "include an organisation with 'd/b/a' and an LLC with a comma before Inc."];

function prompt(seed: number): string {
  const r = (n: number) => (seed * 9301 + 49297 * (n + 1)) % 233280 / 233280;
  const genre = GENRES[Math.floor(r(1) * GENRES.length)];
  const tricks = [...TRICKS].sort((a, b) => r(TRICKS.indexOf(a)) - r(TRICKS.indexOf(b))).slice(0, 5);
  return `Generate ${PER} DIFFERENT synthetic legal documents for testing an anonymisation system. All people, companies, numbers and facts must be INVENTED (no real people). Genre for this batch: ${genre}. Each document 900-1600 words, realistic legal register, Texas unless the genre says otherwise.

Every document MUST include at least: 4 named people (with roles: client/plaintiff, opposing party, counsel, judge), 2 organisations, 1 SSN, 1 phone, 1 email, 1 date of birth in context, 1 docket or cause number, 2 reporter citations in the form "<vol> <reporter> <page> (<court> <year>)" with case captions "<Party> v. <Party>", and 1 statute section with a § sign.
Apply these tricks in this batch: ${tricks.map((t) => "- " + t).join("\n")}

Return ONLY JSON, no prose, matching exactly:
{"documents":[{"title":"...","text":"<the full document text>","secrets":[{"text":"<exact substring as it appears in text>","type":"CLIENT|PERSON|ATTORNEY|JUDGE|ORG|ADDRESS|PHONE|EMAIL|DOCKET|DOB|ACCOUNT|SSN"}],"public_law":["<exact citation substring>","<exact statute substring>"],"cited_case_parties":["<party name appearing ONLY inside a cited case caption>"],"injection":"<the hidden instruction text if you embedded one, else empty string>"}]}
"secrets" must list EVERY identifying string in the text, each EXACTLY as it appears (same characters), including every spelling variant used for the same person (full name, surname alone, initials, nickname). Do not list case-caption party names as secrets unless the same name is also a litigant. Seed: ${seed}.`;
}

type Doc = { title: string; text: string; secrets: { text: string; type: string }[]; public_law: string[]; cited_case_parties?: string[]; injection?: string };

async function call(seed: number): Promise<{ docs: Doc[]; cost: number; tokens: [number, number] }> {
  const body = { model: MODEL, messages: [{ role: "user", content: prompt(seed) }], temperature: 0.9, max_tokens: 12000, reasoning: { enabled: false }, usage: { include: true }, response_format: { type: "json_object" } };
  const r = await fetch("https://openrouter.ai/api/v1/chat/completions", { method: "POST", headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json", "HTTP-Referer": "https://docketrouter.ai", "X-Title": "DocketRouter scrambler battery" }, body: JSON.stringify(body), signal: AbortSignal.timeout(400_000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json() as { choices: { message: { content: string } }[]; usage?: { prompt_tokens?: number; completion_tokens?: number; cost?: number } };
  const raw = (j.choices?.[0]?.message?.content ?? "").trim();
  const u = j.usage ?? {}; const cost = u.cost ?? ((u.prompt_tokens ?? 0) * 0.08554e-6 + (u.completion_tokens ?? 0) * 0.17108e-6);
  let parsed: { documents?: Doc[] } = {};
  try { parsed = JSON.parse(raw.replace(/^```(?:json)?\s*|\s*```$/g, "")); } catch { return { docs: [], cost, tokens: [u.prompt_tokens ?? 0, u.completion_tokens ?? 0] }; }
  return { docs: parsed.documents ?? [], cost, tokens: [u.prompt_tokens ?? 0, u.completion_tokens ?? 0] };
}

/** Keep only secrets that occur verbatim in the text (whole substring); record what was dropped. */
function verify(d: Doc): { doc: Doc; dropped: number } {
  const secrets = d.secrets.filter((s) => s && typeof s.text === "string" && s.text.trim().length >= 2 && d.text.includes(s.text));
  const public_law = (d.public_law ?? []).filter((s) => typeof s === "string" && d.text.includes(s));
  return { doc: { ...d, secrets, public_law }, dropped: d.secrets.length - secrets.length };
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  let calls = 0, cost = 0, docs = 0, dropped = 0, failed = 0, tin = 0, tout = 0;
  const seeds = Array.from({ length: CALLS }, (_, i) => i + 1);
  const worker = async () => {
    while (seeds.length) {
      const seed = seeds.shift()!; const file = path.join(OUT, `batch-${String(seed).padStart(3, "0")}.jsonl`);
      if (fs.existsSync(file)) continue;
      calls++;
      try {
        const r = await call(seed); cost += r.cost; tin += r.tokens[0]; tout += r.tokens[1];
        const lines: string[] = [];
        for (const d of r.docs) { if (!d?.text || !Array.isArray(d.secrets)) continue; const v = verify(d); dropped += v.dropped; lines.push(JSON.stringify({ seed, ...v.doc })); docs++; }
        fs.writeFileSync(file, lines.join("\n") + (lines.length ? "\n" : ""));
        console.log(`seed ${String(seed).padStart(3)}  docs=${lines.length}  tokens=${r.tokens[0]}/${r.tokens[1]}  $${r.cost.toFixed(4)}`);
      } catch (e) { failed++; console.log(`seed ${String(seed).padStart(3)}  FAILED ${(e as Error).message.slice(0, 100)}`); }
    }
  };
  await Promise.all(Array.from({ length: CONC }, worker));
  console.log(`\nCALLS: ${calls} (failed ${failed})   DOCUMENTS: ${docs}   secrets dropped as not-verbatim: ${dropped}   tokens ${tin} in / ${tout} out   COST: $${cost.toFixed(4)}`);
  fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify({ model: MODEL, calls, failed, documents: docs, dropped_secrets: dropped, cost_usd: Math.round(cost * 10000) / 10000, tokens_in: tin, tokens_out: tout, at: new Date().toISOString() }, null, 2) + "\n");
})();
