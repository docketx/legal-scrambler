/* WHOLE CASE FILES against the private liaison: every filing of a real docket through ONE matter graph, then the
 * cross-document final pass, then the swap-back -- measured. Founder, 2026-09-15: "stress test our ability to
 * actually swap out entire case files"; "the swap back needs to be clean and seamless".
 *
 *   put RECAP docket folders (one per docket id, plain-text filings) under data/dockets/
 *   LOCAL_LLM_BASE_URL=http://127.0.0.1:11437/v1 LIAISON_MODEL=local/qwen3:8b \
 *     npx tsx scripts/scrambler-casefile.ts [--dockets data/dockets] [--limit N] [--docket gov.uscourts.txsd.NNN]
 *                                          [--chunk 4000] [--overlap 200] [--json out.json] [--resume out.json] [--fake]
 *
 * Ground truth is the docket's OWN party / attorney / judge list (CourtListener's docket.json on the RECAP mirror),
 * typed: a party is ORG or PERSON by shape, an attorney ATTORNEY, a judge JUDGE. A name counts only where it is
 * present in the filings outside a cited caption; a person also counts by surname. Per docket: leak per 1,000 by
 * type, CROSS-DOCUMENT CONSISTENCY (one ground-truth entity -> how many placeholders across the whole file),
 * citations kept, refusals (with the residual's type), RESTORE EXACTNESS (every chunk byte-exact from its ledger),
 * throughput. Transport failures exclude the docket from the rate under their own heading. JSON is checkpointed
 * after every docket; --resume continues. --fake is the oracle (proposes the ground truth): the pipeline ceiling
 * on real filings, never a liaison number. */
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { MatterGraph, scrambleDocument, finalizeChunksWithLedger, restoreDocument, ORG_SHAPED, type LocalModel } from "../src";
import { scramble, residualAliases, flex } from "../src/apply";
import { regexSpans } from "../src/patterns";
import { localScrambler } from "../src/liaison";
import { isSovereign } from "../src/guard";
import { occurrences as occurrencesOf, wilson, isTransportFailure, paragraphs } from "../src/measure";
import { normalizeInput } from "../src/normalize";
import { extractCitations } from "../src/citations";

const argv = process.argv.slice(2);
const arg = (k: string) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
const has = (k: string) => argv.includes(`--${k}`);
const DIR = path.resolve(arg("dockets") ?? "data/dockets");
const LIMIT = Number(arg("limit") ?? Infinity), ONLY = arg("docket") ?? null;
const CHUNK = Number(arg("chunk") ?? 4000), OVERLAP = Number(arg("overlap") ?? 200);
const DEBUG = has("debug");
// the commit: git where there is a checkout, else a COMMIT file written beside the harness when it is synced to a box
const COMMIT = (() => { try { return execFileSync("git", ["rev-parse", "--short", "HEAD"], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch { try { return fs.readFileSync(path.join(process.cwd(), "COMMIT"), "utf8").trim(); } catch { return "unknown"; } } })();
const DUMP = arg("dump-graph");
const DUMP_OUT = arg("dump-output"); // directory: each docket's released output, concatenated, so a placeholder can be read in context // directory: each docket's graph as JSON, so a split entity can be read node by node
/** --debug: on a refusal, the residual aliases with their node and the input/output context. The dockets are public
 *  filings, so the values can be printed here; never in the library's own errors. */
function explainRefusal(chunk: string, graph: MatterGraph, where: string) {
  if (!DEBUG) return;
  const out = scramble(chunk, graph);
  // an identifier the regex pass produced on the input and the substitution did not reach in the output
  const inputRegex = new Set(regexSpans(chunk).map((s) => s.text));
  for (const s of regexSpans(out)) if (!/\[[A-Z]+_\d+\]/.test(s.text) && inputRegex.has(s.text)) { const i = out.indexOf(s.text); console.log(`      [${where}] regex leftover ${JSON.stringify(s)}\n         OUT: ${JSON.stringify(out.slice(Math.max(0, i - 70), i + s.text.length + 25))}`); }
  for (const r of residualAliases(out, graph)) {
    const node = graph.find(r); const mo = new RegExp(flex(r), "iu").exec(out); const mi = new RegExp(flex(r), "iu").exec(chunk);
    if (!mo && node) for (const tok of r.replace(/[,.;:()"']/g, " ").split(/\s+/)) { if (tok.length < 3) continue; const ph = node.placeholder.replace(/[[\]]/g, "\\$&"); const f = new RegExp(`${tok}[ \\t]*${ph}|${ph}[ \\t]*${tok}`, "i").exec(out); if (f) { console.log(`         FRAGMENT "${tok}": ${JSON.stringify(out.slice(Math.max(0, f.index - 60), f.index + f[0].length + 30))}`); break; } }
    console.log(`      [${where}] residual ${JSON.stringify(r)} node=${node?.placeholder}/${node?.type} aliases=${JSON.stringify(node?.aliases.slice(0, 5))}\n         OUT: ${JSON.stringify(mo ? out.slice(Math.max(0, mo.index - 70), mo.index + mo[0].length + 25) : "(no match in output: fragment rule)")}\n         IN : ${JSON.stringify(mi ? chunk.slice(Math.max(0, mi.index - 70), mi.index + mi[0].length + 25) : "(no match in input)")}`);
  }
}

type Docket = { identifier: string; court: string; title?: string; case_name?: string; docket_number?: string; judges: string[]; parties: { name: string; type: string }[]; attorneys: string[]; docs: { file: string; chars: number }[] };
type Truth = { name: string; type: "PERSON" | "ORG" | "ATTORNEY" | "JUDGE"; variants: string[] };
type Report = {
  identifier: string; case_name?: string; docs: number; chunks: number; chars: number; ms: number;
  /** chunks actually sent to the model (a refusal stops its filing, so this can be < chunks), the model calls made, and
   *  the time spent inside them: model time is comparable across runs only per chunk sent (2026-09-16) */
  chunks_sent: number; model_calls: number; model_ms: number;
  /** pass 2 (the audit call) on its own: calls, time, and the names it caught that pass 1 missed -- what pass 2 buys */
  pass2_calls: number; pass2_ms: number; pass2_catches: number;
  /** the scrambler code this docket ran on: a resumed run can span commits, and each docket says which */
  commit: string;
  truth: number; present: number; leaked: number; by_type: Record<string, { present: number; leaked: number; leaked_names?: string[] }>;
  consistency: { entities_seen: number; consistent: number; split: { name: string; placeholders: string[] }[] };
  citations_in: number; citations_out: number; citations_missing: string[];
  refused_docs: { file: string; message: string }[]; degraded: number;
  restore: { chunks: number; exact: number; normalized_basis: number };
  over_scrub_proxy: number; over_scrub_candidates: number; over_scrub_tight: number;
};

const ORG_SHAPE = /\b(?:Administration|Agency|Bureau|Office|Service|Ministry|Council|Committee|Court|Inc|LLC|L\.C|LC|Motor|America|Wash|Car|Grocery|Restaurant|Express|Brothers|Bros|Fuel|Systems|Industrial|Corporation|Corp|Ltd|Metal|Metals|Management|Waste|Scrap|Terminal|Terminals|Liquid|Global|Building|Buildings|Products|Solutions|Supply|Equipment|Rental|Rentals|Tank|Trucks|Truck|Transport|Recycling|Chemical|Chemicals|Marine|Steel|Pipe|Oil|Gas|Energy|Electric|Power|Paint|Auto|Motors|Way|Site|Landfill|Disposal|Environmental|Salvage|Machine|Machinery|Tool|Tools|Foods|Food|Beverage|Packaging|Plastics|Rubber|Textile|Lumber|Paper|Glass|Concrete|Construction|Contractors|Contracting|Builders|Roofing|Plumbing|Electrical|Welding|Fabrication|Fabricators|Coatings|Refinery|Refining|Aviation|Airlines|Shipping|Freight|Trucking|Towing|Wrecker|Storage|Distribution|Distributors|Wholesale|Retail|Sales|Leasing|Realty|Homes|Properties|Development|Ventures|Capital|Investments|Trading|Imports|Exports|Import|Export|Communications|Technologies|Technology|Systems|Networks|Consulting|Consultants|Engineering|Engineers|Surveying|Surveyors|Laboratories|Labs|Clinic|Dental|Medical|Pharmacy|Health|Healthcare|Hospice|Nursing|Care|Ranch|Farms|Farm|Dairy|Cattle|Feed|Seed|Grain|Cotton|Timber|Mining|Minerals|Quarry|Sand|Gravel|Aggregates|Asphalt|Paving|Drilling|Wells|Pumps|Valves|Fittings|Bearings|Hydraulics|Compressors|Generators|Batteries|Tires|Tire|Parts|Body|Collision|Detailing|Cleaning|Cleaners|Janitorial|Laundry|Linen|Uniforms|Printing|Signs|Graphics|Studio|Studios|Gallery|Theater|Theatre|Cinema|Films|Film|Pictures|Records|Music|Entertainment|Sports|Fitness|Gym|Club|Lodge|Resort|Inn|Suites|Hotel|Motel|Cafe|Grill|Kitchen|Bakery|Deli|Diner|Cantina|Tavern|Bar|Pub|Lounge|Brewery|Winery|Distillery|Spirits|Liquor|Tobacco|Vapor|Nutrition|Vitamins|Cosmetics|Beauty|Salon|Spa|Nails|Barber|Boutique|Fashion|Apparel|Jewelers|Jewelry|Pawn|Loans|Finance|Financial|Credit|Mortgage|Title|Escrow|Insurance|Assurance|Underwriters|Adjusters|Appraisal|Appraisers|Auction|Auctions|Marketing|Media|Publishing|Publications|Press|News|Radio|Broadcasting|Cable|Wireless|Telecom|Telephone|Internet|Software|Data|Analytics|Security|Alarm|Locksmith|Guard|Patrol|Investigations|Staffing|Personnel|Payroll|Accounting|Tax|Bookkeeping|Notary|Translation|Interpreting|Tutoring|Academy|Institute|Seminary|Ministries|Church|Temple|Mosque|Synagogue|Chapel|Mission|Charities|Charity|Relief|Outreach|Shelter|Rescue|Humane|Kennel|Veterinary|Animal|Pet|Aquarium|Zoo|Nursery|Landscape|Landscaping|Lawn|Garden|Irrigation|Sprinkler|Pool|Pools|Fence|Fencing|Gate|Gates|Door|Doors|Window|Windows|Siding|Insulation|Drywall|Flooring|Carpet|Tile|Cabinet|Cabinets|Countertops|Granite|Marble|Stone|Masonry|Brick|Block|Foundation|Foundations|Excavation|Demolition|Hauling|Dumpster|Sanitation|Septic|Sewer|Water|Utility|Utilities|Solar|Wind|Nuclear|Petroleum|Propane|Fuel|Fuels|Lubricants|Asphalt|Roads|Highway|Bridge|Rail|Railroad|Railway|Transit|Bus|Taxi|Limo|Limousine|Charter|Cruise|Cruises|Travel|Tours|Vacations|Timeshare|Condominium|Condominiums|Apartments|Estates|Villas|Manor|Plaza|Mall|Center|Centre|Square|Park|Parkway|Tower|Towers|Place|Point|Ridge|Hills|Valley|Creek|River|Lake|Bay|Harbor|Harbour|Port|Island|Coast|Shore|Beach|Springs|Falls|Canyon|Mesa|Prairie|Meadows|Woods|Forest|Grove|Orchard|Vineyard|Acres|Trails|Crossing|Junction|Station|Depot|Yard|Yards|Works|Mill|Mills|Foundry|Forge|Plant|Factory|Assembly|Manufacturing|Manufacturers|Industrial|Commercial|Residential|Mechanical|Automotive|Aerospace|Defense|Logistics|Warehouse|Warehousing|Fulfillment|Courier|Delivery|Express|Parcel|Post|Postal|Mail|Messenger|L\.L\.C|LLP|L\.P|LP|PLLC|P\.C|Ltd|Co|Corp|Corporation|Company|Companies|Association|Associates|Insurance|Department|Board|Commission|Authority|District|Agency|Bank|Trust|Group|Holdings|Partners|Partnership|Firm|Enterprises|Services|Systems|Solutions|Industries|International|Foundation|Hospital|University|College|School|City|County|State|United States|Government|Fund|Church|Union|Society|Institute|Center|Centre|Clinic|Realty|Properties|Investments|Capital|Financial|Energy|Oil|Gas|Petroleum|Motors|Airlines|Railroad|Railway|Transportation|Logistics|Manufacturing|Products|Technologies|Communications|Network|Media|Entertainment|Studios|Pharmaceuticals|Laboratories|Labs|N\.A|S\.A|N\.V|GmbH|AG|PLC|Ltd|et al)\b/i;
const NAME_PUNCT = /[,.;:()"]/g;
function personVariants(name: string): string[] {
  // "Hanen, Andrew S" (PACER order) and "Andrew S Hanen" both occur; the surname alone counts too
  const out = new Set<string>([name]);
  if (name.includes(",")) { const [last, first] = name.split(",").map((x) => x.trim()); if (first) { out.add(`${first} ${last}`); out.add(last); } }
  else { const toks = name.replace(NAME_PUNCT, " ").trim().split(/\s+/).filter((t) => t.length >= 2 && !/^(?:Jr|Sr|II|III|IV|Esq|Hon|Mr|Ms|Mrs|Dr)$/i.test(t)); if (toks.length >= 2) out.add(toks[toks.length - 1]); }
  // a "surname" that is a sovereign ("HYUNDIA MOTOR AMERICA" typed as a person by its shape -> "AMERICA") is not a
  // variant to score: the guard refuses it by design, and scoring it charged the pipeline with every "America" on
  // the docket (proof run 4, 2026-09-16)
  return [...out].filter((v) => v.length >= 3 && !isSovereign(v));
}
function truthOf(d: Docket): Truth[] {
  const out: Truth[] = []; const seen = new Set<string>();
  const add = (name: string, type: Truth["type"]) => { const n = name.trim(); if (!n || seen.has(n.toLowerCase())) return; seen.add(n.toLowerCase()); out.push({ name: n, type, variants: type === "ORG" ? [n] : personVariants(n) }); };
  // "John Doe 342", "Does 1-25", "Jane Roe": pseudonyms already, not secrets to score
  // a role listed as a party ("U.S. Attorney", "Attorney General") is not a person to score
  // a sovereign as a party ("State Of Texas", "USA", "UNITED STATES OF AMERICA") is public and the guard refuses
  // it by design (2026-09-16); its agencies ("United States Coast Guard") are still scored
  // a forfeiture "party" is a sum of money or a thing ("$35,131.00 IN U.S. CURRENCY", "2014 Ford F-150"), not a name
  for (const p of d.parties ?? []) { if (/\b(?:Doe|Does|Roe)\b/.test(p.name) || isSovereign(p.name) || /^\$|\bCURRENCY\b|\bU\.S\. Currency\b|^\d{4}\s+[A-Z]/i.test(p.name.trim()) || /^(?:U\.?S\.? Attorney|Attorney General|District Attorney|County Attorney|City Attorney|Public Defender|Federal Public Defender|Pro Se|Unknown|Interested Party)\b/i.test(p.name.trim())) continue; add(p.name, ORG_SHAPE.test(p.name) || ORG_SHAPED.test(p.name) || /\b(?:of|the)\b/i.test(p.name) && !/,/.test(p.name) ? "ORG" : "PERSON"); }
  for (const a of d.attorneys ?? []) add(a, "ATTORNEY");
  for (const j of d.judges ?? []) add(j, "JUDGE");
  return out;
}
const nonCaption = (text: string, s: string) => occurrencesOf(text, s).filter((o) => !o.caption).length;
/** Only reporter citations count as citations here: the general extractor reads a transcript's line numbers as
 *  volumes and pages ("11 MS. GEORGETTE P. ODEN 12", "01 P.M. 2"), and 23 of the first 28 "lost" citations on
 *  forty dockets were that. A volume, a reporter we know, a page. */
const REPORTER = /^\d{1,4}\s+(?:U\.S\.|S\.\s?Ct\.|L\.\s?Ed\.(?:\s?2d)?|F\.(?:\s?(?:2d|3d|4th))?|F\.\s?Supp\.(?:\s?(?:2d|3d))?|F\.R\.D\.|B\.R\.|S\.W\.(?:\s?(?:2d|3d))?|S\.E\.(?:\s?2d)?|N\.E\.(?:\s?(?:2d|3d))?|N\.W\.(?:\s?2d)?|P\.(?:\s?(?:2d|3d))?|A\.(?:\s?(?:2d|3d))?|So\.(?:\s?(?:2d|3d))?|Cal\.\s?Rptr\.(?:\s?(?:2d|3d))?|N\.Y\.S\.(?:\s?(?:2d|3d))?|Tex\.|WL|Fed\.\s?Appx\.|F\.\s?App'x)\s+\d{1,8}$/;
// a dotted phone or fax number on a signature block ("T. 832.393.6491\nF. 832.393.6259") reads as "6491 F. 832" to the
// extractor: the sixth proof run's last two "lost" citations were the fax numbers the scrambler had rightly taken
const PHONE_SHAPE = /\b\d{3}[.\-]\d{3}[.\-]\d{4}\b/g;
const reporterCites = (t: string) => new Set(extractCitations(t.replace(PHONE_SHAPE, (m) => " ".repeat(m.length))).filter((c) => REPORTER.test(c.replace(/\s+/g, " ").trim())));
const CAP_PHRASE = /\b(?:[A-Z][\p{L}'’.-]+(?:\s+[A-Z][\p{L}'’.-]+){0,3})\b/gu;

function summarize(reports: Report[], excluded: string[]) {
  const by: Record<string, { present: number; leaked: number; per_1000: number | null; ci: [number, number] | null }> = {};
  let present = 0, leaked = 0, cin = 0, lost = 0, ms = 0, chunks = 0, exact = 0, refused = 0, split = 0, ents = 0, chars = 0;
  for (const r of reports) {
    present += r.present; leaked += r.leaked; cin += r.citations_in; lost += r.citations_missing.length; ms += r.ms; chunks += r.restore.chunks; exact += r.restore.exact; refused += r.refused_docs.length; split += r.consistency.split.length; ents += r.consistency.entities_seen; chars += r.chars;
    for (const [t, v] of Object.entries(r.by_type)) { const b = by[t] ??= { present: 0, leaked: 0, per_1000: null, ci: null }; b.present += v.present; b.leaked += v.leaked; }
  }
  for (const b of Object.values(by)) { b.per_1000 = b.present ? Math.round((b.leaked / b.present) * 10000) / 10 : null; b.ci = wilson(b.leaked, b.present); }
  return { dockets: reports.length, excluded_transport: excluded.length, docs_refused: refused, chars, present, leaked, per_1000: present ? Math.round((leaked / present) * 10000) / 10 : null, per_1000_ci: wilson(leaked, present), by_type: by, entities_seen: ents, entities_split: split, citations_in: cin, citations_lost: lost, restore_chunks: chunks, restore_exact: exact, ms_total: ms };
}

(async () => {
  const ids = fs.existsSync(DIR) ? fs.readdirSync(DIR).filter((f) => fs.existsSync(path.join(DIR, f, "docket.json"))).sort() : [];
  if (!ids.length) { console.error(`no dockets under ${DIR} (see the header of this script)`); process.exit(2); }
  const jsonPath = arg("json");
  const prior = arg("resume") && fs.existsSync(arg("resume")!) ? JSON.parse(fs.readFileSync(arg("resume")!, "utf8")) as { reports?: Report[]; excluded_transport?: string[] } : {};
  const reports: Report[] = prior.reports ?? []; const excluded: string[] = argv.includes("--retry-excluded") ? [] : (prior.excluded_transport ?? []);
  const done = new Set([...reports.map((r) => r.identifier), ...excluded]);
  const fake = has("fake");
  const liaison = fake ? null : localScrambler();
  console.log(`case files at ${COMMIT}: ${ids.length} dockets under ${DIR}; model: ${fake ? "ORACLE (ceiling, not a liaison number)" : `private liaison ${process.env.LIAISON_MODEL}`}; chunk ${CHUNK}/${OVERLAP}`);
  const save = (partial: boolean) => { if (jsonPath) fs.writeFileSync(jsonPath, JSON.stringify({ summary: summarize(reports, excluded), reports, excluded_transport: excluded, partial, mode: fake ? "oracle" : "liaison", model: fake ? "oracle" : process.env.LIAISON_MODEL, chunk: CHUNK, overlap: OVERLAP, at: new Date().toISOString() }, null, 2) + "\n"); };

  let n = 0;
  for (const id of ids) {
    if (n >= LIMIT) break; if (done.has(id) || (ONLY && id !== ONLY)) continue; n++;
    const d = JSON.parse(fs.readFileSync(path.join(DIR, id, "docket.json"), "utf8")) as Docket;
    const truth = truthOf(d);
    const files = (d.docs ?? []).map((x) => x.file).sort((a, b) => { const na = a.match(/\.(\d+)\.(\d+)\.txt$/), nb = b.match(/\.(\d+)\.(\d+)\.txt$/); return na && nb ? (Number(na[1]) - Number(nb[1])) || (Number(na[2]) - Number(nb[2])) : a.localeCompare(b); });
    const docs = files.map((f) => ({ file: f, text: fs.readFileSync(path.join(DIR, id, "docs", f), "utf8").slice(0, 60_000) }));
    // the oracle proposes every ground-truth variant present in the chunk, AS IT APPEARS THERE ("STATE OF TEXAS",
    // "PAUL WATKINS"): a case-sensitive check made the ceiling report two leaks that were the oracle's misses
    const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+(?:§\\s*)?"); // (a caption gutter "§" between the words is whitespace, as flex() reads it)
    // (the name as it appears, minus a caption gutter "§": a real model reads across the gutter and proposes the clean name)
    // (the oracle reads the DOCUMENT part of the prompt: the alias hints above it list what is already known, and
    // an oracle that re-proposed those filled its 80 spans with rejections and never reached the rest of a party list)
    // ...and, like a competent model, it does not re-propose what the alias hints already list: under the regex-only
    // model view (lesson XXIII) the known names stay visible in the document, and an oracle that re-listed its first
    // 80 every round added nothing new, the rounds stopped, and the tail of a 1,494-party list was never proposed
    const model: LocalModel = fake ? async (p) => { if (p.includes("auditing")) return JSON.stringify({ leaks: [], inconsistent: [] }); const hints = p.slice(0, p.indexOf("<<<DOCUMENT")); const known = new Set([...hints.matchAll(/^- "((?:[^"\\]|\\.)*)" = \[/gm)].map((m) => JSON.parse(`"${m[1]}"`).toLowerCase())); const body = p.slice(p.indexOf("<<<DOCUMENT")); return JSON.stringify({ spans: truth.flatMap((t) => t.variants.filter((v) => !known.has(v.toLowerCase())).flatMap((v) => { const m = new RegExp(`(?<![\\p{L}])${esc(v)}(?![\\p{L}])`, "iu").exec(body); return m ? [{ text: m[0].replace(/\s*§\s*/g, " ").replace(/\s+/g, " "), type: t.type }] : []; })).slice(0, 80), coref: {} }); } : liaison!;
    let chunksSent = 0, modelCalls = 0, modelMs = 0, pass2Calls = 0, pass2Ms = 0, pass2Catches = 0;
    const timed: LocalModel = async (p, f) => { const tm = Date.now(); const audit = p.includes("auditing"); modelCalls++; if (audit) pass2Calls++; try { return await model(p, f); } finally { const d = Date.now() - tm; modelMs += d; if (audit) pass2Ms += d; } };
    const graph = new MatterGraph(`casefile:${id}`); const t0 = Date.now();
    const refusedDocs: Report["refused_docs"] = []; let degraded = 0, transport = false, nChunks = 0;
    // phase 1: discovery -- every chunk of every filing, in docket order, one graph
    let fi = 0;
    for (const doc of docs) {
      const chunks = paragraphs(doc.text, CHUNK, OVERLAP); nChunks += chunks.length;
      // progress, one line per filing (not for the oracle): a live docket runs for hours and printed nothing until it
      // finished, so a slow run and a stuck one looked the same (2026-09-16)
      const tf = Date.now(); let rounds = 0, maxRounds = 0; fi++;
      for (const c of chunks) {
        try {
          // a transport failure (the tunnel re-dialing) costs the chunk a retry, not the docket two hours of work
          chunksSent++; let r = await scrambleDocument(c, graph, timed); pass2Catches += r.verdict_leaks ?? 0; rounds += r.pass1_rounds ?? 1; maxRounds = Math.max(maxRounds, r.pass1_rounds ?? 1);
          for (let attempt = 1; attempt <= 3 && r.degraded.some(isTransportFailure); attempt++) { await new Promise((res) => setTimeout(res, 15_000 * attempt)); console.log(`    transport on a chunk of ${doc.file}; retry ${attempt} (${r.degraded.find(isTransportFailure)?.slice(0, 100)})`); r = await scrambleDocument(c, graph, timed); }
          if (r.degraded.length) { degraded++; if (r.degraded.some(isTransportFailure)) transport = true; }
        }
        catch (e) { refusedDocs.push({ file: doc.file, message: (e as Error).message.slice(0, 200) }); explainRefusal(c, graph, doc.file); break; }
      }
      if (!fake) console.log(`    [${fi}/${docs.length}] ${doc.file.split(".").slice(-3, -1).join(".")}  ${(doc.text.length / 1000).toFixed(0)}k  ${chunks.length} chunks  pass-1 rounds ${rounds} (max ${maxRounds})  ${((Date.now() - tf) / 1000).toFixed(0)}s  graph ${graph.size}  pass-2 caught so far ${pass2Catches}`);
    }
    if (transport) { excluded.push(id); console.log(`${id}  EXCLUDED (transport)`); save(true); continue; }
    // phase 2: the cross-document final pass with the complete graph, ledgered
    // released text only on both sides: a refused filing is counted as refused, never as "lost citations"
    let input = ""; let output = ""; let exact = 0, normalizedBasis = 0, finalChunks = 0;
    const truthLowerAll = truth.flatMap((t) => t.variants.map((v) => v.toLowerCase().replace(/\s+/g, " "))); const nameOriginals: string[] = [];
    for (const doc of docs) {
      const chunks = paragraphs(doc.text, CHUNK, OVERLAP);
      let finals: ReturnType<typeof finalizeChunksWithLedger>;
      try { finals = finalizeChunksWithLedger(chunks, graph); }
      catch (e) { refusedDocs.push({ file: doc.file, message: `final pass: ${(e as Error).message.slice(0, 180)}` }); for (const c of chunks) explainRefusal(c, graph, `${doc.file} final`); continue; }
      input += doc.text + "\n\n";
      for (let i = 0; i < finals.length; i++) {
        finalChunks++; const f = finals[i]; if (f.basis === "normalized") normalizedBasis++;
        // every original a placeholder replaced whose text carries a ground-truth variant: a phrase that vanished
        // INSIDE one of these ("Jason" of "Jason Shurb") was scrubbed as part of a name, by design
        for (const o of f.occurrences) { const low = o.original.toLowerCase().replace(/\s+/g, " "); if (truthLowerAll.some((v) => low.includes(v))) nameOriginals.push(low); }
        const expected = f.basis === "raw" ? chunks[i] : normalizeInput(chunks[i]).text;
        try { if (restoreDocument(f.text, f.occurrences) === expected) exact++; } catch { /* counted as inexact */ }
        output += f.text + "\n\n";
      }
    }
    // measure: leaks by type; cross-document consistency of each ground-truth entity
    const by: Report["by_type"] = {}; let present = 0, leaked = 0;
    const split: Report["consistency"]["split"] = []; let seenEnts = 0, consistent = 0;
    const subs = graph.substitutions();
    for (const t of truth) {
      const here = t.variants.filter((v) => nonCaption(input, v) > 0);
      if (!here.length) continue;
      present++; const b = by[t.type] ??= { present: 0, leaked: 0 }; b.present++;
      if (here.some((v) => nonCaption(output, v) > 0)) { leaked++; b.leaked++; (b.leaked_names ??= []).push(t.name); }
      // which placeholders did this entity's surface forms map to across the whole file? A bare surname that the
      // MATTER shares (two or more nodes carry a fuller name ending in it) is its own node by design and restores
      // verbatim; it is left out of the entity's forms here, so consistency is measured on the unambiguous ones.
      // (Before the regex-only model view, lesson XXIII, a second person of a known surname was silently absorbed
      // into the first and this count read them as one -- the old figure was partly wrong merges.)
      const owners = (sur: string) => new Set(subs.filter((s) => /\s/.test(s.alias.trim()) && s.alias.trim().toLowerCase().replace(/[,.;:()"']/g, "").split(/\s+/).filter((t) => !/^(?:jr|sr|ii|iii|iv|esq|md|phd)$/.test(t)).pop() === sur.toLowerCase()).map((s) => s.placeholder)).size;
      const forms = here.filter((v) => /\s/.test(v.trim()) || owners(v) < 2);
      const phs = new Set(subs.filter((s) => forms.some((v) => s.alias.toLowerCase() === v.toLowerCase())).map((s) => s.placeholder));
      if (phs.size) { seenEnts++; if (phs.size === 1) consistent++; else split.push({ name: t.name, placeholders: [...phs] }); }
    }
    const cin = reporterCites(input), cout = reporterCites(output); const missing = [...cin].filter((c) => !cout.has(c));
    const truthLower = new Set(truthLowerAll);
    const phrases = new Set([...input.matchAll(CAP_PHRASE)].map((m) => m[0]).filter((p) => p.length >= 6 && !truthLower.has(p.toLowerCase())));
    // (compared with whitespace folded: a phrase wrapped across a line in the input is the same phrase in the output)
    const outputFolded = output.replace(/\s+/g, " ");
    const vanished = [...phrases].filter((p) => !outputFolded.includes(p.replace(/\s+/g, " ")));
    const overScrub = vanished.length;
    // the tighter bound: vanished phrases that are not part of a scrubbed ground-truth name and carry no digit or "@"
    // (an identifier); what is left is a non-party name the list does not carry, a defined term, or a real over-scrub
    // the phrase's CORE: no leading role or connective word ("Plaintiff Jason Shurb", "When Dr. McLendon", "The
    // University"), no trailing punctuation or possessive ("Shurb\u2019s", "Hospital."); an empty or role-only core is noise
    const core = (p: string) => p.trim().replace(/^(?:Plaintiffs?|Defendants?|Respondents?|Petitioners?|Appellants?|Appellees?|Dr|Mr|Mrs|Ms|Judge|Hon|The|When|Despite|Although|During|In|By|See|Also|And|Or|Of|To|At|On|For|With|From|As|If|But|That|This|Because|While|After|Before|Since|Resident|Professor|Deputy|Assistant)\.?\s+/iu, "").replace(/[\u2019'’]s$/u, "").replace(/[,.;:()"']+$/u, "").trim().toLowerCase().replace(/\s+/g, " ");
    const vanishedTight = vanished.filter((p) => { const c = core(p); return c.length >= 3 && !/[\p{N}@]/u.test(c) && !/^(?:plaintiffs?|defendants?|the|of|and|by|dr|mr|ms|mrs|jr|sr|attorney-in-charge)$/i.test(c) && !truthLowerAll.some((v) => c.includes(v) || v.includes(c)) && !nameOriginals.some((o) => o.includes(c) || c.includes(o)); });
    const overScrubTight = vanishedTight.length;
    if (DUMP_OUT) { fs.mkdirSync(DUMP_OUT, { recursive: true }); fs.writeFileSync(path.join(DUMP_OUT, `${id}.vanished.txt`), vanishedTight.join("\n") + "\n"); } // (with --dump-output: the phrases behind the tight bound, to read)
    const rep: Report = { identifier: id, case_name: d.case_name ?? d.title, docs: docs.length, chunks: nChunks, chars: input.length, ms: Date.now() - t0, chunks_sent: chunksSent, model_calls: modelCalls, model_ms: modelMs, pass2_calls: pass2Calls, pass2_ms: pass2Ms, pass2_catches: pass2Catches, commit: COMMIT, truth: truth.length, present, leaked, by_type: by,
      consistency: { entities_seen: seenEnts, consistent, split }, citations_in: cin.size, citations_out: cout.size, citations_missing: missing, refused_docs: refusedDocs, degraded,
      restore: { chunks: finalChunks, exact, normalized_basis: normalizedBasis }, over_scrub_proxy: overScrub, over_scrub_candidates: phrases.size, over_scrub_tight: overScrubTight };
    reports.push(rep); save(true);
    const leakStr = Object.entries(by).filter(([, v]) => v.leaked).map(([t, v]) => `${t} ${v.leaked}/${v.present}`).join(" ");
    if (DUMP_OUT) { fs.mkdirSync(DUMP_OUT, { recursive: true }); fs.writeFileSync(path.join(DUMP_OUT, `${id}.out.txt`), output); }
    if (DUMP) { fs.mkdirSync(DUMP, { recursive: true }); fs.writeFileSync(path.join(DUMP, `${id}.graph.json`), JSON.stringify(graph.toJSON(), null, 1)); }
    console.log(`${id}  "${(rep.case_name ?? "").slice(0, 40)}"  docs=${docs.length} chunks=${nChunks} sent=${chunksSent} calls=${modelCalls} model=${(modelMs / 1000).toFixed(0)}s (${chunksSent ? (modelMs / 1000 / chunksSent).toFixed(1) : "-"}s/chunk) pass2 ${pass2Calls} calls ${(pass2Ms / 1000).toFixed(0)}s caught ${pass2Catches} ${(input.length / 1000).toFixed(0)}k  truth ${present}/${truth.length} present, leaked ${leaked}  entities ${consistent}/${seenEnts} consistent${split.length ? ` SPLIT ${split.length}` : ""}  cites ${cin.size}->${cout.size}${missing.length ? " LOST" : ""}  restore ${exact}/${finalChunks} exact  refused ${refusedDocs.length}  ${(rep.ms / 1000).toFixed(0)}s  ${leakStr}`);
    for (const r of refusedDocs) console.log(`    refused ${r.file}: ${r.message.slice(0, 120)}`);
  }
  const s = summarize(reports, excluded);
  console.log(`\ndockets ${s.dockets} (excluded for transport ${s.excluded_transport}); filings refused ${s.docs_refused}; ${(s.chars / 1e6).toFixed(2)}M chars; model time ${(s.ms_total / 1000).toFixed(0)}s`);
  console.log(`ground-truth entities present ${s.present}, leaked ${s.leaked} => ${s.per_1000 ?? "n/a"} per 1,000  ${s.per_1000_ci ? `[${s.per_1000_ci[0]}, ${s.per_1000_ci[1]}]` : ""}`);
  for (const [t, b] of Object.entries(s.by_type)) console.log(`  ${t.padEnd(9)} ${String(b.leaked).padStart(4)} / ${String(b.present).padEnd(5)} => ${String(b.per_1000 ?? "n/a").padStart(6)} per 1,000  ${b.ci ? `[${b.ci[0]}, ${b.ci[1]}]` : ""}`);
  console.log(`cross-document consistency: ${s.entities_seen - s.entities_split} of ${s.entities_seen} entities on one placeholder (${s.entities_split} split)`);
  console.log(`citations ${s.citations_in} in, ${s.citations_lost} lost; restore ${s.restore_exact}/${s.restore_chunks} chunks byte-exact`);
  save(false);
})().catch((e) => { console.error(`casefile: ${(e as Error).message}`); process.exit(1); });
