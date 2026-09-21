// The DeepSeek-generated battery (scripts/scrambler-battery-gen.ts): loading it and cleaning its ground truth. Shared
// by the offline test (tests/scrambler-battery.test.ts, fake models) and the live harness
// (scripts/scrambler-battery-liaison.ts, the private liaison), so both score against the same truth.
import fs from "node:fs";
import path from "node:path";
import { ENTITY_TYPES, type EntityType } from "./types";
import { isStatuteOrRule } from "./guard";
import { extractCitations } from "./citations";

/** `id` is `${seed}-${n}`: a seed names a generator CALL of five documents, so it is not a document key. */
export type BatteryDoc = { id: string; seed: number; title: string; text: string; secrets: { text: string; type: string }[]; public_law: string[]; cited_case_parties?: string[]; injection?: string };

export const BATTERY_DIR = path.join(process.cwd(), "data", "battery");

/** The generator sometimes lists PUBLIC LAW as a "secret" -- "11 U.S.C. § 523(a)(6)" typed "PUBLIC" on seed 1 --
 *  and the scrambler is REQUIRED to leave that alone. A secret is only a secret if its type is one of ours and
 *  it is not a citation or statute section; the rest is the generator mislabelling, dropped here just as
 *  measure.ts's usableNames() drops it for the HLL ground truth. A bare number of six digits or fewer ("4567" from
 *  "account ending in 4567") is not a secret on its own -- it is a year, a page, a section as often as not -- and
 *  the guard refuses it as a span on purpose; the PHRASE is what the regex pass catches. */
export function cleanSecrets(secrets: BatteryDoc["secrets"]): BatteryDoc["secrets"] {
  return secrets.filter((s) => (ENTITY_TYPES as readonly string[]).includes(s.type) && !extractCitations(s.text).length && !isStatuteOrRule(s.text) && !/^\(?[A-Z][A-Za-z.& ]{0,30}\d{4}\)?$/.test(s.text) && !/^\d{1,6}$/.test(s.text)
    // a city, a county, a state, a street name with no number ("Houston", "Harris County", "Westheimer Road",
    // "Texas 77005") is not an address to anonymise; an ADDRESS secret carries a number
    && !(s.type === "ADDRESS" && !/\d/.test(s.text.replace(/\b(?:Texas|TX)\s+\d{5}$/, "")))
    // a case name or an administrative reporter the generator typed as a person, judge or docket ("Matter of Cruz",
    // "Vasquez v. Lone Star Logistics, Inc.", "25 I&N Dec. 410"), and a role label ("Attorney for Plaintiff")
    && !/^(?:Matter of|In re|Ex parte)\b/.test(s.text) && !/\sv\.\s/.test(s.text) && !/^\d+\s+[A-Z&.]+\s+(?:Dec|Rep|Ops?)\.?\s+\d+$/.test(s.text)
    && !/^(?:Attorneys?|Counsel)\s+for\s+\w+$/i.test(s.text));
}

export const asType = (t: string): EntityType => ((ENTITY_TYPES as readonly string[]).includes(t) ? t : "OTHER") as EntityType;

export function loadBattery(dir = BATTERY_DIR): BatteryDoc[] {
  if (!fs.existsSync(dir)) return [];
  const out: BatteryDoc[] = [];
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".jsonl")).sort())
    fs.readFileSync(path.join(dir, f), "utf8").split("\n").filter((l) => l.trim()).forEach((line, i) => { const d = JSON.parse(line) as BatteryDoc; out.push({ ...d, id: `${d.seed}-${i + 1}`, secrets: cleanSecrets(d.secrets) }); });
  return out;
}
