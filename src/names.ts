// One honorific list, shared. index.ts derives surnames with it and apply.ts's fragment rule skips titles with
// it; when they were two lists, "Officer" was in one and not the other, and "Officer [PERSON_4]" -- a title next
// to a placeholder, which is exactly right -- was refused as a leaked fragment on five battery documents
// (2026-09-15). Titles, ranks, suffixes and the connective words that appear inside organisation names.
export const HONORIFIC = /^(mr|mrs|ms|miss|mx|dr|judge|justice|hon|honorable|sen|senator|rep|representative|gov|governor|mayor|sheriff|constable|atty|attorney|prof|professor|sir|dame|rev|reverend|pastor|father|sister|officer|detective|sergeant|sgt|lieutenant|lt|captain|capt|deputy|trooper|agent|nurse|coach|jr|sr|ii|iii|iv|the|of|and|inc|llc|llp|lp|co|corp|ltd|plc)\.?$/i;
