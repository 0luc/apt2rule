import type { Country, TargetGroup } from "./types";

/**
 * Curated target groups. Every variant is spelled out: matching is whole-word, with no stemming.
 * Capitalised terms (EU, US, UK, NATO, IT, ...) match case-sensitively; everything else ignores case.
 */
const EU = "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE";
const EUROPE = `${EU} IS NO LI CH GB AL AD BA XK MD MC ME MK RS SM UA VA`;

/**
 * Regions, with the country codes they also cover: a group naming "Germany" names Europe too.
 * Russia, Belarus, Turkey and the Caucasus are left out of Europe: naming them says little about Europe.
 */
const REGIONS: [string, string, string[], string][] = [
  ["west", "West", ["Western", "the West", "NATO", "Five Eyes", "Europe", "European", "EU", "European Union", "North America",
    "North American", "United States", "U.S.", "US", "USA", "United Kingdom", "UK", "U.K.", "Britain", "British", "Canada",
    "Canadian", "Australia", "Australian", "New Zealand"], `${EU} IS NO LI CH GB AL ME MK US CA AU NZ`],
  ["europe", "Europe", ["Europe", "European", "EU", "European Union", "Western Europe", "Eastern Europe", "Central Europe",
    "Northern Europe", "Southern Europe", "Scandinavia", "Scandinavian", "Nordic", "Baltic", "Baltics", "Benelux", "Balkans"], EUROPE],
  ["north-america", "North America", ["North America", "North American", "United States", "U.S.", "US", "USA", "Canada", "Canadian"], "US CA"],
  ["middle-east", "Middle East", ["Middle East", "Middle Eastern", "Gulf", "Persian Gulf", "GCC", "MENA"],
    "AE BH EG IL IQ IR JO KW LB OM PS QA SA SY TR YE"],
  ["asia-pacific", "Asia-Pacific", ["Asia", "Asian", "Asia-Pacific", "Asia Pacific", "APAC", "APJ", "East Asia", "East Asian",
    "Southeast Asia", "Southeast Asian", "South East Asia", "South Asia", "South Asian", "Central Asia", "Central Asian", "Pacific"],
    "AF AU BD BN BT CN FJ FM HK ID IN JP KG KH KI KP KR KZ LA LK MH MM MN MV MY NP NR NZ PG PH PK PW SB SG TH TJ TL TM TO TV TW UZ VN VU WS"],
  ["africa", "Africa", ["Africa", "African", "North Africa", "North African", "Sub-Saharan", "West Africa", "East Africa"],
    "AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG ER ET GA GH GM GN GQ GW KE KM LR LS LY MA MG ML MR MU MW MZ NA NE NG RW SC SD SL SN SO SS ST SZ TD TG TN TZ UG ZA ZM ZW"],
  ["latin-america", "Latin America", ["Latin America", "Latin American", "South America", "South American", "Central America",
    "Central American", "Caribbean"], "AG AR BB BO BR BS BZ CL CO CR CU DM DO EC GD GT GY HN HT JM KN LC MX NI PA PE PY SR SV TT UY VC VE"],
  ["international", "International organisations", ["NATO", "United Nations", "UN", "OSCE", "intergovernmental",
    "international organizations", "international organisations", "international affairs"], ""],
];

const SECTORS: [string, string, string[]][] = [
  ["government", "Government", ["government", "governments", "governmental", "ministry", "ministries", "diplomatic",
    "diplomats", "diplomat", "embassy", "embassies", "consulate", "foreign affairs", "public sector", "public administration",
    "government agencies", "state agencies", "parliament", "parliaments", "municipal", "municipalities", "local government"]],
  ["defence", "Defence", ["defense", "defence", "military", "armed forces", "defense industrial base", "defense contractors",
    "defence contractors", "aerospace"]],
  ["energy", "Energy", ["energy", "oil", "gas", "oil and gas", "petroleum", "petrochemical", "electric", "electricity",
    "power grid", "utilities", "utility", "nuclear"]],
  ["finance", "Finance", ["financial", "finance", "financial institutions", "bank", "banks", "banking", "insurance",
    "fintech", "payment", "payments"]],
  ["crypto", "Cryptocurrency", ["cryptocurrency", "cryptocurrencies", "crypto", "cryptocurrency exchanges",
    "cryptocurrency exchange", "blockchain", "DeFi", "Bitcoin", "digital currency", "NFT", "NFTs"]],
  ["healthcare", "Healthcare", ["healthcare", "health care", "health", "hospital", "hospitals", "medical", "pharmaceutical",
    "pharmaceuticals", "biotechnology"]],
  ["telecom", "Telecommunications", ["telecommunications", "telecommunication", "telecom", "telecoms", "internet service providers",
    "internet service provider", "ISP", "ISPs", "satellite"]],
  ["technology", "Technology and IT services", ["technology", "IT", "IT service providers", "managed service providers",
    "managed service provider", "MSP", "MSPs", "software", "semiconductor", "cloud"]],
  ["education", "Education and research", ["education", "educational", "university", "universities", "academic",
    "academia", "research", "think tank", "think tanks"]],
  ["critical-infrastructure", "Critical infrastructure", ["critical infrastructure", "industrial control", "ICS", "SCADA",
    "water", "utilities"]],
  ["transport", "Transport and logistics", ["transportation", "transport", "aviation", "airline", "airlines", "maritime",
    "shipping", "logistics", "rail"]],
  ["manufacturing", "Manufacturing and engineering", ["manufacturing", "industrial", "engineering", "automotive", "chemical"]],
  ["media", "Media", ["media", "journalists", "journalist", "news", "broadcasting", "publishing"]],
  ["civil-society", "Civil society", ["NGO", "NGOs", "non-governmental", "nongovernmental", "non-profit", "nonprofit",
    "human rights", "activists", "dissidents", "minority rights", "civil society"]],
  ["legal", "Legal", ["law firms", "law firm", "legal"]],
  ["retail", "Retail and hospitality", ["retail", "hospitality", "restaurant", "restaurants", "hotel", "hotels", "gaming"]],
];

/** Hits inside these phrases never count, whatever target group they belong to. */
export const BLOCKING_PHRASES = ["non-governmental", "non-government", "nongovernmental"];

export function targetGroups(countries: Country[]): TargetGroup[] {
  return [
    ...REGIONS.map(([id, label, terms, codes]): TargetGroup => {
      const known = new Set(countries.map((c) => c.code));
      return { id: `region:${id}`, kind: "region", label, terms, countries: codes.split(" ").filter((c) => known.has(c)) };
    }),
    ...SECTORS.map(([id, label, terms]): TargetGroup => ({ id: `sector:${id}`, kind: "sector", label, terms })),
    ...countries.map((c): TargetGroup => ({ id: `country:${c.code}`, kind: "country", label: c.name, terms: c.terms, country: c.code })),
  ];
}
