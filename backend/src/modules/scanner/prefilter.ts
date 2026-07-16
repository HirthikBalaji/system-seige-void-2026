export interface Candidate {
  secretType: string;
  match: string;
  index: number;
}

const NAMED_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: 'aws_key', regex: /AKIA[0-9A-Z]{16}/g },
  { type: 'generic_api_key', regex: /(?:api[_-]?key|secret)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}/gi },
  { type: 'private_key', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g },
];

const HIGH_ENTROPY_TOKEN = /[A-Za-z0-9+/=_-]{20,}/g;
const ENTROPY_THRESHOLD = 4.0;

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  const len = str.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Deterministic Stage 1: regex + entropy only, no LLM call. */
export function findCandidates(content: string): Candidate[] {
  const candidates: Candidate[] = [];
  const seen = new Set<string>();

  for (const { type, regex } of NAMED_PATTERNS) {
    for (const match of content.matchAll(regex)) {
      candidates.push({ secretType: type, match: match[0], index: match.index ?? 0 });
      seen.add(match[0]);
    }
  }

  for (const match of content.matchAll(HIGH_ENTROPY_TOKEN)) {
    const token = match[0];
    if (seen.has(token)) continue;
    if (shannonEntropy(token) > ENTROPY_THRESHOLD) {
      candidates.push({ secretType: 'generic_high_entropy', match: token, index: match.index ?? 0 });
      seen.add(token);
    }
  }

  return candidates;
}

/** Masks the middle of a secret value — only ever what leaves this process. */
export function maskSecret(value: string): string {
  const edgeLen = Math.min(4, Math.floor(value.length / 4));
  if (value.length <= edgeLen * 2) {
    return '*'.repeat(value.length);
  }
  const prefix = value.slice(0, edgeLen);
  const suffix = value.slice(value.length - edgeLen);
  return `${prefix}${'*'.repeat(value.length - edgeLen * 2)}${suffix}`;
}
