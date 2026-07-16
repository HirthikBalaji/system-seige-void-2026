import { env } from '../../env';

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';

// BYOK per the hackathon rule — real model, disclosed in README. Overridable
// via LLM_MODEL for whoever runs this, but this is what we used and tested.
export const LLM_MODEL = process.env.LLM_MODEL ?? 'claude-haiku-4-5-20251001';

export type Verdict = 'confirmed_leak' | 'likely_false_positive';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface LlmClassification {
  verdict: Verdict;
  severity: Severity;
  remediation: string;
  /** false when the real LLM call failed and this is the conservative fallback — surfaced to callers so the UI can be honest about it. */
  usedLlm: boolean;
}

const SYSTEM_PROMPT = [
  'You are a security triage assistant classifying potential leaked credentials found by a',
  'regex/entropy pre-filter. You are given: a secret type label, a MASKED snippet (middle',
  'characters replaced with *, never the full value), a few lines of surrounding context, and a',
  'filename. Decide whether this is a real leaked secret or a false positive (test key,',
  'placeholder, documentation example), assign a severity, and suggest one concrete remediation',
  'step. Respond with ONLY a JSON object, no prose, no markdown fences, matching exactly:',
  '{"verdict":"confirmed_leak"|"likely_false_positive","severity":"low"|"medium"|"high"|"critical","remediation":"<one short actionable sentence>"}',
].join(' ');

const FALLBACK_CLASSIFICATION: LlmClassification = {
  verdict: 'confirmed_leak',
  severity: 'medium',
  remediation: 'Automated classification was unavailable — review this finding manually.',
  usedLlm: false,
};

function parseClassification(text: string): LlmClassification {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return FALLBACK_CLASSIFICATION;
  }
  if (typeof raw !== 'object' || raw === null) {
    return FALLBACK_CLASSIFICATION;
  }

  const obj = raw as Record<string, unknown>;
  const verdict: Verdict = obj.verdict === 'likely_false_positive' ? 'likely_false_positive' : 'confirmed_leak';
  const severities: Severity[] = ['low', 'medium', 'high', 'critical'];
  const severity: Severity = severities.includes(obj.severity as Severity) ? (obj.severity as Severity) : 'medium';
  const remediation =
    typeof obj.remediation === 'string' && obj.remediation.trim().length > 0
      ? obj.remediation.trim().slice(0, 500)
      : FALLBACK_CLASSIFICATION.remediation;

  return { verdict, severity, remediation, usedLlm: true };
}

async function callLlm(userPrompt: string): Promise<LlmClassification> {
  const response = await fetch(ANTHROPIC_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': env.LLM_API_KEY,
      'anthropic-version': ANTHROPIC_VERSION,
    },
    body: JSON.stringify({
      model: LLM_MODEL,
      max_tokens: 300,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });

  if (!response.ok) {
    throw new Error(`LLM request failed with status ${response.status}`);
  }

  const data = (await response.json()) as { content?: Array<{ type: string; text?: string }> };
  const text = data.content?.find((block) => block.type === 'text')?.text ?? '';
  return parseClassification(text);
}

/**
 * Classifies one candidate. Never throws — a single candidate's LLM call
 * failing (network blip, rate limit, malformed response) falls back to a
 * conservative "review manually" verdict instead of failing the whole scan
 * request for every other candidate in it.
 */
export async function classifyCandidate(params: {
  secretType: string;
  maskedSnippet: string;
  context: string;
  filename: string;
}): Promise<LlmClassification> {
  const userPrompt = [
    `secret_type: ${params.secretType}`,
    `filename: ${params.filename}`,
    `masked_snippet: ${params.maskedSnippet}`,
    'context:',
    params.context,
  ].join('\n');

  try {
    return await callLlm(userPrompt);
  } catch (err) {
    console.error('[scanner] LLM classification failed:', err instanceof Error ? err.message : 'unknown error');
    return FALLBACK_CLASSIFICATION;
  }
}
