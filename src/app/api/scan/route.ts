import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { logEvent } from '@/lib/audit';

const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NIM_BASE_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { text, filename } = body;

    if (!text) {
      throw new ApiError(400, 'Content to scan is required');
    }

    let scanResult;
    let isMockedResponse = false;
    let usedModel = 'none';

    if (!NVIDIA_API_KEY) {
      isMockedResponse = true;
      scanResult = runMockScanner(text, filename);
    } else {
      try {
        // Step 1: Attempt scan with primary 70B model (8-second timeout limit)
        usedModel = 'meta/llama-3.3-70b-instruct';
        scanResult = await fetchNIM(usedModel, text, filename);
      } catch (err: any) {
        console.warn(`Primary model ${usedModel} failed (${err.message}). Attempting Llama 3.1 8B fallback...`);
        
        try {
          // Step 2: Fallback to highly responsive 8B model (8-second timeout limit)
          usedModel = 'meta/llama-3.1-8b-instruct';
          scanResult = await fetchNIM(usedModel, text, filename);
        } catch (fallbackErr: any) {
          console.error('All NVIDIA NIM models failed or timed out:', fallbackErr.message);
          
          // Step 3: Fallback to local heuristic regex scanning
          isMockedResponse = true;
          usedModel = 'local-heuristics';
          scanResult = {
            ...runMockScanner(text, filename),
            summary: `Note: Live AI Scan failed (${fallbackErr.message}). Switched to local heuristics engine.`
          };
        }
      }
    }

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'AI Exposure Scan',
      result: 'SUCCESS',
      details: {
        filename,
        safe: scanResult.safe,
        findingsCount: scanResult.findings.length,
        isMocked: isMockedResponse,
        modelUsed: usedModel
      }
    });

    return NextResponse.json({
      ...scanResult,
      isMocked: isMockedResponse,
      modelUsed: usedModel
    });
  } catch (error) {
    return handleApiError(error);
  }
}

// NIM API Request wrapper with AbortController timeout
async function fetchNIM(modelName: string, text: string, filename?: string) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 seconds timeout

  try {
    const response = await fetch(NIM_BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${NVIDIA_API_KEY}`
      },
      body: JSON.stringify({
        model: modelName,
        messages: [
          {
            role: 'system',
            content: `You are an enterprise-grade AI security scanner. Analyze the provided text/code for sensitive data exposure (such as passwords, API keys, private keys, JWTs, cloud credentials, database connection strings, certificates).
Return your analysis ONLY in valid JSON format. Do not write markdown wrappers like \`\`\`json or explanations.

Follow this structure exactly:
{
  "safe": boolean,
  "findings": [
    {
      "type": "string (e.g. AWS API Key, Private Key, Database Password)",
      "risk": "string (HIGH, MEDIUM, LOW)",
      "evidence": "string (the matching string/context, partially masked with asterisks)",
      "line": number,
      "remediation": "string (concrete steps to secure it)"
    }
  ],
  "summary": "string summarising the scan results"
}`
          },
          {
            role: 'user',
            content: `Scan the following file content${filename ? ` (filename: ${filename})` : ''}:\n\n${text}`
          }
        ],
        temperature: 0.1,
        max_tokens: 2048
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Status ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const contentText = data.choices[0]?.message?.content || '';
    
    try {
      const cleanedText = contentText.replace(/```json/g, '').replace(/```/g, '').trim();
      return JSON.parse(cleanedText);
    } catch (parseErr) {
      console.error('Failed to parse NIM JSON response:', contentText);
      throw new Error('Invalid JSON format returned from AI model');
    }
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new Error('Request timed out after 8 seconds');
    }
    throw err;
  }
}

// Heuristics scanner to simulate LLM structure when NVIDIA key is missing or calls fail
function runMockScanner(text: string, filename?: string) {
  const findings = [];
  const lines = text.split('\n');

  const patterns = [
    { type: 'AWS API Key', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA)[A-Z0-9]{16}/, risk: 'HIGH', rec: 'Revoke key in AWS IAM console and rotate credentials.' },
    { type: 'Private Key', regex: /-----BEGIN (RSA |EC |PGP )?PRIVATE KEY-----/, risk: 'HIGH', rec: 'Revoke and rotate certificate. Do not commit private keys to source control.' },
    { type: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, risk: 'MEDIUM', rec: 'Deactivate and delete webhook URL in Slack settings.' },
    { type: 'Generic API Key / Token', regex: /(api_key|apikey|secret|token|password|passwd|auth_token)\s*[:=]\s*['"`][A-Za-z0-9\-_\.\+=]{8,}['"`]/i, risk: 'HIGH', rec: 'Rotate secret, and store it in an environment variable or secret manager.' }
  ];

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];
    for (const pattern of patterns) {
      const match = lineContent.match(pattern.regex);
      if (match) {
        const matchedStr = match[0];
        let masked = matchedStr;
        if (matchedStr.length > 8) {
          masked = matchedStr.substring(0, 4) + '...' + matchedStr.substring(matchedStr.length - 4);
        }

        findings.push({
          type: pattern.type,
          risk: pattern.risk,
          evidence: masked,
          line: i + 1,
          remediation: pattern.rec
        });
      }
    }
  }

  const safe = findings.length === 0;
  return {
    safe,
    findings,
    summary: safe
      ? 'No exposed secrets or credentials detected in the code.'
      : `Detected ${findings.length} potential security exposure(s) in file: ${filename || 'unnamed'}.`
  };
}
