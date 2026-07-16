import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateBody } from '../../middleware/validate';
import { asyncHandler, HttpError } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';
import { findCandidates, maskSecret } from './prefilter';
import { classifyCandidate, LLM_MODEL } from './llm';
import { fetchRemoteSource, RemoteFetchError } from './fetchRemote';

const router = Router();
router.use(verifyJwt);

const CONTEXT_RADIUS = 60;
// Caps LLM calls (cost + latency) per request — plenty for a hackathon demo file/paste.
const MAX_CANDIDATES_PER_SCAN = 25;

const scanSchema = z
  .object({
    source: z.string().trim().min(1).max(255),
    content: z.string().max(2_000_000).optional(),
    repoUrl: z.string().url().optional(),
  })
  .refine((body) => Boolean(body.content) !== Boolean(body.repoUrl), {
    message: 'exactly one of content or repoUrl is required',
  });

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

router.post(
  '/scan',
  requirePermission('write'),
  validateBody(scanSchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { source, content, repoUrl } = req.body as z.infer<typeof scanSchema>;

    let text: string;
    if (repoUrl) {
      try {
        text = await fetchRemoteSource(repoUrl);
      } catch (err) {
        if (err instanceof RemoteFetchError) {
          throw new HttpError(400, 'invalid request');
        }
        throw err;
      }
    } else {
      text = content!;
    }

    const candidates = findCandidates(text).slice(0, MAX_CANDIDATES_PER_SCAN);

    // Stage 2 (LLM calls) runs OUTSIDE any DB transaction and in parallel —
    // network round-trips here could easily exceed Prisma's interactive
    // transaction timeout, and there's no reason to hold a DB transaction
    // open while waiting on a third-party API anyway.
    const classified = await Promise.all(
      candidates.map(async (candidate) => {
        const maskedSnippet = maskSecret(candidate.match);
        const start = Math.max(0, candidate.index - CONTEXT_RADIUS);
        const end = Math.min(text.length, candidate.index + candidate.match.length + CONTEXT_RADIUS);
        const rawContext = text.slice(start, end);
        // Mask every occurrence of the real value within the context too —
        // the LLM never sees the unmasked secret, even as surrounding text.
        const context = rawContext.split(candidate.match).join(maskedSnippet);

        const classification = await classifyCandidate({
          secretType: candidate.secretType,
          maskedSnippet,
          context,
          filename: source,
        });

        return {
          candidate,
          maskedSnippet,
          classification,
          line: lineNumberAt(text, candidate.index),
        };
      }),
    );

    const findings = await withTenantTx(auth.tenantId, async (tx) => {
      const created = [];
      for (const { candidate, maskedSnippet, classification, line } of classified) {
        const finding = await tx.scanFinding.create({
          data: {
            tenantId: auth.tenantId,
            source,
            secretType: candidate.secretType,
            matchedSnippet: maskedSnippet,
            severity: classification.severity,
            llmVerdict: classification.verdict,
            remediation: classification.remediation,
          },
        });
        // `line` isn't persisted (the table has no such column — it's
        // purely a same-request convenience for the caller), so it's
        // attached to the response payload rather than the DB row.
        created.push({ ...finding, line });
      }

      if (created.length > 0) {
        await appendAuditEntry(tx, {
          tenantId: auth.tenantId,
          actorId: auth.userId,
          action: 'scanner.scan',
          resourceType: 'scan_finding',
          details: { source, findingsCount: created.length },
        });
      }

      return created;
    });

    const allUsedLlm = classified.every((c) => c.classification.usedLlm);
    res.status(201).json({
      findings,
      modelUsed: allUsedLlm ? LLM_MODEL : 'local-heuristics-fallback',
      isMocked: !allUsedLlm,
    });
  }),
);

router.get(
  '/findings',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const findings = await withTenantTx(auth.tenantId, (tx) =>
      tx.scanFinding.findMany({ where: { tenantId: auth.tenantId }, orderBy: { createdAt: 'desc' } }),
    );
    res.json({ findings });
  }),
);

export default router;
