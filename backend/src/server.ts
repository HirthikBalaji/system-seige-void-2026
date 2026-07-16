import express from 'express';
import { env } from './env';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import vaultRoutes from './modules/vault/routes';
import certRoutes from './modules/certs/routes';
import auditRoutes from './modules/audit/routes';
import scannerRoutes from './modules/scanner/routes';
import rotationRoutes from './modules/rotation/routes';
import sandboxRoutes from './modules/sandbox/routes';
import cyberRoutes from './modules/cyber/routes';
import { startCertLifecycleJob } from './modules/certs/job';
import { startSandboxLifecycleJob } from './modules/sandbox/job';

const app = express();
app.disable('x-powered-by');

// Body size cap — not a substitute for the gateway's own rate-limit policy
// (out of scope here), just a sane default so a single oversized request
// can't balloon memory in this process.
app.use(express.json({ limit: '2mb' }));

app.get('/internal/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/internal/vault', vaultRoutes);
app.use('/internal/certs', certRoutes);
app.use('/internal/audit', auditRoutes);
app.use('/internal/scanner', scannerRoutes);
app.use('/internal/rotation', rotationRoutes);
app.use('/internal/sandbox', sandboxRoutes);
app.use('/internal/cyber', cyberRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

const stopCertJob = startCertLifecycleJob();
const stopSandboxJob = startSandboxLifecycleJob();

const server = app.listen(env.PORT, () => {
  console.log(`secrets-platform backend listening on :${env.PORT}`);
});

function shutdown(): void {
  stopCertJob();
  stopSandboxJob();
  server.close(() => process.exit(0));
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
