import { PrismaClient } from '@prisma/client';

// Never log query params at info level or above — they can contain secret
// ciphertext, wrapped DEKs, or audit details. Errors are logged with only
// their message (see middleware/errorHandler.ts), never raw query text.
export const prisma = new PrismaClient({
  log: [{ level: 'error', emit: 'stdout' }],
});
