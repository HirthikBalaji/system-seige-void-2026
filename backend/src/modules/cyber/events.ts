import { EventEmitter } from 'node:events';
import { Response } from 'express';

export const eventBus = new EventEmitter();

interface SseClient {
  tenantId: string;
  res: Response;
}

let activeClients: SseClient[] = [];

export interface AppEvent {
  id: string;
  tenantId: string;
  type: string;
  payload: any;
  timestamp: string;
}

export function publishEvent(tenantId: string, type: string, payload: any) {
  const event: AppEvent = {
    id: crypto.randomUUID(),
    tenantId,
    type,
    payload,
    timestamp: new Date().toISOString(),
  };

  // Emit to local event emitter for background workers
  eventBus.emit(type, event);
  eventBus.emit('*', event);

  // Broadcast to SSE clients for this tenant
  const tenantClients = activeClients.filter((c) => c.tenantId === tenantId);
  for (const client of tenantClients) {
    try {
      client.res.write(`data: ${JSON.stringify(event)}\n\n`);
    } catch (err) {
      console.error('Failed writing to SSE client:', err);
    }
  }
}

export function registerSseClient(tenantId: string, res: Response) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  const client: SseClient = { tenantId, res };
  activeClients.push(client);

  // Send initial ping/connection event
  res.write(`data: ${JSON.stringify({ type: 'system.connected', tenantId })}\n\n`);

  // Handle client disconnect
  res.on('close', () => {
    activeClients = activeClients.filter((c) => c !== client);
  });
}
