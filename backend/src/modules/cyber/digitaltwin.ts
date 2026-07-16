import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';

export interface GraphNode {
  id: string;
  name: string;
  type: 'USER' | 'SECRET' | 'CERTIFICATE' | 'APPLICATION' | 'API' | 'DATABASE' | 'K8S_CLUSTER' | 'CLOUD_RESOURCE' | 'CICD_PIPELINE';
  properties: any;
}

export interface GraphEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  type: 'ACCESSES' | 'CONTAINS' | 'MANAGES' | 'DEPENDS_ON';
}

export class DigitalTwinService {
  /**
   * Seeds a beautiful enterprise infrastructure graph for demo purposes if empty
   */
  static async seedGraphIfEmpty(tenantId: string) {
    return withTenantTx(tenantId, async (tx) => {
      const count = await tx.digitalTwinNode.count({ where: { tenantId } });
      if (count > 0) return;

      console.log(`[DigitalTwin] Seeding initial infrastructure Digital Twin for tenant ${tenantId}...`);

      const nodes: Omit<GraphNode, 'id'>[] = [
        { name: 'Github CI/CD Runner', type: 'CICD_PIPELINE', properties: { env: 'production', provider: 'GitHub Actions' } },
        { name: 'K8s Production Cluster', type: 'K8S_CLUSTER', properties: { zone: 'us-east-1', version: '1.28' } },
        { name: 'Payment Processing Service', type: 'APPLICATION', properties: { language: 'NodeJS', tier: 'Tier-1' } },
        { name: 'Stripe API Gateway Link', type: 'API', properties: { url: 'https://api.stripe.com/v1', mTLS: true } },
        { name: 'Stripe Live Secret Key', type: 'SECRET', properties: { env: 'production', rotation: '90-days' } },
        { name: 'Customer Database', type: 'DATABASE', properties: { technology: 'PostgreSQL', size: '5TB', containsPII: true } },
        { name: 'DB Credentials', type: 'SECRET', properties: { env: 'production' } },
        { name: 'Auth Server TLS Cert', type: 'CERTIFICATE', properties: { issuer: 'Let\'s Encrypt', expiresDays: 45 } },
        { name: 'CISO / Security Administrator', type: 'USER', properties: { mfaEnabled: true, role: 'admin' } },
        { name: 'Lead Software Engineer', type: 'USER', properties: { mfaEnabled: false, role: 'developer' } },
      ];

      const createdNodes: any[] = [];
      for (const node of nodes) {
        const created = await tx.digitalTwinNode.create({
          data: {
            tenantId,
            name: node.name,
            type: node.type,
            properties: node.properties,
          },
        });
        createdNodes.push(created);
      }

      // Map node names to database IDs
      const findId = (name: string) => createdNodes.find((n) => n.name === name)!.id;

      const edges: Omit<GraphEdge, 'id'>[] = [
        { sourceNodeId: findId('Lead Software Engineer'), targetNodeId: findId('Github CI/CD Runner'), type: 'MANAGES' },
        { sourceNodeId: findId('Github CI/CD Runner'), targetNodeId: findId('K8s Production Cluster'), type: 'MANAGES' },
        { sourceNodeId: findId('K8s Production Cluster'), targetNodeId: findId('Payment Processing Service'), type: 'CONTAINS' },
        { sourceNodeId: findId('Payment Processing Service'), targetNodeId: findId('Stripe API Gateway Link'), type: 'ACCESSES' },
        { sourceNodeId: findId('Payment Processing Service'), targetNodeId: findId('Customer Database'), type: 'ACCESSES' },
        { sourceNodeId: findId('Stripe API Gateway Link'), targetNodeId: findId('Stripe Live Secret Key'), type: 'ACCESSES' },
        { sourceNodeId: findId('Customer Database'), targetNodeId: findId('DB Credentials'), type: 'ACCESSES' },
        { sourceNodeId: findId('K8s Production Cluster'), targetNodeId: findId('Auth Server TLS Cert'), type: 'CONTAINS' },
        { sourceNodeId: findId('CISO / Security Administrator'), targetNodeId: findId('K8s Production Cluster'), type: 'MANAGES' },
      ];

      for (const edge of edges) {
        await tx.digitalTwinEdge.create({
          data: {
            tenantId,
            sourceNodeId: edge.sourceNodeId,
            targetNodeId: edge.targetNodeId,
            type: edge.type,
          },
        });
      }

      await appendAuditEntry(tx, {
        tenantId,
        actorId: '00000000-0000-0000-0000-000000000000',
        action: 'digitaltwin.seed',
        resourceType: 'digital_twin',
        details: { message: 'Initialized Digital Twin graph structure' },
      });
    });
  }

  /**
   * Retrieves the full graph of nodes and edges
   */
  static async getGraph(tenantId: string) {
    await this.seedGraphIfEmpty(tenantId);
    return withTenantTx(tenantId, async (tx) => {
      const nodes = await tx.digitalTwinNode.findMany({ where: { tenantId } });
      const edges = await tx.digitalTwinEdge.findMany({ where: { tenantId } });
      return { nodes, edges };
    });
  }

  /**
   * Simulates the blast radius of a compromised node
   */
  static async simulateBlastRadius(tenantId: string, startNodeId: string) {
    await this.seedGraphIfEmpty(tenantId);

    return withTenantTx(tenantId, async (tx) => {
      const nodes = await tx.digitalTwinNode.findMany({ where: { tenantId } });
      const edges = await tx.digitalTwinEdge.findMany({ where: { tenantId } });

      const nodeMap = new Map(nodes.map((n) => [n.id, n]));
      
      const startNode = nodeMap.get(startNodeId);
      if (!startNode) {
        throw new Error('Start node not found in Digital Twin');
      }

      // Breadth-First Search to find compromised nodes & lateral movement paths
      const compromised = new Set<string>();
      const pathQueue: string[][] = [[startNodeId]];
      const lateralPaths: any[] = [];
      const steps = [];

      compromised.add(startNodeId);

      while (pathQueue.length > 0) {
        const currentPath = pathQueue.shift()!;
        const currentNodeId = currentPath[currentPath.length - 1]!;

        // Find outgoing edges
        const outgoing = edges.filter((e) => e.sourceNodeId === currentNodeId);
        // Find incoming edges (lateral movement back-doors)
        const incoming = edges.filter((e) => e.targetNodeId === currentNodeId);

        const neighbors = [
          ...outgoing.map((e) => ({ id: e.targetNodeId, rel: e.type, direction: 'out' })),
          ...incoming.map((e) => ({ id: e.sourceNodeId, rel: e.type, direction: 'in' })),
        ];

        for (const neighbor of neighbors) {
          if (!compromised.has(neighbor.id)) {
            compromised.add(neighbor.id);
            const newPath = [...currentPath, neighbor.id];
            pathQueue.push(newPath);

            const sourceNode = nodeMap.get(currentNodeId);
            const targetNode = nodeMap.get(neighbor.id);

            lateralPaths.push({
              source: sourceNode?.name,
              sourceType: sourceNode?.type,
              target: targetNode?.name,
              targetType: targetNode?.type,
              vector: neighbor.direction === 'out' ? neighbor.rel : `REVERSE_${neighbor.rel}`,
            });
          }
        }
      }

      const compromisedList = Array.from(compromised).map((id) => nodeMap.get(id)!);

      // Risk score calculation based on compromised assets
      let riskScore = 0;
      let containsPII = false;
      let businessImpact = 'LOW';
      const recommendations: string[] = [];

      for (const node of compromisedList) {
        if (node.type === 'DATABASE') {
          riskScore += 40;
          if ((node.properties as any)?.containsPII) containsPII = true;
        } else if (node.type === 'SECRET') {
          riskScore += 25;
        } else if (node.type === 'CICD_PIPELINE') {
          riskScore += 35;
        } else if (node.type === 'APPLICATION') {
          riskScore += 20;
        } else {
          riskScore += 10;
        }
      }

      riskScore = Math.min(riskScore, 100);

      if (riskScore >= 80) {
        businessImpact = 'CRITICAL';
        recommendations.push('Immediate credential rotation: Compromise path affects production databases and Tier-1 gateways.');
        recommendations.push('Deploy network isolation policy for compromised containers.');
      } else if (riskScore >= 50) {
        businessImpact = 'HIGH';
        recommendations.push('Trigger secret rotation within 24 hours.');
        recommendations.push('Audit CI/CD pipeline permissions and enable MFA requirement.');
      } else {
        businessImpact = 'MEDIUM';
        recommendations.push('Review access logs and security policy.');
      }

      if (containsPII) {
        businessImpact = 'CRITICAL';
        riskScore = Math.max(riskScore, 90);
        recommendations.push('Compliance Alert: GDPR/HIPAA-regulated PII database is in the compromise path. Revoke all keys immediately.');
      }

      // Save simulation run to database
      const simulation = await tx.blastRadiusSimulation.create({
        data: {
          tenantId,
          startNodeId,
          riskScore,
          compromisedNodes: compromisedList as any,
          lateralPaths: lateralPaths as any,
          businessImpact,
          recommendations: recommendations as any,
        },
      });

      await appendAuditEntry(tx, {
        tenantId,
        actorId: '00000000-0000-0000-0000-000000000000',
        action: 'digitaltwin.simulate',
        resourceType: 'blast_radius_simulation',
        resourceId: simulation.id,
        details: { startNode: startNode.name, riskScore, compromisedCount: compromisedList.length },
      });

      return {
        simulationId: simulation.id,
        startNode: startNode.name,
        startNodeType: startNode.type,
        riskScore,
        businessImpact,
        compromisedNodes: compromisedList,
        lateralPaths,
        recommendations,
      };
    });
  }
}
