import React, { useState } from 'react';
import { Network, Play, ShieldAlert, AlertTriangle, AlertCircle, Info, RefreshCw } from 'lucide-react';

interface DigitalTwinTabProps {
  graph: { nodes: any[]; edges: any[] } | null;
  simulations: any[];
  onRefresh: () => void;
}

export default function DigitalTwinTab({ graph, simulations, onRefresh }: DigitalTwinTabProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSimulate = async () => {
    if (!selectedNodeId) return;
    setSimulating(true);
    setError(null);
    setSimResult(null);

    try {
      const res = await fetch('/api/cyber?action=digitaltwin-simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ startNodeId: selectedNodeId }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to simulate blast radius');
      }

      const data = await res.json();
      setSimResult(data);
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSimulating(false);
    }
  };

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'USER': return '#3b82f6'; // Blue
      case 'SECRET': return '#f43f5e'; // Rose
      case 'CERTIFICATE': return '#ec4899'; // Pink
      case 'APPLICATION': return '#a855f7'; // Purple
      case 'API': return '#06b6d4'; // Cyan
      case 'DATABASE': return '#10b981'; // Emerald
      case 'K8S_CLUSTER': return '#f59e0b'; // Amber
      case 'CLOUD_RESOURCE': return '#64748b'; // Slate
      case 'CICD_PIPELINE': return '#84cc16'; // Lime
      default: return '#94a3b8';
    }
  };

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '2rem', alignItems: 'start' }}>
      {/* Interactive Topology Graph */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Network size={20} color="var(--accent-cyan)" />
            Digital Twin Topology
          </h3>
          <button onClick={onRefresh} className="btn btn-secondary btn-sm" style={{ padding: '0.4rem 0.6rem' }}>
            <RefreshCw size={14} />
          </button>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Overview of managed assets and structural relationships. Red/Rose nodes denote high-value secrets or credentials.
        </p>

        {/* CSS-Grid visualizer for nodes */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))',
            gap: '1rem',
            background: 'rgba(0,0,0,0.4)',
            padding: '1.5rem',
            borderRadius: 'var(--r-md)',
            border: '1px solid rgba(255,255,255,0.06)',
            minHeight: '320px',
            alignContent: 'center',
          }}
        >
          {nodes.length === 0 ? (
            <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', gridColumn: '1/-1', textAlign: 'center' }}>
              Seeding digital twin graph...
            </p>
          ) : (
            nodes.map((node) => {
              const borderCol = getNodeColor(node.type);
              const isSelected = selectedNodeId === node.id;
              const isCompromised = simResult?.compromisedNodes?.some((cn: any) => cn.id === node.id);

              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNodeId(node.id)}
                  style={{
                    padding: '0.75rem',
                    borderRadius: '8px',
                    background: isSelected
                      ? 'rgba(124, 108, 240, 0.15)'
                      : isCompromised
                      ? 'rgba(242, 97, 122, 0.15)'
                      : 'rgba(255, 255, 255, 0.03)',
                    border: `1.5px solid ${isSelected ? 'var(--accent)' : isCompromised ? 'var(--accent-red)' : borderCol}`,
                    cursor: 'pointer',
                    textAlign: 'center',
                    transition: 'all 0.2s ease',
                    boxShadow: isCompromised ? '0 0 10px rgba(242, 97, 122, 0.4)' : 'none',
                  }}
                >
                  <div style={{ fontSize: '0.65rem', fontWeight: 800, color: borderCol, marginBottom: '0.25rem' }}>
                    {node.type}
                  </div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, wordBreak: 'break-word', color: 'var(--text-primary)' }}>
                    {node.name}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Simulator Controls */}
        <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <div style={{ flex: 1 }}>
            <select
              className="input"
              value={selectedNodeId}
              onChange={(e) => setSelectedNodeId(e.target.value)}
            >
              <option value="">-- Select Asset Node --</option>
              {nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name} ({n.type})
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={handleSimulate}
            className="btn btn-primary"
            disabled={simulating || !selectedNodeId}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}
          >
            {simulating ? 'Simulating...' : (
              <>
                <Play size={16} /> Run Blast Simulator
              </>
            )}
          </button>
        </div>
      </div>

      {/* Simulator Results & History */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Simulation Output */}
        {simResult && (
          <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)', border: '1px solid rgba(242, 97, 122, 0.3)' }}>
            <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={20} color="var(--accent-red)" />
              Simulation Report: {simResult.startNode}
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.2rem' }}>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Risk Index</span>
                <span style={{ fontSize: '1.8rem', fontWeight: 800, color: simResult.riskScore >= 80 ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                  {simResult.riskScore}/100
                </span>
              </div>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block' }}>Business Impact</span>
                <span style={{ fontSize: '1.2rem', fontWeight: 800, color: simResult.businessImpact === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-amber)', marginTop: '0.4rem', display: 'inline-block' }}>
                  {simResult.businessImpact}
                </span>
              </div>
            </div>

            {/* Compromised Chain */}
            <div style={{ marginBottom: '1.2rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '0.5rem' }}>Compromised Blast Radius ({simResult.compromisedNodes.length} nodes):</h4>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {simResult.compromisedNodes.map((node: any) => (
                  <span key={node.id} className="badge badge-purple" style={{ fontSize: '0.72rem', background: 'rgba(242, 97, 122, 0.1)', color: 'var(--accent-red)', border: '1px solid rgba(242, 97, 122, 0.2)' }}>
                    {node.name}
                  </span>
                ))}
              </div>
            </div>

            {/* Lateral Movement Paths */}
            <div style={{ marginBottom: '1.2rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '0.5rem' }}>Lateral Attack Vectors:</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '180px', overflowY: 'auto' }}>
                {simResult.lateralPaths.map((path: any, idx: number) => (
                  <div key={idx} style={{ fontSize: '0.78rem', display: 'flex', justifyContent: 'space-between', background: 'rgba(0,0,0,0.15)', padding: '0.35rem 0.5rem', borderRadius: '4px' }}>
                    <span>{path.source} <span style={{ color: 'var(--text-tertiary)' }}>({path.sourceType})</span></span>
                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>── {path.vector} ──&gt;</span>
                    <span>{path.target} <span style={{ color: 'var(--text-tertiary)' }}>({path.targetType})</span></span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '0.5rem' }}>Remediation Advisory:</h4>
              <ul style={{ paddingLeft: '1.2rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {simResult.recommendations.map((rec: string, idx: number) => (
                  <li key={idx} style={{ marginBottom: '0.25rem' }}>{rec}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Simulation Run History */}
        <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={20} color="var(--accent)" />
            Simulation Ledger
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '300px', overflowY: 'auto' }}>
            {simulations.length === 0 ? (
              <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '1.5rem' }}>
                No blast simulations recorded.
              </p>
            ) : (
              simulations.map((sim) => (
                <div
                  key={sim.id}
                  style={{
                    padding: '0.75rem',
                    background: 'rgba(255,255,255,0.01)',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,255,255,0.04)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontSize: '0.8rem',
                  }}
                >
                  <div>
                    <strong style={{ display: 'block' }}>Compromise Start: {nodes.find((n) => n.id === sim.startNodeId)?.name || 'Unknown'}</strong>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.72rem' }}>
                      {new Date(sim.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span className="badge badge-purple" style={{ marginRight: '0.5rem' }}>Risk: {sim.riskScore}%</span>
                    <span className={`badge ${sim.businessImpact === 'CRITICAL' ? 'badge-danger' : 'badge-amber'}`}>
                      {sim.businessImpact}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
