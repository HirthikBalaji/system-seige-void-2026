import React, { useState } from 'react';
import { Eye, Shield, GitMerge, RefreshCw, Cpu, Award } from 'lucide-react';

interface FederatedIntelligenceTabProps {
  rules: any[];
  onRefresh: () => void;
}

export default function FederatedIntelligenceTab({ rules, onRefresh }: FederatedIntelligenceTabProps) {
  const [aggregating, setAggregating] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAggregate = async () => {
    setAggregating(true);
    setSuccess(null);
    setError(null);
    try {
      const res = await fetch('/api/cyber?action=federated-aggregate', {
        method: 'POST',
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to aggregate federated intelligence models');
      }

      const result = await res.json();
      setSuccess(`Federated model aggregated! Extract local pattern successfully. Distributed ${result.rulesCount} global intelligence rules.`);
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAggregating(false);
    }
  };

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '2rem', alignItems: 'start' }}>
      {/* Federated Learning Info Card */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cpu size={20} color="var(--accent-cyan)" />
          Federated Leak Intelligence (AI)
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: '1.6', marginBottom: '1.2rem' }}>
          SovereignGuard leverages a <strong>privacy-preserving Federated Learning</strong> architecture. Instead of uploading source code, configuration files, or raw keys to a central server:
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'start' }}>
            <div style={{ background: 'rgba(124, 108, 240, 0.15)', padding: '0.4rem', borderRadius: '6px', color: 'var(--accent)' }}>
              <Shield size={16} />
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', display: 'block' }}>1. Local Pattern Extraction</strong>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Each tenant parses local leaks to extract anonymous patterns (e.g. key length, prefix character sets, file shapes, and entropy weights).
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'start' }}>
            <div style={{ background: 'rgba(34, 211, 238, 0.15)', padding: '0.4rem', borderRadius: '6px', color: 'var(--accent-cyan)' }}>
              <GitMerge size={16} />
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', display: 'block' }}>2. Secure Model Aggregation</strong>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Anonymized patterns are combined across all tenants in a cryptographically isolated environment. No raw data ever crosses the tenant boundaries.
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'start' }}>
            <div style={{ background: 'rgba(45, 212, 166, 0.15)', padding: '0.4rem', borderRadius: '6px', color: 'var(--accent-emerald)' }}>
              <Award size={16} />
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', display: 'block' }}>3. Anonymous Rule Distribution</strong>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Aggregated leak patterns generate new detection rules (regex models & advisory rules) which are instantly distributed back to protect all tenants.
              </span>
            </div>
          </div>
        </div>

        {error && <div className="alert alert-error" style={{ marginBottom: '1rem' }}>{error}</div>}
        {success && <div className="alert alert-success" style={{ marginBottom: '1rem' }}>{success}</div>}

        <button
          onClick={handleAggregate}
          className="btn btn-primary"
          style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
          disabled={aggregating}
        >
          {aggregating ? (
            <>
              <RefreshCw size={18} className="spin" /> Aggregating Models...
            </>
          ) : (
            <>
              <RefreshCw size={18} /> Run Model Aggregation
            </>
          )}
        </button>
      </div>

      {/* Rules Distributed Card */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={20} color="var(--accent)" />
          Distributed Intelligence Rules
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          These scan prevention models are generated from aggregated cross-tenant signals. The local AI Exposure Scan Engine uses these rules to run client-side detection.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxHeight: '480px', overflowY: 'auto' }}>
          {rules.length === 0 ? (
            <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '2rem' }}>
              No global intelligence rules loaded.
            </p>
          ) : (
            rules.map((rule) => (
              <div
                key={rule.id}
                style={{
                  padding: '1rem',
                  borderRadius: 'var(--r-md)',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>{rule.ruleName}</span>
                  <span className={`badge ${rule.severity === 'CRITICAL' ? 'badge-danger' : 'badge-amber'}`}>
                    {rule.severity}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <div>
                    <strong>Regex Pattern:</strong> <code style={{ fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.2)', padding: '0.1rem 0.3rem', borderRadius: '4px' }}>{rule.pattern}</code>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.4rem', color: 'var(--text-tertiary)' }}>
                    <span>Federated Source Count: {rule.sourceCount} tenants</span>
                    <span>Distributed Model</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
