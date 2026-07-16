import React, { useState } from 'react';
import { AlertOctagon, RefreshCw, CheckCircle, Clock, AlertTriangle, Shield, Play } from 'lucide-react';

interface AutonomousRevocationsTabProps {
  revocations: any[];
  onRefresh: () => void;
}

export default function AutonomousRevocationsTab({ revocations, onRefresh }: AutonomousRevocationsTabProps) {
  const [form, setForm] = useState({ provider: 'AWS', value: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    // Provide realistic looking keys if the user doesn't enter any
    let keyVal = form.value.trim();
    if (!keyVal) {
      if (form.provider === 'AWS') keyVal = 'aws-access-key-mock-placeholder-12345';
      else if (form.provider === 'GitHub') keyVal = 'github-token-mock-placeholder-12345';
      else if (form.provider === 'Stripe') keyVal = 'stripe-secret-key-mock-placeholder-12345';
      else if (form.provider === 'Twilio') keyVal = 'twilio-secret-key-mock-placeholder-12345';
      else if (form.provider === 'GCP') keyVal = 'gcp-private-key-mock-placeholder-12345';
      else if (form.provider === 'AZURE') keyVal = 'azure-credential-mock-placeholder-12345';
    }

    try {
      const res = await fetch('/api/cyber?action=revocations-trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: form.provider, value: keyVal }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to trigger autonomous revocation');
      }

      setSuccess('Leaked credential finding simulated. Autonomous Revocation agent has been launched.');
      setForm({ provider: 'AWS', value: '' });
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'var(--accent-emerald)';
      case 'FAILED':
        return 'var(--accent-red)';
      case 'PENDING':
      case 'VALIDATING':
      case 'REVOKING':
      case 'ROTATING':
        return 'var(--accent-amber)';
      default:
        return 'var(--text-secondary)';
    }
  };

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: '2rem', alignItems: 'start' }}>
      {/* Simulation Trigger */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertOctagon size={20} color="var(--accent-red)" />
          Simulate Credential Leak Finding
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Trigger a mock public Git repository leak detection alert. SovereignGuard's Autonomous Agent will intercept the leak, run API checks, revoke the key, deploy replacements, and log the steps.
        </p>

        <form onSubmit={handleSimulate}>
          <div className="form-group" style={{ marginBottom: '1rem' }}>
            <label className="form-label">API Credentials Provider</label>
            <select
              className="input"
              value={form.provider}
              onChange={(e) => setForm({ ...form, provider: e.target.value })}
            >
              <option value="AWS">Amazon Web Services (AWS)</option>
              <option value="GitHub">GitHub Personal Token</option>
              <option value="Stripe">Stripe API Live Key</option>
              <option value="Twilio">Twilio API Key</option>
              <option value="GCP">Google Cloud Platform (SA Key)</option>
              <option value="AZURE">Microsoft Azure App Credential</option>
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: '1.5rem' }}>
            <label className="form-label">Leaked Key Content (Optional - leave empty for mock default)</label>
            <input
              type="text"
              className="input"
              placeholder="e.g. AKIA..."
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
            />
          </div>

          {error && (
            <div className="alert alert-error" style={{ marginBottom: '1rem' }}>
              {error}
            </div>
          )}

          {success && (
            <div className="alert alert-success" style={{ marginBottom: '1rem' }}>
              {success}
            </div>
          )}

          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? (
              <>
                <RefreshCw size={16} className="spin" style={{ marginRight: '0.5rem' }} /> Dispatching Agent...
              </>
            ) : (
              <>
                <Play size={16} style={{ marginRight: '0.5rem' }} /> Trigger Autonomous Agent
              </>
            )}
          </button>
        </form>
      </div>

      {/* Execution Tracker */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="var(--accent-cyan)" />
            Autonomous Remediation Ledger
          </h3>
          <button onClick={onRefresh} className="btn btn-secondary btn-sm" style={{ padding: '0.4rem 0.6rem' }}>
            <RefreshCw size={14} />
          </button>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Real-time logs showing agent decisions, verification checks, revocations, and rollback plans.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxHeight: '720px', overflowY: 'auto' }}>
          {revocations.length === 0 ? (
            <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '2rem' }}>
              No active or completed remediation runs in this workspace.
            </p>
          ) : (
            revocations.map((run) => {
              const steps = run.executedActions || [];
              const isCompleted = run.status === 'COMPLETED';
              const isFailed = run.status === 'FAILED';

              return (
                <div
                  key={run.id}
                  style={{
                    padding: '1.2rem',
                    borderRadius: 'var(--r-md)',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '1rem' }}>{run.provider} Leak Run</span>
                      <span className="badge badge-purple" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>
                        ID: {run.id.slice(0, 8)}
                      </span>
                    </div>
                    <span
                      style={{
                        fontWeight: 600,
                        color: getStatusColor(run.status),
                        fontSize: '0.85rem',
                      }}
                    >
                      {run.status}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                    <strong>Leaked Token Hash:</strong> {run.credentialIdentifier}
                  </div>

                  {/* Step Checklist */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
                    {steps.map((step: any, idx: number) => {
                      const stepFailed = step.status === 'FAILED';
                      const stepActive = ['VALIDATING', 'REVOKING', 'ROTATING', 'REPLACING'].includes(step.status);

                      return (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            gap: '0.75rem',
                            alignItems: 'start',
                            fontSize: '0.85rem',
                          }}
                        >
                          <div style={{ marginTop: '0.15rem' }}>
                            {stepFailed ? (
                              <AlertTriangle size={14} color="var(--accent-red)" />
                            ) : stepActive ? (
                              <RefreshCw size={14} className="spin" color="var(--accent-amber)" />
                            ) : (
                              <CheckCircle size={14} color="var(--accent-emerald)" />
                            )}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                              <span>{step.name}</span>
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>
                                {new Date(step.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.1rem' }}>
                              {step.details?.message || JSON.stringify(step.details || {})}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {run.rollbackPlan && (
                    <div
                      style={{
                        marginTop: '1.2rem',
                        padding: '0.75rem',
                        background: 'rgba(0,0,0,0.2)',
                        borderRadius: '6px',
                        border: '1px solid rgba(255,255,255,0.04)',
                        fontSize: '0.78rem',
                      }}
                    >
                      <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '0.25rem' }}>
                        Rollback Strategy
                      </strong>
                      <p style={{ color: 'var(--text-secondary)' }}>{run.rollbackPlan}</p>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
