import React, { useState } from 'react';
import { Shield, Clock, Eye, EyeOff, Lock, AlertTriangle, CheckCircle } from 'lucide-react';

interface TimelockSecretsTabProps {
  secrets: any[];
  onRefresh: () => void;
}

export default function TimelockSecretsTab({ secrets, onRefresh }: TimelockSecretsTabProps) {
  const [form, setForm] = useState({ name: '', value: '', expiresAt: '', provider: 'ephemeral' as 'ephemeral' | 'vdf' });
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [decryptingId, setDecryptingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await fetch('/api/cyber?action=timelock-create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name,
          value: form.value,
          expiresAt: new Date(form.expiresAt).toISOString(),
          provider: form.provider,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to create time-locked secret');
      }

      setSuccess('Cryptographic time-lock secret successfully provisioned.');
      setForm({ name: '', value: '', expiresAt: '', provider: 'ephemeral' });
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReveal = async (id: string) => {
    if (revealed[id]) {
      setRevealed((prev) => {
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
      return;
    }

    setDecryptingId(id);
    setError(null);
    try {
      const res = await fetch('/api/cyber?action=timelock-decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to decrypt secret');
      }

      const data = await res.json();
      setRevealed((prev) => ({ ...prev, [id]: data.value }));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDecryptingId(null);
    }
  };

  const isExpired = (expiresAtStr: string) => {
    return new Date() > new Date(expiresAtStr);
  };

  return (
    <div className="fade-in">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', alignItems: 'start' }}>
        {/* Creation Form */}
        <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="var(--accent-cyan)" />
            Provision Time-Locked Secret
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
            Encrypt credentials using a cryptographic time-lock. The keys will be automatically purged upon expiration, rendering data permanently unrecoverable.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Secret Name</label>
              <input
                type="text"
                className="input"
                placeholder="e.g. STRIPE_API_PROD"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Plaintext Value</label>
              <textarea
                className="input"
                style={{ height: '80px', resize: 'vertical' }}
                placeholder="Enter sensitive key material"
                value={form.value}
                onChange={(e) => setForm({ ...form, value: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Purge / Expiration Time (UTC)</label>
              <input
                type="datetime-local"
                className="input"
                value={form.expiresAt}
                onChange={(e) => setForm({ ...form, expiresAt: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: '1.5rem' }}>
              <label className="form-label">Cryptographic Provider</label>
              <select
                className="input"
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value as any })}
              >
                <option value="ephemeral">Ephemeral Key Custody (Purges keys on expiry)</option>
                <option value="vdf">VDF Time-Lock Puzzle (Simulates work-delay puzzle)</option>
              </select>
            </div>

            {error && (
              <div className="alert alert-error" style={{ marginBottom: '1rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <AlertTriangle size={16} />
                <span>{error}</span>
              </div>
            )}

            {success && (
              <div className="alert alert-success" style={{ marginBottom: '1rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <CheckCircle size={16} />
                <span>{success}</span>
              </div>
            )}

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Encrypting...' : 'Provision Cryptographic Lock'}
            </button>
          </form>
        </div>

        {/* Secrets List */}
        <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={20} color="var(--accent)" />
            Cryptographic Lock Ledger
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
            Cryptographically bounded secrets. Check access or view expired states below.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxHeight: '420px', overflowY: 'auto' }}>
            {secrets.length === 0 ? (
              <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '2rem' }}>
                No time-locked secrets registered on the ledger.
              </p>
            ) : (
              secrets.map((s) => {
                const expired = isExpired(s.expiresAt);
                const metadata = s.timeLockMetadata || {};

                return (
                  <div
                    key={s.id}
                    style={{
                      padding: '1rem',
                      borderRadius: 'var(--r-md)',
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: `1px solid ${expired ? 'rgba(242, 97, 122, 0.2)' : 'rgba(124, 108, 240, 0.15)'}`,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600 }}>{s.name}</span>
                      <span
                        className={`badge ${expired ? 'badge-danger' : 'badge-green'}`}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.2rem 0.5rem', borderRadius: '4px' }}
                      >
                        {expired ? <Lock size={12} /> : <Clock size={12} />}
                        {expired ? 'EXPIRED' : 'ACTIVE'}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <div>
                        <strong>Expires:</strong> {new Date(s.expiresAt).toLocaleString()}
                      </div>
                      <div style={{ marginTop: '0.25rem', display: 'flex', gap: '0.5rem' }}>
                        <span className="badge badge-purple" style={{ fontSize: '0.65rem' }}>
                          Provider: {metadata.provider || 'ephemeral'}
                        </span>
                        <span className="badge badge-cyan" style={{ fontSize: '0.65rem' }}>
                          Cipher: {metadata.algorithm || 'aes-256-gcm'}
                        </span>
                      </div>
                    </div>

                    {revealed[s.id] && (
                      <div
                        style={{
                          marginTop: '0.5rem',
                          padding: '0.5rem',
                          background: 'rgba(0,0,0,0.3)',
                          borderRadius: '4px',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.85rem',
                          wordBreak: 'break-all',
                          color: 'var(--accent-emerald)',
                          border: '1px solid rgba(45, 212, 166, 0.2)',
                        }}
                      >
                        {revealed[s.id]}
                      </div>
                    )}

                    <div style={{ marginTop: '0.5rem', display: 'flex', justifyContent: 'flex-end' }}>
                      <button
                        onClick={() => handleReveal(s.id)}
                        className={`btn btn-sm ${expired ? 'btn-danger' : revealed[s.id] ? 'btn-secondary' : 'btn-primary'}`}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.35rem 0.75rem' }}
                        disabled={decryptingId === s.id}
                      >
                        {decryptingId === s.id ? (
                          'Decrypting...'
                        ) : revealed[s.id] ? (
                          <>
                            <EyeOff size={14} /> Hide
                          </>
                        ) : (
                          <>
                            <Eye size={14} /> {expired ? 'Purged (Verify)' : 'Decrypt'}
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
