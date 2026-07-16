import React, { useState } from 'react';
import { Network, Shield, Trash2, Key, Users, AlertOctagon, HelpCircle } from 'lucide-react';

interface WorkloadIdentityTabProps {
  identities: any[];
  onRefresh: () => void;
}

export default function WorkloadIdentityTab({ identities, onRefresh }: WorkloadIdentityTabProps) {
  const [form, setForm] = useState({ name: '', type: 'KUBERNETES', attestationType: 'K8S_SA', namespace: '', serviceAccount: '', hostIp: '' });
  const [attestForm, setAttestForm] = useState({ workloadId: '', token: '', hostIp: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [issuedCert, setIssuedCert] = useState<any>(null);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    const selector: any = {};
    if (form.type === 'KUBERNETES') {
      selector.namespace = form.namespace || 'default';
      selector.serviceAccount = form.serviceAccount || 'default';
    } else {
      selector.hostIp = form.hostIp || '127.0.0.1';
    }

    try {
      const res = await fetch('/api/cyber?action=workload-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name,
          type: form.type,
          attestationType: form.attestationType,
          selector,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to register workload');
      }

      setSuccess('Workload Identity registered successfully.');
      setForm({ name: '', type: 'KUBERNETES', attestationType: 'K8S_SA', namespace: '', serviceAccount: '', hostIp: '' });
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAttest = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setIssuedCert(null);
    try {
      const res = await fetch('/api/cyber?action=workload-attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workloadId: attestForm.workloadId,
          attestationData: {
            token: attestForm.token || undefined,
            hostIp: attestForm.hostIp || undefined,
          },
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Attestation verification failed');
      }

      const certData = await res.json();
      setIssuedCert(certData);
      setAttestForm({ workloadId: '', token: '', hostIp: '' });
      onRefresh();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (workloadId: string) => {
    if (!confirm('Are you sure you want to revoke this workload identity and all associated certificates?')) return;
    setError(null);
    try {
      const res = await fetch('/api/cyber?action=workload-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workloadId }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to revoke workload');
      }

      onRefresh();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleRevokeCert = async (serialNumber: string) => {
    if (!confirm('Are you sure you want to revoke this certificate?')) return;
    setError(null);
    try {
      const res = await fetch('/api/cyber?action=workload-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serialNumber }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to revoke certificate');
      }

      onRefresh();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '2rem', alignItems: 'start' }}>
      {/* Forms Section */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Register Workload */}
        <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="var(--accent-cyan)" />
            Register Workload Identity
          </h3>
          <form onSubmit={handleRegister}>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Workload Name</label>
              <input
                type="text"
                className="input"
                placeholder="e.g. payment-service"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Deployment Environment</label>
              <select
                className="input"
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value, attestationType: e.target.value === 'KUBERNETES' ? 'K8S_SA' : 'TPM' })}
              >
                <option value="KUBERNETES">Kubernetes Cluster</option>
                <option value="DOCKER">Docker Container</option>
                <option value="MICROSERVICE">Standalone Microservice</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Attestation Mechanism</label>
              <select
                className="input"
                value={form.attestationType}
                onChange={(e) => setForm({ ...form, attestationType: e.target.value })}
              >
                {form.type === 'KUBERNETES' ? (
                  <>
                    <option value="K8S_SA">Kubernetes Service Account JWT</option>
                    <option value="SPIFFE">SPIFFE ID Protocol (mTLS)</option>
                  </>
                ) : (
                  <>
                    <option value="TPM">Trusted Platform Module (TPM v2.0 Key)</option>
                    <option value="SPIFFE">SPIFFE ID Protocol</option>
                  </>
                )}
              </select>
            </div>

            {form.type === 'KUBERNETES' ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Kubernetes Namespace</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="prod"
                    value={form.namespace}
                    onChange={(e) => setForm({ ...form, namespace: e.target.value })}
                  />
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Service Account</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="payment-sa"
                    value={form.serviceAccount}
                    onChange={(e) => setForm({ ...form, serviceAccount: e.target.value })}
                  />
                </div>
              </div>
            ) : (
              <div className="form-group" style={{ marginBottom: '1rem' }}>
                <label className="form-label">Host IP Address Selector</label>
                <input
                  type="text"
                  className="input"
                  placeholder="10.0.12.34"
                  value={form.hostIp}
                  onChange={(e) => setForm({ ...form, hostIp: e.target.value })}
                />
              </div>
            )}

            {success && (
              <div className="alert alert-success" style={{ marginBottom: '1rem' }}>
                {success}
              </div>
            )}

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Registering...' : 'Register Identity'}
            </button>
          </form>
        </div>

        {/* Attest Workload & Get Certificate */}
        <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={20} color="var(--accent)" />
            Attest Workload (Get Short-Lived Cert)
          </h3>
          <form onSubmit={handleAttest}>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label className="form-label">Select Workload</label>
              <select
                className="input"
                value={attestForm.workloadId}
                onChange={(e) => setAttestForm({ ...attestForm, workloadId: e.target.value })}
                required
              >
                <option value="">-- Choose Workload --</option>
                {identities
                  .filter((i) => i.status === 'ACTIVE')
                  .map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.name} ({i.type})
                    </option>
                  ))}
              </select>
            </div>

            {attestForm.workloadId && (
              <>
                {identities.find((i) => i.id === attestForm.workloadId)?.attestationType === 'K8S_SA' ? (
                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label className="form-label">Kubernetes SA Token (JWT)</label>
                    <textarea
                      className="input"
                      style={{ height: '70px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}
                      placeholder="eyJhbGciOiJSUzI1NiIsImtpZCI6..."
                      value={attestForm.token}
                      onChange={(e) => setAttestForm({ ...attestForm, token: e.target.value })}
                      required
                    />
                  </div>
                ) : (
                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label className="form-label">IP Address (Attestation Metadata)</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="10.0.12.34"
                      value={attestForm.hostIp}
                      onChange={(e) => setAttestForm({ ...attestForm, hostIp: e.target.value })}
                      required
                    />
                  </div>
                )}
              </>
            )}

            {error && (
              <div className="alert alert-error" style={{ marginBottom: '1rem' }}>
                {error}
              </div>
            )}

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Verifying Attestation...' : 'Attest & Issue Certificate'}
            </button>
          </form>

          {issuedCert && (
            <div style={{ marginTop: '1.5rem' }}>
              <div className="alert alert-success" style={{ marginBottom: '1rem' }}>
                🎉 Workload Identity Confirmed! Issued 10m short-lived cert.
              </div>
              <div className="form-group">
                <label className="form-label">Issued Certificate PEM</label>
                <textarea
                  className="input"
                  style={{ height: '100px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
                  readOnly
                  value={issuedCert.certificatePem}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Private Key PEM</label>
                <textarea
                  className="input"
                  style={{ height: '100px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
                  readOnly
                  value={issuedCert.privateKeyPem}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Identities Ledger */}
      <div className="card" style={{ padding: '1.5rem', background: 'var(--glass)' }}>
        <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Network size={20} color="var(--accent-cyan)" />
          Workload Registry
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Overview of registered applications and short-lived certificates.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxHeight: '720px', overflowY: 'auto' }}>
          {identities.length === 0 ? (
            <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', textAlign: 'center', padding: '2rem' }}>
              No workload identities registered.
            </p>
          ) : (
            identities.map((id) => (
              <div
                key={id.id}
                style={{
                  padding: '1.2rem',
                  borderRadius: 'var(--r-md)',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: `1px solid ${id.status === 'REVOKED' ? 'rgba(242, 97, 122, 0.15)' : 'rgba(255,255,255,0.06)'}`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '1.05rem' }}>{id.name}</span>
                    <span className="badge badge-purple" style={{ fontSize: '0.65rem' }}>
                      {id.type}
                    </span>
                  </div>
                  <span className={`badge ${id.status === 'REVOKED' ? 'badge-danger' : 'badge-green'}`}>
                    {id.status}
                  </span>
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '1rem' }}>
                  <div>
                    <strong>Attestation:</strong> {id.attestationType}
                  </div>
                  <div>
                    <strong>Selectors:</strong> {JSON.stringify(id.selector)}
                  </div>
                </div>

                {id.certificates && id.certificates.length > 0 && (
                  <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.75rem', marginTop: '0.75rem' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.8rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Key size={14} color="var(--accent)" /> Active Certificates
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {id.certificates.map((cert: any) => (
                        <div
                          key={cert.id}
                          style={{
                            fontSize: '0.75rem',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            background: 'rgba(0,0,0,0.2)',
                            padding: '0.4rem 0.6rem',
                            borderRadius: '4px',
                            border: `1px solid ${cert.status === 'REVOKED' ? 'rgba(242, 97, 122, 0.1)' : 'rgba(255,255,255,0.04)'}`,
                          }}
                        >
                          <div>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                              SN: {cert.serialNumber.slice(0, 8)}...
                            </span>
                            <span style={{ marginLeft: '0.5rem', color: 'var(--text-tertiary)' }}>
                              Expires: {new Date(cert.expiresAt).toLocaleTimeString()}
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span className={`badge ${cert.status === 'REVOKED' ? 'badge-danger' : 'badge-green'}`} style={{ fontSize: '0.6rem' }}>
                              {cert.status}
                            </span>
                            {cert.status === 'ACTIVE' && (
                              <button
                                onClick={() => handleRevokeCert(cert.serialNumber)}
                                className="btn btn-danger btn-sm"
                                style={{ padding: '0.2rem 0.4rem', fontSize: '0.65rem' }}
                              >
                                Revoke
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {id.status === 'ACTIVE' && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
                    <button
                      onClick={() => handleRevoke(id.id)}
                      className="btn btn-danger btn-sm"
                      style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                    >
                      <Trash2 size={12} /> Revoke Workload
                    </button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
