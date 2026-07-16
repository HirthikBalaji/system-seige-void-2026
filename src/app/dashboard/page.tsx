'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldCheck,
  KeyRound,
  Code2,
  ShieldAlert,
  Eye,
  Globe2,
  FileCheck2,
  ScanLine,
  Link2,
  Users,
  LogOut,
  Lock,
  LockOpen,
  RefreshCw,
  Trash2,
  RotateCw,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Radar,
  Building2,
  KeySquare,
  Info,
} from 'lucide-react';
import { encryptWithPublicKeyPem } from '@/lib/browserCrypto';

type Tab = 'secrets' | 'certs' | 'scanner' | 'audit' | 'users';

interface UserContext {
  id: string;
  name: string;
  email: string;
  role: string;
  status: string;
  tenant: { id: string; name: string };
  permissions: string[];
}

interface SecretRow {
  id: string;
  name: string;
  value: string;
  version: number;
  updatedAt: string;
}

interface CertRow {
  id: string;
  name: string;
  domain: string;
  issuedAt: string;
  expiresAt: string;
  status: string;
  autoRenew: boolean;
}

interface AuditRow {
  id: string;
  timestamp: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  details: string;
  prevHash: string;
  entryHash: string;
}

interface ChainResult {
  valid: boolean;
  totalRecords?: number;
  errors: Array<{ id: string; index: number; error: string }>;
}

interface ScanFinding {
  type: string;
  risk: 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: string;
  line: number;
  remediation: string;
}

interface ScanResult {
  safe: boolean;
  findings: ScanFinding[];
  summary: string;
  isMocked: boolean;
  modelUsed: string;
  usedOwnKey: boolean;
}

interface Member {
  id: string;
  name: string;
  email: string;
  role: string;
  status: string;
  lastLogin: string;
}

const ROLE_ICON: Record<string, typeof KeyRound> = {
  ORG_ADMIN: KeyRound,
  DEVELOPER: Code2,
  SECURITY_ADMIN: ShieldAlert,
  AUDITOR: Eye,
  SUPER_ADMIN: Globe2,
};

function RoleIcon({ role, size = 14 }: { role: string; size?: number }) {
  const Icon = ROLE_ICON[role] ?? Building2;
  return <Icon size={size} strokeWidth={2} />;
}

function actionIcon(action: string) {
  const a = action.toLowerCase();
  if (a.includes('read')) return <Eye size={16} />;
  if (a.includes('rotate') || a.includes('update')) return <RefreshCw size={16} />;
  if (a.includes('delete')) return <Trash2 size={16} />;
  if (a.includes('renew')) return <RotateCw size={16} />;
  if (a.startsWith('secret')) return <KeyRound size={16} />;
  if (a.startsWith('cert')) return <FileCheck2 size={16} />;
  if (a.startsWith('scanner')) return <ScanLine size={16} />;
  return <Link2 size={16} />;
}

const SCRAMBLE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*';

/** Decrypt reveal effect — scrambles through random characters before settling on the real value. */
function DecryptText({ text }: { text: string }) {
  const [display, setDisplay] = useState(text);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplay(text);
      return;
    }
    let frame = 0;
    const totalFrames = 9;
    const id = setInterval(() => {
      frame += 1;
      const revealCount = Math.floor((frame / totalFrames) * text.length);
      setDisplay(
        text
          .split('')
          .map((c, i) => (i < revealCount ? c : SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)]))
          .join(''),
      );
      if (frame >= totalFrames) {
        setDisplay(text);
        clearInterval(id);
      }
    }, 35);
    return () => clearInterval(id);
  }, [text]);

  return <span className="vault-value">{display}</span>;
}

function ExpiryRing({ issuedAt, expiresAt }: { issuedAt: string; expiresAt: string }) {
  const issued = new Date(issuedAt).getTime();
  const expires = new Date(expiresAt).getTime();
  const now = Date.now();
  const total = Math.max(expires - issued, 1);
  const elapsed = Math.min(Math.max(now - issued, 0), total);
  const pct = elapsed / total;
  const daysLeft = Math.ceil((expires - now) / 86400000);
  const isExpired = daysLeft <= 0;
  const isExpiringSoon = daysLeft > 0 && daysLeft <= 30;
  const color = isExpired ? 'var(--accent-red)' : isExpiringSoon ? 'var(--accent-amber)' : 'var(--accent-emerald)';
  const r = 21;
  const c = 2 * Math.PI * r;

  return (
    <div style={{ position: 'relative', width: 54, height: 54, flexShrink: 0 }}>
      <svg width="54" height="54" viewBox="0 0 54 54">
        <circle cx="27" cy="27" r={r} fill="none" stroke="var(--glass-border)" strokeWidth="4" />
        <circle
          cx="27"
          cy="27"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - pct)}
          transform="rotate(-90 27 27)"
          style={{ transition: 'stroke-dashoffset 700ms var(--ease-out)' }}
        />
      </svg>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '0.6rem',
          fontWeight: 700,
          color,
        }}
      >
        {isExpired ? '0d' : `${daysLeft}d`}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('secrets');
  const [userContext, setUserContext] = useState<UserContext | null>(null);
  const [loading, setLoading] = useState(true);

  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [certs, setCerts] = useState<CertRow[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditRow[]>([]);
  const [teamMembers, setTeamMembers] = useState<Member[]>([]);
  const [tabError, setTabError] = useState<string | null>(null);

  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({});
  const [chainValidationResult, setChainValidationResult] = useState<ChainResult | null>(null);
  const [validatingChain, setValidatingChain] = useState(false);
  const [verifyRunId, setVerifyRunId] = useState(0);

  const [scanText, setScanText] = useState('');
  const [scanFilename, setScanFilename] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [ownApiKey, setOwnApiKey] = useState('');
  const [showOwnKeyInput, setShowOwnKeyInput] = useState(false);

  const [secretForm, setSecretForm] = useState({ name: '', value: '' });
  const [certForm, setCertForm] = useState({ name: '', domain: '', data: '', expiresAt: '' });
  const [userForm, setUserForm] = useState({ email: '', name: '', role: 'DEVELOPER' });

  const [isSandbox, setIsSandbox] = useState(false);

  useEffect(() => {
    setIsSandbox(process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true');
    fetchUserContext();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (userContext) fetchTabData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, userContext]);

  const fetchUserContext = async () => {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      if (data.authenticated) {
        setUserContext(data.user);
        setLoading(false);
      } else {
        router.push('/');
      }
    } catch {
      router.push('/');
    }
  };

  const fetchTabData = async () => {
    setTabError(null);
    try {
      if (activeTab === 'secrets') {
        const res = await fetch('/api/secrets');
        if (!res.ok) {
          const err = await res.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setSecrets([]);
          return;
        }
        const data = await res.json();
        setSecrets(Array.isArray(data) ? data : []);
      } else if (activeTab === 'certs') {
        const res = await fetch('/api/certificates');
        if (!res.ok) {
          const err = await res.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setCerts([]);
          return;
        }
        const data = await res.json();
        setCerts(Array.isArray(data) ? data : []);
      } else if (activeTab === 'audit') {
        const res = await fetch('/api/audit-logs');
        if (!res.ok) {
          const err = await res.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setAuditLogs([]);
          return;
        }
        const data = await res.json();
        setAuditLogs(Array.isArray(data) ? data : []);
        setChainValidationResult(null);
        setVerifyRunId(0);
      } else if (activeTab === 'users') {
        const res = await fetch('/api/users');
        if (!res.ok) {
          const err = await res.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setTeamMembers([]);
          return;
        }
        const data = await res.json();
        setTeamMembers(Array.isArray(data) ? data : []);
      }
    } catch (err: unknown) {
      console.error('Failed to fetch tab data:', err);
      setTabError(err instanceof Error ? err.message : 'An unexpected error occurred');
    }
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/');
  };

  const switchSandboxPersona = async (email: string, role: string, tenant: string, name: string) => {
    try {
      const res = await fetch('/api/dev/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role, tenant, name }),
      });
      const data = await res.json();
      if (data.redirectUrl) {
        setRevealedSecrets({});
        window.location.href = data.redirectUrl;
      }
    } catch (err) {
      alert('Error switching sandbox persona: ' + err);
    }
  };

  const can = (permission: string) => userContext?.permissions?.includes(permission) ?? false;

  const handleRevealSecret = async (id: string) => {
    if (revealedSecrets[id]) {
      const updated = { ...revealedSecrets };
      delete updated[id];
      setRevealedSecrets(updated);
      return;
    }
    try {
      const res = await fetch(`/api/secrets?id=${id}&reveal=true`);
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      const data = await res.json();
      setRevealedSecrets({ ...revealedSecrets, [id]: data.value });
    } catch (err: unknown) {
      alert('Failed to decrypt secret: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleCreateSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secretForm.name || !secretForm.value) return;
    try {
      const res = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(secretForm),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setSecretForm({ name: '', value: '' });
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to save secret: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleRotateSecret = async (id: string) => {
    if (!confirm('Are you sure you want to rotate this secret? It will generate a new cryptographically secure random value.')) return;
    try {
      const res = await fetch('/api/secrets', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action: 'rotate' }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      const updatedReveals = { ...revealedSecrets };
      delete updatedReveals[id];
      setRevealedSecrets(updatedReveals);
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to rotate secret: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleDeleteSecret = async (id: string) => {
    if (!confirm('Are you sure you want to permanently delete this secret?')) return;
    try {
      const res = await fetch(`/api/secrets?id=${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to delete secret: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleImportCert = async (e: React.FormEvent) => {
    e.preventDefault();
    const { name, domain, data, expiresAt } = certForm;
    if (!name || !domain || !data || !expiresAt) return;
    try {
      const res = await fetch('/api/certificates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, domain, certificateData: data, expiresAt }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setCertForm({ name: '', domain: '', data: '', expiresAt: '' });
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to import certificate: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleRenewCert = async (id: string) => {
    try {
      const res = await fetch('/api/certificates', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to renew certificate: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleDeleteCert = async (id: string) => {
    if (!confirm('Are you sure you want to delete this certificate?')) return;
    try {
      const res = await fetch(`/api/certificates?id=${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to delete certificate: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleVerifyAuditLogsChain = async () => {
    setValidatingChain(true);
    setChainValidationResult(null);
    try {
      const res = await fetch('/api/audit-logs?verify=true');
      const data = await res.json();
      setChainValidationResult(data);
      setVerifyRunId((v) => v + 1);
    } catch (err: unknown) {
      alert('Failed to verify audit logs chain: ' + (err instanceof Error ? err.message : String(err)));
    } finally {
      setValidatingChain(false);
    }
  };

  const handleAiScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanText) return;
    setScanning(true);
    setScanResult(null);
    try {
      let encryptedApiKey: string | undefined;
      if (ownApiKey.trim()) {
        // Fetch the gateway's public key fresh each time and encrypt
        // client-side — the plaintext key never leaves the browser.
        const keyRes = await fetch('/api/scan/key');
        if (keyRes.ok) {
          const { publicKey } = await keyRes.json();
          encryptedApiKey = await encryptWithPublicKeyPem(publicKey, ownApiKey.trim());
        } else {
          alert('Could not fetch the encryption key — falling back to the shared server key for this scan.');
        }
      }

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: scanText, filename: scanFilename || 'unnamed_source.txt', encryptedApiKey }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Scan failed: ${err.error}`);
        return;
      }
      const data = await res.json();
      setScanResult(data);
    } catch (err: unknown) {
      alert('Scan error: ' + (err instanceof Error ? err.message : String(err)));
    } finally {
      setScanning(false);
    }
  };

  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.email || !userForm.role) return;
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userForm),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setUserForm({ email: '', name: '', role: 'DEVELOPER' });
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to invite user: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleUpdateUserRole = async (userId: string, newRole: string) => {
    try {
      const res = await fetch('/api/users', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: userId, role: newRole }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to update user role: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  const handleRemoveUser = async (userId: string) => {
    if (!confirm('Are you sure you want to remove this user from the organization?')) return;
    try {
      const res = await fetch(`/api/users?id=${userId}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: unknown) {
      alert('Failed to remove user: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  if (loading || !userContext) {
    return (
      <div style={{ display: 'flex', height: '100dvh', justifyContent: 'center', alignItems: 'center', gap: '0.75rem', color: 'var(--text-secondary)' }}>
        <Loader2 className="spin" size={20} />
        Authenticating Secure Session…
      </div>
    );
  }

  const NAV: Array<{ id: Tab; label: string; icon: typeof KeyRound }> = [
    { id: 'secrets', label: 'Secrets Manager', icon: KeyRound },
    { id: 'certs', label: 'TLS Certificates', icon: FileCheck2 },
    { id: 'scanner', label: 'AI Secret Scanner', icon: ScanLine },
    { id: 'audit', label: 'Audit Trail', icon: Link2 },
    { id: 'users', label: 'User Roles (RBAC)', icon: Users },
  ];

  const TAB_TITLES: Record<Tab, string> = {
    secrets: 'Secrets & Cryptographic Keys',
    certs: 'TLS Certificate Lifecycles',
    scanner: 'AI Exposure Scan Engine',
    audit: 'Cryptographic Immutable Audit Trail',
    users: 'Team Identities & Access Controls',
  };

  return (
    <div className="dashboard-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="brand-mark">
            <ShieldCheck size={20} color="#fff" />
          </span>
          <span style={{ fontSize: '1.15rem', fontWeight: 800 }}>
            Sovereign<span className="title-gradient">Guard</span>
          </span>
        </div>

        <ul className="sidebar-menu">
          {NAV.map(({ id, label, icon: Icon }) => (
            <li key={id}>
              <div className={`sidebar-link ${activeTab === id ? 'active' : ''}`} onClick={() => setActiveTab(id)}>
                <Icon size={18} strokeWidth={1.75} />
                {label}
              </div>
            </li>
          ))}
        </ul>

        {isSandbox && (
          <div className="dev-sandbox-widget">
            <div className="dev-sandbox-title">
              <span>Sandbox Controls</span>
              <span className="badge badge-purple" style={{ fontSize: '0.6rem' }}>Mock Auth</span>
            </div>
            <p style={{ color: 'var(--text-tertiary)', fontSize: '0.72rem', marginBottom: '0.5rem' }}>
              Quick-swap role/tenant context:
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
              <button className="persona-btn" onClick={() => switchSandboxPersona('admin@acme.com', 'ORG_ADMIN', 'Acme Corp', 'Sarah Connor')}>
                <KeyRound /> Acme &bull; Org Admin
              </button>
              <button className="persona-btn" onClick={() => switchSandboxPersona('dev@acme.com', 'DEVELOPER', 'Acme Corp', 'John Doe')}>
                <Code2 /> Acme &bull; Developer
              </button>
              <button className="persona-btn" onClick={() => switchSandboxPersona('security@acme.com', 'SECURITY_ADMIN', 'Acme Corp', 'Ellen Ripley')}>
                <ShieldAlert /> Acme &bull; Security Admin
              </button>
              <button className="persona-btn" onClick={() => switchSandboxPersona('auditor@acme.com', 'AUDITOR', 'Acme Corp', 'Marcus Aurelius')}>
                <Eye /> Acme &bull; Auditor
              </button>
              <button className="persona-btn" onClick={() => switchSandboxPersona('dev@betacorp.com', 'DEVELOPER', 'Beta Corp', 'Alice Smith')}>
                <Building2 /> Beta Corp &bull; Developer
              </button>
              <button className="persona-btn" onClick={() => switchSandboxPersona('super@sovereignguard.io', 'SUPER_ADMIN', 'Sovereign Provider', 'Neo Matrix')}>
                <Globe2 /> Global &bull; Super Admin
              </button>
            </div>
          </div>
        )}

        <div className="sidebar-footer">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8125rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {userContext.name}
            </div>
            <div className="subtle" style={{ fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {userContext.email}
            </div>
            <div style={{ display: 'flex', gap: '0.35rem', marginTop: '0.5rem' }}>
              <span className="badge badge-purple" style={{ fontSize: '0.62rem' }}>
                <RoleIcon role={userContext.role} size={11} />
                {userContext.role}
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.62rem' }}>{userContext.tenant.name}</span>
            </div>
            <button onClick={handleLogout} className="btn btn-danger btn-sm" style={{ marginTop: '0.75rem', width: '100%' }}>
              <LogOut size={13} />
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <div className="container">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', borderBottom: '1px solid var(--glass-border)', paddingBottom: '1.25rem' }}>
            <div>
              <h2 style={{ fontSize: '1.6rem' }}>{TAB_TITLES[activeTab]}</h2>
              <p className="muted" style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>
                Active Organization Scope: <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{userContext.tenant.name}</span>
              </p>
            </div>
            <div className="badge badge-green" style={{ padding: '0.45rem 0.8rem' }}>
              <span className="badge-dot" style={{ animation: 'verify-pulse 2s ease-out infinite' }} />
              Security Guard Active
            </div>
          </div>

          {tabError && (
            <div className="alert alert-error">
              <AlertTriangle size={18} />
              <div><strong>Access Denied:</strong> {tabError}</div>
            </div>
          )}

          {/* SECRETS */}
          {activeTab === 'secrets' && (
            <div className="fade-in">
              {can('secrets:create') ? (
                <form onSubmit={handleCreateSecret} className="card" style={{ marginBottom: '2rem' }}>
                  <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Provision New Cryptographic Secret</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Secret Name</label>
                      <input type="text" className="input" placeholder="e.g. STRIPE_API_KEY" value={secretForm.name} onChange={(e) => setSecretForm({ ...secretForm, name: e.target.value })} required />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Secret Value</label>
                      <input type="text" className="input" placeholder="Paste value to encrypt at rest" value={secretForm.value} onChange={(e) => setSecretForm({ ...secretForm, value: e.target.value })} required />
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary">
                    <Lock size={15} />
                    Encrypt &amp; Store Secret
                  </button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  <ShieldAlert size={18} />
                  Your role (<strong>&nbsp;{userContext.role}&nbsp;</strong>) does not have write/create permissions for Secrets. Displaying read-only view.
                </div>
              )}

              <div className="card">
                <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Active Vault Items</h3>
                {secrets.length === 0 ? (
                  <p className="subtle" style={{ fontSize: '0.875rem' }}>No secrets stored for this organization.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }} className="stagger">
                    {secrets.map((sec) => {
                      const isRevealed = Boolean(revealedSecrets[sec.id]);
                      return (
                        <div
                          key={sec.id}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '1rem',
                            padding: '0.9rem 1.1rem',
                            borderRadius: 'var(--r-md)',
                            background: 'rgba(255,255,255,0.02)',
                            border: '1px solid var(--glass-border)',
                          }}
                        >
                          <div key={isRevealed ? 'open' : 'closed'} className={`vault-lock ${isRevealed ? 'unlocked' : ''}`}>
                            {isRevealed ? <LockOpen size={16} /> : <Lock size={16} />}
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem', flexWrap: 'wrap' }}>
                              <span className="text-mono" style={{ fontWeight: 600, fontSize: '0.875rem' }}>{sec.name}</span>
                              <span className="badge badge-cyan">v{sec.version}</span>
                              <span className="subtle" style={{ fontSize: '0.72rem' }}>{new Date(sec.updatedAt).toLocaleString()}</span>
                            </div>
                            <div style={{ fontSize: '0.8rem', color: isRevealed ? 'var(--accent-emerald)' : 'var(--text-tertiary)' }}>
                              {isRevealed ? <DecryptText text={revealedSecrets[sec.id]} /> : <span className="vault-value">••••••••••••••••</span>}
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                            <button onClick={() => handleRevealSecret(sec.id)} className="btn btn-secondary btn-sm">
                              {isRevealed ? <Lock size={13} /> : <Eye size={13} />}
                              {isRevealed ? 'Hide' : 'Decrypt'}
                            </button>
                            {can('secrets:rotate') && (
                              <button onClick={() => handleRotateSecret(sec.id)} className="btn btn-secondary btn-sm" style={{ color: 'var(--accent-amber)' }}>
                                <RefreshCw size={13} />
                                Rotate
                              </button>
                            )}
                            {can('secrets:delete') && (
                              <button onClick={() => handleDeleteSecret(sec.id)} className="btn btn-danger btn-sm">
                                <Trash2 size={13} />
                                Delete
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* CERTS */}
          {activeTab === 'certs' && (
            <div className="fade-in">
              {can('certs:import') ? (
                <form onSubmit={handleImportCert} className="card" style={{ marginBottom: '2rem' }}>
                  <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Import TLS Certificate</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Friendly Name</label>
                      <input type="text" className="input" placeholder="e.g. Acme Web SSL" value={certForm.name} onChange={(e) => setCertForm({ ...certForm, name: e.target.value })} required />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Domain Name</label>
                      <input type="text" className="input" placeholder="e.g. *.acme.com" value={certForm.domain} onChange={(e) => setCertForm({ ...certForm, domain: e.target.value })} required />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Expiration Date</label>
                      <input type="date" className="input" value={certForm.expiresAt} onChange={(e) => setCertForm({ ...certForm, expiresAt: e.target.value })} required />
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Certificate PEM Data</label>
                    <textarea className="textarea input" style={{ height: '80px', fontSize: '0.75rem' }} placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'} value={certForm.data} onChange={(e) => setCertForm({ ...certForm, data: e.target.value })} required />
                  </div>
                  <button type="submit" className="btn btn-primary">
                    <FileCheck2 size={15} />
                    Import &amp; Register Certificate
                  </button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  <ShieldAlert size={18} />
                  Your role (<strong>&nbsp;{userContext.role}&nbsp;</strong>) does not have import permissions for TLS certificates.
                </div>
              )}

              <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Registered Certificates</h3>
              {certs.length === 0 ? (
                <div className="card"><p className="subtle" style={{ fontSize: '0.875rem' }}>No TLS certificates registered.</p></div>
              ) : (
                <div className="grid-2 stagger">
                  {certs.map((cert) => {
                    const daysLeft = Math.ceil((new Date(cert.expiresAt).getTime() - Date.now()) / 86400000);
                    const isExpired = daysLeft <= 0;
                    const isExpiringSoon = daysLeft > 0 && daysLeft <= 30;
                    const badgeType = isExpired ? 'badge-red' : isExpiringSoon ? 'badge-amber' : 'badge-green';
                    const statusText = isExpired ? 'EXPIRED' : isExpiringSoon ? 'EXPIRING' : 'ACTIVE';
                    return (
                      <div key={cert.id} className="card card-glow" style={{ display: 'flex', gap: '1rem' }}>
                        <ExpiryRing issuedAt={cert.issuedAt} expiresAt={cert.expiresAt} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.3rem' }}>
                            <span style={{ fontWeight: 700 }}>{cert.name}</span>
                            <span className={`badge ${badgeType}`}><span className="badge-dot" />{statusText}</span>
                          </div>
                          <div className="text-mono subtle" style={{ fontSize: '0.78rem', marginBottom: '0.4rem' }}>{cert.domain}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.85rem' }}>
                            Expires {new Date(cert.expiresAt).toLocaleDateString()}
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem' }}>
                            {can('certs:renew') && (
                              <button onClick={() => handleRenewCert(cert.id)} className="btn btn-secondary btn-sm" style={{ color: 'var(--accent-cyan)' }}>
                                <RotateCw size={13} />
                                Auto-Renew
                              </button>
                            )}
                            {can('certs:delete') && (
                              <button onClick={() => handleDeleteCert(cert.id)} className="btn btn-danger btn-sm">
                                <Trash2 size={13} />
                                Remove
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* SCANNER */}
          {activeTab === 'scanner' && (
            <div className="fade-in">
              <div className={`card ${scanning ? 'scan-frame' : ''}`} style={{ marginBottom: '2rem' }}>
                <h3 style={{ marginBottom: '0.5rem', fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Radar size={19} color="var(--accent)" />
                  Scan Code for Secrets &amp; Exposed Credentials
                </h3>
                <p className="muted" style={{ fontSize: '0.875rem', marginBottom: '1.25rem' }}>
                  Analyze source files, environment configs, or scripts for hardcoded secrets, private keys, and API
                  tokens. A deterministic regex/entropy pre-filter finds candidates, then{' '}
                  <span style={{ color: 'var(--accent)', fontWeight: 600 }}>Anthropic Claude</span> classifies each
                  one — only a masked snippet ever leaves this process.
                </p>

                <form onSubmit={handleAiScan}>
                  <div className="form-group">
                    <label className="form-label">Filename Context</label>
                    <input type="text" className="input" placeholder="e.g. src/utils/db.ts" value={scanFilename} onChange={(e) => setScanFilename(e.target.value)} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Code / File Content to Scan</label>
                    <textarea className="textarea input" style={{ height: '200px', fontSize: '0.8125rem' }} placeholder="Paste code or config text here… (e.g. const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE')" value={scanText} onChange={(e) => setScanText(e.target.value)} required />
                  </div>

                  <div style={{ marginBottom: '1.25rem', borderRadius: 'var(--r-md)', border: '1px solid var(--glass-border)', background: 'rgba(255,255,255,0.02)' }}>
                    <button
                      type="button"
                      onClick={() => setShowOwnKeyInput((v) => !v)}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '0.5rem',
                        padding: '0.7rem 0.9rem',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-secondary)',
                        fontSize: '0.82rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <KeySquare size={15} color="var(--accent-cyan)" />
                        Use your own Anthropic API key
                        {ownApiKey.trim() && <span className="badge badge-cyan" style={{ fontSize: '0.62rem' }}>Active</span>}
                      </span>
                      <span style={{ fontSize: '0.72rem' }}>{showOwnKeyInput ? 'Hide' : 'Optional'}</span>
                    </button>
                    {showOwnKeyInput && (
                      <div style={{ padding: '0 0.9rem 0.9rem' }}>
                        <input
                          type="password"
                          autoComplete="off"
                          className="input"
                          placeholder="sk-ant-…"
                          value={ownApiKey}
                          onChange={(e) => setOwnApiKey(e.target.value)}
                          style={{ marginBottom: '0.5rem' }}
                        />
                        <p className="subtle" style={{ fontSize: '0.72rem', display: 'flex', gap: '0.4rem', alignItems: 'flex-start' }}>
                          <Info size={13} style={{ flexShrink: 0, marginTop: '0.15rem' }} />
                          Encrypted in your browser (RSA-OAEP) before it's sent — the server only ever sees ciphertext
                          on the wire, decrypts it in memory for this one scan, and never stores or logs it. Leave
                          blank to use the shared demo key instead.
                        </p>
                      </div>
                    )}
                  </div>

                  <button type="submit" disabled={scanning} className="btn btn-primary">
                    {scanning ? <Loader2 className="spin" size={15} /> : <Radar size={15} />}
                    {scanning ? 'Analyzing Exposures…' : 'Run Security Audit'}
                  </button>
                </form>
              </div>

              {scanResult && (
                <div className="card fade-in">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid var(--glass-border)', paddingBottom: '1rem' }}>
                    <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '1.05rem' }}>
                      Scan Summary
                      <span className={`badge ${scanResult.safe ? 'badge-green' : 'badge-red'}`}>
                        <span className="badge-dot" />
                        {scanResult.safe ? 'COMPLIANT' : 'EXPOSED'}
                      </span>
                    </h3>
                  </div>
                  <p className="muted" style={{ fontSize: '0.8125rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    {scanResult.isMocked
                      ? 'Executed via local regex/entropy pre-filter only — live LLM classification was unavailable for this scan.'
                      : `Classified by ${scanResult.modelUsed || 'Anthropic Claude'} after the deterministic pre-filter stage.`}
                    {scanResult.usedOwnKey && (
                      <span className="badge badge-cyan"><KeySquare size={11} />Your API key</span>
                    )}
                  </p>
                  <p style={{ fontWeight: 500, marginBottom: '1.25rem' }}>{scanResult.summary}</p>

                  {scanResult.findings.length === 0 ? (
                    <div className="alert alert-success" style={{ marginBottom: 0 }}>
                      <CheckCircle2 size={18} />
                      No credentials, private keys, or API tokens were found in the scanned text.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }} className="stagger">
                      {scanResult.findings.map((f, idx) => (
                        <div key={idx} style={{ display: 'flex', gap: '1rem', padding: '0.9rem 1.1rem', borderRadius: 'var(--r-md)', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--glass-border)' }}>
                          <span
                            className={`badge ${f.risk === 'HIGH' ? 'badge-red' : f.risk === 'MEDIUM' ? 'badge-amber' : 'badge-cyan'}`}
                            style={{ height: 'fit-content' }}
                          >
                            <span className="badge-dot" />
                            {f.risk}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.3rem', flexWrap: 'wrap' }}>
                              <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{f.type}</span>
                              <span className="subtle text-mono" style={{ fontSize: '0.72rem' }}>Line {f.line}</span>
                            </div>
                            <code style={{ display: 'inline-block', background: 'rgba(0,0,0,0.3)', padding: '0.15rem 0.5rem', borderRadius: 'var(--r-sm)', color: '#f8cd8d', fontSize: '0.78rem', marginBottom: '0.5rem' }}>
                              {f.evidence}
                            </code>
                            <p className="muted" style={{ fontSize: '0.8rem' }}>{f.remediation}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* AUDIT — visual hash chain */}
          {activeTab === 'audit' && (
            <div className="fade-in">
              <div className="card" style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                <div>
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.05rem' }}>
                    <Link2 size={19} color="var(--accent)" />
                    Hash Chain Verification
                  </h3>
                  <p className="muted" style={{ fontSize: '0.8125rem', marginTop: '0.25rem' }}>
                    Recomputes every entry&apos;s hash from genesis and confirms each link still points to the previous
                    entry&apos;s true hash.
                  </p>
                </div>
                <button onClick={handleVerifyAuditLogsChain} disabled={validatingChain} className="btn btn-primary">
                  {validatingChain ? <Loader2 className="spin" size={15} /> : <ShieldCheck size={15} />}
                  {validatingChain ? 'Validating Chain…' : 'Verify Chain Integrity'}
                </button>
              </div>

              {chainValidationResult && (
                <div className={`alert ${chainValidationResult.valid ? 'alert-success' : 'alert-error'} fade-in`} style={{ flexDirection: 'column', gap: '0.35rem' }}>
                  {chainValidationResult.valid ? (
                    <>
                      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <CheckCircle2 size={18} />
                        Cryptographic Verification Successful
                      </div>
                      <p style={{ fontSize: '0.8125rem' }}>
                        Verified <strong>{chainValidationResult.totalRecords ?? auditLogs.length}</strong> platform-wide
                        entries. Hash linkage is continuous — no tampering detected.
                      </p>
                    </>
                  ) : (
                    <>
                      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <AlertTriangle size={18} />
                        Tampering Detected
                      </div>
                      {chainValidationResult.errors.map((err, idx) => (
                        <p key={idx} className="text-mono" style={{ fontSize: '0.75rem' }}>
                          Broken link at record ID {err.id}: {err.error}
                        </p>
                      ))}
                    </>
                  )}
                </div>
              )}

              <div className="card">
                <h3 style={{ marginBottom: '0.3rem', fontSize: '1.05rem' }}>Ledger Chain</h3>
                <p className="subtle" style={{ fontSize: '0.75rem', marginBottom: '1.5rem' }}>
                  Every block below is cryptographically linked to the one before it — this is the actual chain
                  &quot;Verify Chain Integrity&quot; walks.
                </p>

                {auditLogs.length === 0 ? (
                  <p className="subtle" style={{ fontSize: '0.875rem' }}>No audit entries recorded yet.</p>
                ) : (
                  <div className="chain-track">
                    {auditLogs.map((log, idx) => {
                      const brokenHere = Boolean(
                        chainValidationResult && !chainValidationResult.valid && chainValidationResult.errors?.[0]?.id === log.id,
                      );
                      const verified = Boolean(chainValidationResult?.valid && verifyRunId > 0);
                      const stateClass = brokenHere ? 'invalid' : verified ? 'valid' : '';
                      const shouldPulse = verified || brokenHere;
                      return (
                        <div key={`${log.id}-${verifyRunId}`} className={`chain-node ${stateClass}`}>
                          <div className="chain-line" />
                          <div className={`chain-dot ${shouldPulse ? 'pulse' : ''}`} style={shouldPulse ? { animationDelay: `${idx * 55}ms` } : undefined}>
                            {actionIcon(log.action)}
                          </div>
                          <div className="chain-card">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.35rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                                <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{log.action}</span>
                                {verified && (
                                  <span className="badge badge-green"><span className="badge-dot" />Verified</span>
                                )}
                                {brokenHere && (
                                  <span className="badge badge-red"><span className="badge-dot" />Tampered</span>
                                )}
                              </div>
                              <span className="subtle" style={{ fontSize: '0.72rem' }}>{new Date(log.timestamp).toLocaleString()}</span>
                            </div>
                            <div className="text-mono subtle" style={{ fontSize: '0.75rem', marginBottom: '0.4rem' }}>
                              {log.resourceType}
                              {log.resourceId ? `:${log.resourceId.slice(0, 8)}…` : ''}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', wordBreak: 'break-word' }}>
                              {log.details}
                            </div>
                            <div className="chain-hash">hash {log.entryHash.slice(0, 24)}…</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* USERS */}
          {activeTab === 'users' && (
            <div className="fade-in">
              {can('users:invite') ? (
                <form onSubmit={handleInviteUser} className="card" style={{ marginBottom: '2rem' }}>
                  <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Add User to Organization</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Email Address</label>
                      <input type="email" className="input" placeholder="e.g. engineer@acme.com" value={userForm.email} onChange={(e) => setUserForm({ ...userForm, email: e.target.value })} required />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Full Name</label>
                      <input type="text" className="input" placeholder="e.g. Robert Smith" value={userForm.name} onChange={(e) => setUserForm({ ...userForm, name: e.target.value })} />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Assign Role</label>
                      <select className="select" value={userForm.role} onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}>
                        <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                        <option value="ORG_ADMIN">ORG_ADMIN</option>
                        <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
                        <option value="DEVELOPER">DEVELOPER</option>
                        <option value="AUDITOR">AUDITOR</option>
                        <option value="READ_ONLY">READ_ONLY</option>
                        <option value="SERVICE_ACCOUNT">SERVICE_ACCOUNT</option>
                      </select>
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary">
                    <Users size={15} />
                    Add Member
                  </button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  <ShieldAlert size={18} />
                  Your role (<strong>&nbsp;{userContext.role}&nbsp;</strong>) does not have invite permissions.
                </div>
              )}

              <h3 style={{ marginBottom: '1rem', fontSize: '1.05rem' }}>Organization Membership</h3>
              <div className="grid-2 stagger">
                {teamMembers.map((member) => (
                  <div key={member.id} className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span style={{ width: 40, height: 40, borderRadius: 'var(--r-md)', background: 'var(--glass)', border: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', flexShrink: 0 }}>
                      <RoleIcon role={member.role} size={18} />
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontWeight: 600 }}>{member.name}</span>
                        <span className={`badge ${member.status === 'ACTIVE' ? 'badge-green' : 'badge-red'}`}>
                          <span className="badge-dot" />
                          {member.status}
                        </span>
                      </div>
                      <div className="text-mono subtle" style={{ fontSize: '0.78rem', margin: '0.2rem 0' }}>{member.email}</div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', marginTop: '0.4rem' }}>
                        {can('users:update-role') && member.id !== userContext.id ? (
                          <select className="select" style={{ padding: '0.25rem 0.5rem', width: 'auto', fontSize: '0.75rem' }} value={member.role} onChange={(e) => handleUpdateUserRole(member.id, e.target.value)}>
                            <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                            <option value="ORG_ADMIN">ORG_ADMIN</option>
                            <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
                            <option value="DEVELOPER">DEVELOPER</option>
                            <option value="AUDITOR">AUDITOR</option>
                            <option value="READ_ONLY">READ_ONLY</option>
                            <option value="SERVICE_ACCOUNT">SERVICE_ACCOUNT</option>
                          </select>
                        ) : (
                          <span className="badge badge-purple"><RoleIcon role={member.role} size={11} />{member.role}</span>
                        )}
                        {can('users:remove') && member.id !== userContext.id && (
                          <button onClick={() => handleRemoveUser(member.id)} className="btn btn-danger btn-sm">
                            <Trash2 size={13} />
                          </button>
                        )}
                      </div>
                      <div className="subtle" style={{ fontSize: '0.7rem', marginTop: '0.4rem' }}>
                        Last login {new Date(member.lastLogin).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
