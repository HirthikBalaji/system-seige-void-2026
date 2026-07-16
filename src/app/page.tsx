'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldCheck,
  KeyRound,
  Code2,
  ShieldAlert,
  Eye,
  Building2,
  Globe2,
  ArrowRight,
  Sparkles,
  Loader2,
  Lock,
} from 'lucide-react';

interface SandboxProfile {
  email: string;
  name: string;
  role: string;
  tenant: string;
  description: string;
}

const SANDBOX_PROFILES: SandboxProfile[] = [
  {
    email: 'admin@acme.com',
    name: 'Sarah Connor',
    role: 'ORG_ADMIN',
    tenant: 'Acme Corp',
    description: 'Full administrative access for Acme Corp tenant. Can manage secrets, certs, users, and settings.',
  },
  {
    email: 'dev@acme.com',
    name: 'John Doe',
    role: 'DEVELOPER',
    tenant: 'Acme Corp',
    description: 'Developer access for Acme Corp. Can create/view secrets, view certs, but cannot delete or rotate assets.',
  },
  {
    email: 'security@acme.com',
    name: 'Ellen Ripley',
    role: 'SECURITY_ADMIN',
    tenant: 'Acme Corp',
    description: 'Security Admin. Full control over secrets and certificates, access to audit logs, but cannot update user roles.',
  },
  {
    email: 'auditor@acme.com',
    name: 'Marcus Aurelius',
    role: 'AUDITOR',
    tenant: 'Acme Corp',
    description: 'Compliance role. Has access only to view and export immutable audit logs and check chain integrity.',
  },
  {
    email: 'dev@betacorp.com',
    name: 'Alice Smith',
    role: 'DEVELOPER',
    tenant: 'Beta Corp',
    description: 'Developer access for Beta Corp. Used to test strict multi-tenant isolation from Acme Corp assets.',
  },
  {
    email: 'super@sovereignguard.io',
    name: 'Neo Matrix',
    role: 'SUPER_ADMIN',
    tenant: 'Sovereign Provider',
    description: 'Provider-level administrator. Can verify all tenant audit trails and manage across boundaries.',
  },
];

const ROLE_ICON: Record<string, typeof KeyRound> = {
  ORG_ADMIN: KeyRound,
  DEVELOPER: Code2,
  SECURITY_ADMIN: ShieldAlert,
  AUDITOR: Eye,
  SUPER_ADMIN: Globe2,
};

const ROLE_BADGE: Record<string, string> = {
  ORG_ADMIN: 'badge-purple',
  SECURITY_ADMIN: 'badge-purple',
  SUPER_ADMIN: 'badge-purple',
  AUDITOR: 'badge-amber',
  DEVELOPER: 'badge-green',
};

function roleIcon(role: string, size = 20) {
  const Icon = ROLE_ICON[role] ?? Building2;
  return <Icon size={size} strokeWidth={1.75} />;
}

export default function LandingPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [isMock, setIsMock] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [customEmail, setCustomEmail] = useState('');
  const [customName, setCustomName] = useState('');
  const [customRole, setCustomRole] = useState('DEVELOPER');
  const [customTenant, setCustomTenant] = useState('Custom Org');

  useEffect(() => {
    setIsMock(process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true');

    fetch('/api/auth/me')
      .then((res) => res.json())
      .then((data) => {
        if (data.authenticated) {
          router.push('/dashboard');
        } else {
          setLoading(false);
        }
      })
      .catch(() => {
        setLoading(false);
      });
  }, [router]);

  const handleLogin = async (profile: Omit<SandboxProfile, 'description'>) => {
    setSubmitting(true);
    try {
      const res = await fetch('/api/dev/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(profile),
      });
      const data = await res.json();
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
      } else {
        alert(data.error || 'Failed to generate sandbox session');
        setSubmitting(false);
      }
    } catch (err: unknown) {
      alert('Error: ' + (err instanceof Error ? err.message : String(err)));
      setSubmitting(false);
    }
  };

  const handleCloudflareRedirect = () => {
    const teamDomain = process.env.NEXT_PUBLIC_CF_TEAM_DOMAIN || 'hirthikbalaji.cloudflareaccess.com';
    window.location.href = `https://${teamDomain}/cdn-cgi/access/login`;
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', height: '100dvh', justifyContent: 'center', alignItems: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <Loader2 className="spin" size={40} color="var(--accent)" />
          <p style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Verifying Zero Trust Session…
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100dvh', display: 'flex', flexDirection: 'column', padding: '3rem 1.5rem' }}>
      <div style={{ maxWidth: '1040px', margin: 'auto', width: '100%' }}>
        <header style={{ textAlign: 'center', marginBottom: '3rem' }} className="fade-in">
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.5rem' }}>
            <span className="brand-mark" style={{ width: 48, height: 48 }}>
              <ShieldCheck size={26} color="#fff" strokeWidth={2} />
            </span>
            <span style={{ fontSize: '1.9rem', fontWeight: 800 }}>
              Sovereign<span className="title-gradient">Guard</span>
            </span>
          </div>
          <h1 style={{ fontSize: 'clamp(1.75rem, 4vw, 2.75rem)', marginBottom: '0.75rem' }}>
            Secrets &amp; Certificate Control Plane
          </h1>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '620px', margin: 'auto', fontSize: '0.95rem' }}>
            Enterprise-grade cryptographic asset management — Zero Trust identity, tenant-isolated RBAC,
            hash-chained tamper-evident auditing, and AI-assisted exposure scanning.
          </p>
        </header>

        {!isMock ? (
          <div className="card fade-in" style={{ textAlign: 'center', padding: '3rem 2rem', maxWidth: '480px', margin: 'auto' }}>
            <div className="badge badge-cyan" style={{ marginBottom: '1.5rem' }}>
              <Lock size={13} />
              Cloudflare Access Protected
            </div>
            <h2 style={{ marginBottom: '0.75rem' }}>Zero Trust Access Control</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '2rem' }}>
              This portal relies on Cloudflare Access authentication. Sign in via your identity provider
              gateway to obtain an authorization token.
            </p>
            <button onClick={handleCloudflareRedirect} className="btn btn-primary" style={{ width: '100%', padding: '0.8rem' }}>
              Sign In with Cloudflare
              <ArrowRight size={16} />
            </button>
          </div>
        ) : (
          <div className="fade-in">
            <div className="alert alert-info">
              <ShieldAlert size={20} />
              <div>
                <strong>Developer Sandbox Active:</strong> Cloudflare Access JWT validation is simulated.
                Select a persona below to sign in instantly and explore RBAC + tenant isolation.
              </div>
            </div>

            <div style={{ display: 'grid', gap: '2rem' }}>
              <div>
                <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem' }}>
                  <Sparkles size={18} color="var(--accent)" />
                  Select a Sandbox Identity
                </h3>

                <div className="grid-2 stagger">
                  {SANDBOX_PROFILES.map((profile) => (
                    <div
                      key={profile.email}
                      className="card card-glow card-interactive"
                      style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}
                      onClick={() =>
                        !submitting &&
                        handleLogin({ email: profile.email, name: profile.name, role: profile.role, tenant: profile.tenant })
                      }
                    >
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.6rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <span
                              style={{
                                width: 34,
                                height: 34,
                                borderRadius: 'var(--r-md)',
                                background: 'var(--glass)',
                                border: '1px solid var(--glass-border)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'var(--accent)',
                                flexShrink: 0,
                              }}
                            >
                              {roleIcon(profile.role, 17)}
                            </span>
                            <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{profile.name}</span>
                          </div>
                          <span className="badge badge-cyan">
                            <Building2 size={11} />
                            {profile.tenant}
                          </span>
                        </div>
                        <div className="text-mono subtle" style={{ fontSize: '0.75rem', marginBottom: '0.75rem' }}>
                          {profile.email}
                        </div>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem', marginBottom: '1rem' }}>
                          {profile.description}
                        </p>
                      </div>
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          paddingTop: '0.75rem',
                          borderTop: '1px solid var(--glass-border)',
                        }}
                      >
                        <span className={`badge ${ROLE_BADGE[profile.role] ?? 'badge-purple'}`}>
                          <span className="badge-dot" />
                          {profile.role}
                        </span>
                        <span style={{ fontSize: '0.78rem', color: 'var(--accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          Sign In
                          <ArrowRight size={13} />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card" style={{ marginTop: '0.5rem' }}>
                <h3 style={{ marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem' }}>
                  <KeyRound size={18} color="var(--accent-cyan)" />
                  Custom Identity Generator
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Full Name</label>
                    <input type="text" className="input" placeholder="e.g. Tony Stark" value={customName} onChange={(e) => setCustomName(e.target.value)} />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Email Address</label>
                    <input type="email" className="input" placeholder="e.g. tony@stark.com" value={customEmail} onChange={(e) => setCustomEmail(e.target.value)} />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Tenant Name</label>
                    <input type="text" className="input" placeholder="e.g. Stark Industries" value={customTenant} onChange={(e) => setCustomTenant(e.target.value)} />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">RBAC Role</label>
                    <select className="select" value={customRole} onChange={(e) => setCustomRole(e.target.value)}>
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
                <button
                  onClick={() =>
                    handleLogin({
                      email: customEmail || 'custom@org.com',
                      name: customName || 'Custom User',
                      role: customRole,
                      tenant: customTenant || 'Custom Tenant',
                    })
                  }
                  disabled={submitting}
                  className="btn btn-secondary"
                  style={{ width: '100%' }}
                >
                  {submitting ? <Loader2 className="spin" size={16} /> : <Sparkles size={16} />}
                  Generate &amp; Inject Custom Sandbox JWT
                </button>
              </div>
            </div>
          </div>
        )}

        <footer style={{ marginTop: '4rem', borderTop: '1px solid var(--glass-border)', paddingTop: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>
          SovereignGuard &copy; {new Date().getFullYear()} &bull; Security Compliance Verified
        </footer>
      </div>
    </div>
  );
}
