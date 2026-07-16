'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

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
    description: 'Full administrative access for Acme Corp tenant. Can manage secrets, certs, users, and settings.'
  },
  {
    email: 'dev@acme.com',
    name: 'John Doe',
    role: 'DEVELOPER',
    tenant: 'Acme Corp',
    description: 'Developer access for Acme Corp. Can create/view secrets, view certs, but cannot delete or rotate assets.'
  },
  {
    email: 'security@acme.com',
    name: 'Ellen Ripley',
    role: 'SECURITY_ADMIN',
    tenant: 'Acme Corp',
    description: 'Security Admin. Full control over secrets and certificates, access to audit logs, but cannot update user roles.'
  },
  {
    email: 'auditor@acme.com',
    name: 'Marcus Aurelius',
    role: 'AUDITOR',
    tenant: 'Acme Corp',
    description: 'Compliance role. Has access only to view and export immutable audit logs and check chain integrity.'
  },
  {
    email: 'dev@betacorp.com',
    name: 'Alice Smith',
    role: 'DEVELOPER',
    tenant: 'Beta Corp',
    description: 'Developer access for Beta Corp. Used to test strict multi-tenant isolation from Acme Corp assets.'
  },
  {
    email: 'super@sovereignguard.io',
    name: 'Neo Matrix',
    role: 'SUPER_ADMIN',
    tenant: 'Sovereign Provider',
    description: 'Provider-level administrator. Can verify all tenant audit trails and manage across boundaries.'
  }
];

export default function LandingPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isMock, setIsMock] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  
  // Custom sandbox form
  const [customEmail, setCustomEmail] = useState('');
  const [customName, setCustomName] = useState('');
  const [customRole, setCustomRole] = useState('DEVELOPER');
  const [customTenant, setCustomTenant] = useState('Custom Org');

  useEffect(() => {
    // Check if mock mode is active
    setIsMock(process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true');
    
    // Check session status
    fetch('/api/auth/me')
      .then(res => res.json())
      .then(data => {
        if (data.authenticated) {
          setIsLoggedIn(true);
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
        body: JSON.stringify(profile)
      });
      const data = await res.json();
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
      } else {
        alert(data.error || 'Failed to generate sandbox session');
        setSubmitting(false);
      }
    } catch (err: any) {
      alert('Error: ' + err.message);
      setSubmitting(false);
    }
  };

  const handleCloudflareRedirect = () => {
    const teamDomain = process.env.NEXT_PUBLIC_CF_TEAM_DOMAIN || 'hirthikbalaji.cloudflareaccess.com';
    window.location.href = `https://${teamDomain}/cdn-cgi/access/login`;
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', height: '100vh', justifyContent: 'center', alignContent: 'center', alignItems: 'center', backgroundColor: '#09090b' }}>
        <div style={{ textAlign: 'center' }}>
          <svg style={{ width: '48px', height: '48px', animation: 'spin 1s linear infinite', color: '#8b5cf6' }} fill="none" viewBox="0 0 24 24">
            <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p style={{ marginTop: '1rem', color: '#a1a1aa', fontSize: '0.875rem' }}>Verifying Zero Trust Session...</p>
        </div>
        <style dangerouslySetInnerHTML={{__html: `
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}} />
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#09090b', padding: '2rem 1rem' }}>
      <div style={{ maxWidth: '1000px', margin: 'auto', width: '100%' }}>
        
        {/* Header */}
        <header style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <svg style={{ width: '40px', height: '40px', color: '#8b5cf6' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"></path>
            </svg>
            <span style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'Outfit, sans-serif' }}>
              Sovereign<span className="title-gradient">Guard</span>
            </span>
          </div>
          <h1 style={{ fontSize: '2.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>Secrets & Certificate Control Plane</h1>
          <p style={{ color: '#a1a1aa', maxWidth: '600px', margin: 'auto' }}>
            Enterprise-grade cryptographic asset management. Authenticated via Cloudflare Zero Trust with application-level RBAC, dual-protected audit chaining, and AI vulnerability analysis.
          </p>
        </header>

        {/* Auth Content */}
        <div style={{ display: 'grid', gap: '2rem' }}>
          
          {!isMock ? (
            /* Production - Cloudflare Access Required */
            <div className="card" style={{ textAlign: 'center', padding: '3rem 2rem', border: '1px solid #27272a', maxWidth: '500px', margin: 'auto', width: '100%' }}>
              <div style={{ background: 'rgba(6, 182, 212, 0.05)', border: '1px solid rgba(6, 182, 212, 0.2)', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem', color: '#06b6d4', fontSize: '0.875rem' }}>
                <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"></path>
                </svg>
                Cloudflare Access Protected
              </div>
              <h2 style={{ marginBottom: '1rem' }}>Zero Trust Access Control</h2>
              <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '2rem' }}>
                This portal relies on Cloudflare Access authentication. Please sign in via your identity provider gateway to obtain an authorization token.
              </p>
              <button 
                onClick={handleCloudflareRedirect}
                className="btn btn-primary" 
                style={{ width: '100%', padding: '0.75rem' }}
              >
                Sign In with Cloudflare
              </button>
            </div>
          ) : (
            /* Local Development - Sandbox Identities */
            <div>
              <div className="alert alert-info" style={{ marginBottom: '2rem' }}>
                <svg style={{ width: '20px', height: '20px', flexShrink: 0 }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <div>
                  <strong>Developer Sandbox Active:</strong> Cloudflare Access JWT validation is simulated. Select a pre-configured profile below to log in immediately and test the application's multi-tenant isolation and role-based permissions.
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '2rem' }}>
                
                {/* Profile Grid */}
                <div>
                  <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <svg style={{ width: '20px', height: '20px', color: '#8b5cf6' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z"></path>
                    </svg>
                    Select a Sandbox Identity
                  </h3>
                  
                  <div className="grid-2">
                    {SANDBOX_PROFILES.map((profile) => (
                      <div 
                        key={profile.email} 
                        className="card card-glow" 
                        style={{ cursor: 'pointer', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', border: '1px solid #27272a' }}
                        onClick={() => !submitting && handleLogin({
                          email: profile.email,
                          name: profile.name,
                          role: profile.role,
                          tenant: profile.tenant
                        })}
                      >
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <span style={{ fontWeight: 600, fontSize: '1rem' }}>{profile.name}</span>
                            <span className="badge badge-cyan">{profile.tenant}</span>
                          </div>
                          <div style={{ color: '#a1a1aa', fontSize: '0.75rem', fontFamily: 'monospace', marginBottom: '0.75rem' }}>
                            {profile.email}
                          </div>
                          <p style={{ color: '#71717a', fontSize: '0.8125rem', marginBottom: '1rem' }}>
                            {profile.description}
                          </p>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid #1f1f23' }}>
                          <span className={`badge ${
                            profile.role.includes('ADMIN') ? 'badge-purple' : 
                            profile.role === 'AUDITOR' ? 'badge-amber' : 'badge-green'
                          }`}>
                            {profile.role}
                          </span>
                          <span style={{ fontSize: '0.75rem', color: '#8b5cf6', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            Sign In
                            <svg style={{ width: '12px', height: '12px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"></path>
                            </svg>
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Custom Profile Form */}
                <div className="card" style={{ border: '1px solid #27272a', marginTop: '1rem' }}>
                  <h3 style={{ marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <svg style={{ width: '20px', height: '20px', color: '#06b6d4' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.43l-1.003.828c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.43l1.004-.827c.292-.24.437-.613.43-.991a6.936 6.936 0 010-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28z"></path>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    </svg>
                    Custom Identity Generator
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Full Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. Tony Stark" 
                        value={customName}
                        onChange={e => setCustomName(e.target.value)}
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Email Address</label>
                      <input 
                        type="email" 
                        className="input" 
                        placeholder="e.g. tony@stark.com" 
                        value={customEmail}
                        onChange={e => setCustomEmail(e.target.value)}
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Tenant Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. Stark Industries" 
                        value={customTenant}
                        onChange={e => setCustomTenant(e.target.value)}
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">RBAC Role</label>
                      <select 
                        className="select"
                        value={customRole}
                        onChange={e => setCustomRole(e.target.value)}
                      >
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
                    onClick={() => handleLogin({
                      email: customEmail || 'custom@org.com',
                      name: customName || 'Custom User',
                      role: customRole,
                      tenant: customTenant || 'Custom Tenant'
                    })}
                    disabled={submitting}
                    className="btn btn-secondary"
                    style={{ width: '100%' }}
                  >
                    Generate & Inject Custom Sandbox JWT
                  </button>
                </div>

              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <footer style={{ marginTop: '5rem', borderTop: '1px solid #1f1f23', paddingTop: '1.5rem', textAlign: 'center', color: '#71717a', fontSize: '0.75rem' }}>
          SovereignGuard &copy; {new Date().getFullYear()} &bull; Security Compliance Verified
        </footer>
      </div>
    </div>
  );
}
