'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';

type Tab = 'secrets' | 'certs' | 'scanner' | 'audit' | 'users' | 'rotation' | 'sandbox';

export default function Dashboard() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('secrets');
  const [userContext, setUserContext] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Data states
  const [secrets, setSecrets] = useState<any[]>([]);
  const [certs, setCerts] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [teamMembers, setTeamMembers] = useState<any[]>([]);
  const [tabError, setTabError] = useState<string | null>(null);

  // Feature 1: AI Risk-Based Rotation States
  const [rotationDashboard, setRotationDashboard] = useState<any>(null);
  const [rotationLogs, setRotationLogs] = useState<any[]>([]);
  const [evaluatingSecretId, setEvaluatingSecretId] = useState<string | null>(null);
  const [riskEvaluationResult, setRiskEvaluationResult] = useState<any>(null);
  const [rotatingSecretId, setRotatingSecretId] = useState<string | null>(null);
  const [rollingBackSecretId, setRollingBackSecretId] = useState<string | null>(null);
  const [rotationSubTab, setRotationSubTab] = useState<'metrics' | 'logs'>('metrics');
  const [failedLogins, setFailedLogins] = useState<number>(0);
  const [travelAnomalies, setTravelAnomalies] = useState<boolean>(false);
  const [leakAlerts, setLeakAlerts] = useState<boolean>(false);
  const [insiderThreats, setInsiderThreats] = useState<boolean>(false);

  // Feature 2: Secret Sandbox States
  const [sandboxSessions, setSandboxSessions] = useState<any[]>([]);
  const [sandboxPrompt, setSandboxPrompt] = useState<string>('');
  const [sandboxExpiresIn, setSandboxExpiresIn] = useState<number>(1);
  const [provisioningSandbox, setProvisioningSandbox] = useState<boolean>(false);
  const [createdSandboxSession, setCreatedSandboxSession] = useState<any>(null);
  const [destroyingSandboxId, setDestroyingSandboxId] = useState<string | null>(null);
  const [viewingCertificate, setViewingCertificate] = useState<string | null>(null);
  const [maskFieldName, setMaskFieldName] = useState<string>('');
  const [maskRawValue, setMaskRawValue] = useState<string>('');
  const [maskedFieldResult, setMaskedFieldResult] = useState<string | null>(null);
  const [maskingField, setMaskingField] = useState<boolean>(false);

  // Action / UI states
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({});
  const [chainValidationResult, setChainValidationResult] = useState<any>(null);
  const [validatingChain, setValidatingChain] = useState(false);

  // AI Scanner state
  const [scanText, setScanText] = useState('');
  const [scanFilename, setScanFilename] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);

  // Form states
  const [secretForm, setSecretForm] = useState({ name: '', value: '' });
  const [certForm, setCertForm] = useState({ name: '', domain: '', data: '', expiresAt: '' });
  const [userForm, setUserForm] = useState({ email: '', name: '', role: 'DEVELOPER' });

  // Sandbox widget state
  const [isSandbox, setIsSandbox] = useState(false);

  useEffect(() => {
    // Check if sandbox is active
    setIsSandbox(process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true');
    fetchUserContext();
  }, []);

  useEffect(() => {
    if (userContext) {
      fetchTabData();
    }
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
      } else if (activeTab === 'rotation') {
        const resDash = await fetch('/api/rotation');
        if (!resDash.ok) {
          const err = await resDash.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setRotationDashboard(null);
          return;
        }
        const dataDash = await resDash.json();
        setRotationDashboard(dataDash);

        const resLogs = await fetch('/api/rotation?tab=logs');
        if (resLogs.ok) {
          const dataLogs = await resLogs.json();
          setRotationLogs(Array.isArray(dataLogs.logs) ? dataLogs.logs : []);
        }
      } else if (activeTab === 'sandbox') {
        const res = await fetch('/api/sandbox');
        if (!res.ok) {
          const err = await res.json();
          setTabError(err.error || 'Access Denied: Insufficient permissions');
          setSandboxSessions([]);
          return;
        }
        const data = await res.json();
        setSandboxSessions(Array.isArray(data.sessions) ? data.sessions : []);
      }
    } catch (err: any) {
      console.error('Failed to fetch tab data:', err);
      setTabError(err.message || 'An unexpected error occurred');
    }
  };

  const handleLogout = async () => {
    try {
      const res = await fetch('/api/auth/logout', { method: 'POST' });
      const data = await res.json();
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
      } else {
        router.push('/');
      }
    } catch (err) {
      console.error('Logout error:', err);
      router.push('/');
    }
  };

  // Sandbox Persona Quick-Switch
  const switchSandboxPersona = async (email: string, role: string, tenant: string, name: string) => {
    try {
      const res = await fetch('/api/dev/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role, tenant, name })
      });
      const data = await res.json();
      if (data.redirectUrl) {
        // Clear state and force page reload via standard callback redirection
        setRevealedSecrets({});
        window.location.href = data.redirectUrl;
      }
    } catch (err) {
      alert('Error switching sandbox persona: ' + err);
    }
  };

  // Permission helper
  const can = (permission: string) => {
    return userContext?.permissions?.includes(permission);
  };

  // --- Secret Actions ---
  const handleRevealSecret = async (id: string) => {
    if (revealedSecrets[id]) {
      // Toggle off
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
      setRevealedSecrets({
        ...revealedSecrets,
        [id]: data.value
      });
    } catch (err: any) {
      alert('Failed to decrypt secret: ' + err.message);
    }
  };

  const handleCreateSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secretForm.name || !secretForm.value) return;

    try {
      const res = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(secretForm)
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setSecretForm({ name: '', value: '' });
      fetchTabData();
    } catch (err: any) {
      alert('Failed to save secret: ' + err.message);
    }
  };

  const handleRotateSecret = async (id: string) => {
    if (!confirm('Are you sure you want to rotate this secret? It will generate a new cryptographically secure random value.')) {
      return;
    }
    try {
      const res = await fetch('/api/secrets', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action: 'rotate' })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      // Remove any active reveal cache for it
      const updatedReveals = { ...revealedSecrets };
      delete updatedReveals[id];
      setRevealedSecrets(updatedReveals);
      fetchTabData();
    } catch (err: any) {
      alert('Failed to rotate secret: ' + err.message);
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
    } catch (err: any) {
      alert('Failed to delete secret: ' + err.message);
    }
  };

  // --- Certificate Actions ---
  const handleImportCert = async (e: React.FormEvent) => {
    e.preventDefault();
    const { name, domain, data, expiresAt } = certForm;
    if (!name || !domain || !data || !expiresAt) return;

    try {
      const res = await fetch('/api/certificates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, domain, certificateData: data, expiresAt })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setCertForm({ name: '', domain: '', data: '', expiresAt: '' });
      fetchTabData();
    } catch (err: any) {
      alert('Failed to import certificate: ' + err.message);
    }
  };

  const handleRenewCert = async (id: string) => {
    try {
      const res = await fetch('/api/certificates', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: any) {
      alert('Failed to renew certificate: ' + err.message);
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
    } catch (err: any) {
      alert('Failed to delete certificate: ' + err.message);
    }
  };

  // --- Audit Logs Verification ---
  const handleVerifyAuditLogsChain = async () => {
    setValidatingChain(true);
    setChainValidationResult(null);
    try {
      const res = await fetch('/api/audit-logs?verify=true');
      const data = await res.json();
      setChainValidationResult(data);
    } catch (err: any) {
      alert('Failed to verify audit logs chain: ' + err.message);
    } finally {
      setValidatingChain(false);
    }
  };

  // --- AI Scanner ---
  const handleAiScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanText) return;
    setScanning(true);
    setScanResult(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: scanText, filename: scanFilename || 'unnamed_source.txt' })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Scan failed: ${err.error}`);
        return;
      }
      const data = await res.json();
      setScanResult(data);
    } catch (err: any) {
      alert('Scan error: ' + err.message);
    } finally {
      setScanning(false);
    }
  };

  // --- User / Role Management ---
  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.email || !userForm.role) return;

    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userForm)
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      setUserForm({ email: '', name: '', role: 'DEVELOPER' });
      fetchTabData();
    } catch (err: any) {
      alert('Failed to invite user: ' + err.message);
    }
  };

  const handleUpdateUserRole = async (userId: string, newRole: string) => {
    try {
      const res = await fetch('/api/users', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: userId, role: newRole })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Access Denied: ${err.error}`);
        return;
      }
      fetchTabData();
    } catch (err: any) {
      alert('Failed to update user role: ' + err.message);
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
    } catch (err: any) {
      alert('Failed to remove user: ' + err.message);
    }
  };

  // --- Feature 1: AI Risk-Based Rotation Handlers ---
  const handleRiskEvaluate = async (secretId: string) => {
    setEvaluatingSecretId(secretId);
    setRiskEvaluationResult(null);
    try {
      const res = await fetch('/api/rotation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'evaluate',
          secretId,
          signals: {
            failedLogins: Number(failedLogins),
            travelAnomalies: travelAnomalies ? 1 : 0,
            leakAlerts: leakAlerts ? 1 : 0,
            insiderThreats: insiderThreats ? 1 : 0
          }
        })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Evaluation Failed: ${err.error}`);
        setEvaluatingSecretId(null);
        return;
      }
      const data = await res.json();
      setRiskEvaluationResult(data);
      // Reset inputs
      setFailedLogins(0);
      setTravelAnomalies(false);
      setLeakAlerts(false);
      setInsiderThreats(false);
      fetchTabData();
    } catch (err: any) {
      alert('Risk evaluation request failed: ' + err.message);
      setEvaluatingSecretId(null);
    }
  };

  const handleManualRotate = async (secretId: string) => {
    if (!confirm('Are you sure you want to trigger manual secret rotation? This will generate a replacement key, push updates to Kubernetes/AWS secret stores, and roll restart dependent workloads.')) return;
    setRotatingSecretId(secretId);
    try {
      const res = await fetch('/api/rotation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'rotate', secretId })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Rotation Failed: ${err.error}`);
        return;
      }
      alert('Secret rotated successfully! Workloads updated and restarted.');
      fetchTabData();
    } catch (err: any) {
      alert('Rotation request failed: ' + err.message);
    } finally {
      setRotatingSecretId(null);
    }
  };

  const handleRollback = async (secretId: string) => {
    if (!confirm('Are you sure you want to rollback this secret to its previous version? This will restore the previous cryptographic state in the database.')) return;
    setRollingBackSecretId(secretId);
    try {
      const res = await fetch('/api/rotation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'rollback', secretId })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Rollback Failed: ${err.error}`);
        return;
      }
      alert('Secret rolled back successfully!');
      fetchTabData();
    } catch (err: any) {
      alert('Rollback request failed: ' + err.message);
    } finally {
      setRollingBackSecretId(null);
    }
  };

  // --- Feature 2: Secret Sandbox Handlers ---
  const handleSandboxProvision = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sandboxPrompt.trim()) return;
    setProvisioningSandbox(true);
    setCreatedSandboxSession(null);
    try {
      const res = await fetch('/api/sandbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'provision',
          prompt: sandboxPrompt,
          expiresInHours: Number(sandboxExpiresIn)
        })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Provisioning Failed: ${err.error}`);
        return;
      }
      const data = await res.json();
      setCreatedSandboxSession(data.session);
      setSandboxPrompt('');
      fetchTabData();
    } catch (err: any) {
      alert('Sandbox provisioning failed: ' + err.message);
    } finally {
      setProvisioningSandbox(false);
    }
  };

  const handleSandboxDestroy = async (sessionId: string) => {
    if (!confirm('Are you sure you want to destroy this sandbox environment? This will purge all mock resources, delete storage, and sign a compliance destruction certificate.')) return;
    setDestroyingSandboxId(sessionId);
    try {
      const res = await fetch('/api/sandbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'destroy', sessionId })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Purge Failed: ${err.error}`);
        return;
      }
      alert('Sandbox destroyed successfully. Resources purged.');
      fetchTabData();
    } catch (err: any) {
      alert('Destruction request failed: ' + err.message);
    } finally {
      setDestroyingSandboxId(null);
    }
  };

  const handleMaskField = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!maskFieldName.trim() || !maskRawValue.trim()) return;
    setMaskingField(true);
    setMaskedFieldResult(null);
    try {
      const res = await fetch('/api/sandbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'mask',
          fieldName: maskFieldName,
          rawValue: maskRawValue
        })
      });
      if (res.ok) {
        const data = await res.json();
        setMaskedFieldResult(data.maskedValue);
      }
    } catch (err: any) {
      alert('Masking request failed: ' + err.message);
    } finally {
      setMaskingField(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', height: '100vh', justifyContent: 'center', alignItems: 'center', backgroundColor: '#09090b', color: '#a1a1aa' }}>
        Authenticating Secure Session...
      </div>
    );
  }

  return (
    <div className="dashboard-layout">
      
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <svg style={{ width: '24px', height: '24px', color: '#8b5cf6' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"></path>
          </svg>
          <span style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'Outfit, sans-serif' }}>
            Sovereign<span className="title-gradient">Guard</span>
          </span>
        </div>

        <ul className="sidebar-menu">
          <li>
            <div className={`sidebar-link ${activeTab === 'secrets' ? 'active' : ''}`} onClick={() => setActiveTab('secrets')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"></path>
              </svg>
              Secrets Manager
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'certs' ? 'active' : ''}`} onClick={() => setActiveTab('certs')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-.778.099-1.533.284-2.253"></path>
              </svg>
              TLS Certificates
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'scanner' ? 'active' : ''}`} onClick={() => setActiveTab('scanner')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 21m0 0l-.813-5.096L3 15.187m6 5.813l.813-5.096L15 15.188m-5.187-6.375L9 3m0 0l-.813 5.813L3 9.812m6-6.813l.813 5.813L15 9.813M21 21l-6-6m6 0l-6 6m6-6H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              AI Secret Scanner
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => setActiveTab('audit')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"></path>
              </svg>
              Audit Trail
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'users' ? 'active' : ''}`} onClick={() => setActiveTab('users')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"></path>
              </svg>
              User Roles (RBAC)
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'rotation' ? 'active' : ''}`} onClick={() => setActiveTab('rotation')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99"></path>
              </svg>
              AI Risk & Rotation
            </div>
          </li>
          <li>
            <div className={`sidebar-link ${activeTab === 'sandbox' ? 'active' : ''}`} onClick={() => setActiveTab('sandbox')}>
              <svg style={{ width: '18px', height: '18px' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              Secret Sandbox
            </div>
          </li>

          {/* Sandbox persona switcher */}
          {isSandbox && (
            <div className="dev-sandbox-widget">
              <div className="dev-sandbox-title">
                <span>Sandbox Controls</span>
                <span className="badge badge-purple" style={{ fontSize: '0.6rem' }}>Mock Auth</span>
              </div>
              <p style={{ color: '#71717a', fontSize: '0.75rem', marginBottom: '0.5rem' }}>
                Quick-swap role/tenant context:
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <button onClick={() => switchSandboxPersona('admin@acme.com', 'ORG_ADMIN', 'Acme Corp', 'Sarah Connor')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  🔑 Acme &bull; Org Admin
                </button>
                <button onClick={() => switchSandboxPersona('dev@acme.com', 'DEVELOPER', 'Acme Corp', 'John Doe')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  💻 Acme &bull; Developer
                </button>
                <button onClick={() => switchSandboxPersona('security@acme.com', 'SECURITY_ADMIN', 'Acme Corp', 'Ellen Ripley')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  🛡️ Acme &bull; Security Admin
                </button>
                <button onClick={() => switchSandboxPersona('auditor@acme.com', 'AUDITOR', 'Acme Corp', 'Marcus Aurelius')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  👁️ Acme &bull; Auditor
                </button>
                <button onClick={() => switchSandboxPersona('dev@betacorp.com', 'DEVELOPER', 'Beta Corp', 'Alice Smith')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  🏢 Beta Corp &bull; Developer
                </button>
                <button onClick={() => switchSandboxPersona('super@sovereignguard.io', 'SUPER_ADMIN', 'Sovereign Provider', 'Neo Matrix')} className="btn btn-secondary btn-sm" style={{ padding: '0.25rem', fontSize: '0.7rem', justifyContent: 'flex-start' }}>
                  🌐 Global &bull; Super Admin
                </button>
              </div>
            </div>
          )}
        </ul>

        {/* Sidebar Footer / User Banner */}
        <div className="sidebar-footer">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8125rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {userContext.name}
            </div>
            <div style={{ color: '#71717a', fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {userContext.email}
            </div>
            <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.5rem' }}>
              <span className="badge badge-purple" style={{ fontSize: '0.625rem' }}>{userContext.role}</span>
              <span className="badge badge-cyan" style={{ fontSize: '0.625rem' }}>{userContext.tenant.name}</span>
            </div>
            <button 
              onClick={handleLogout}
              className="btn btn-danger btn-sm" 
              style={{ marginTop: '0.75rem', width: '100%', padding: '0.3rem' }}
            >
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        <div className="container">
          
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', borderBottom: '1px solid #27272a', paddingBottom: '1rem' }}>
            <div>
              <h2 style={{ fontSize: '1.75rem', fontWeight: 700 }}>
                {activeTab === 'secrets' && 'Secrets & Cryptographic Keys'}
                {activeTab === 'certs' && 'TLS Certificate Lifecycles'}
                {activeTab === 'scanner' && 'AI Exposure Scan Engine'}
                {activeTab === 'audit' && 'Cryptographic Immutable Audit Trails'}
                {activeTab === 'users' && 'Team Identities & Access Controls'}
                {activeTab === 'rotation' && 'AI Risk-Based Secret Rotation'}
                {activeTab === 'sandbox' && 'Enterprise Secret Sandbox'}
              </h2>
              <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginTop: '0.25rem' }}>
                Active Organization Scope: <span style={{ color: '#06b6d4', fontWeight: 600 }}>{userContext.tenant.name}</span>
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', backgroundColor: '#18181b', padding: '0.5rem 0.75rem', borderRadius: '6px', border: '1px solid #27272a' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981', display: 'inline-block' }}></span>
              Security Guard Active
            </div>
          </div>

          {tabError && (
            <div className="alert alert-error" style={{ marginBottom: '1.5rem' }}>
              <svg style={{ width: '20px', height: '20px', flexShrink: 0 }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
              </svg>
              <div>
                <strong>Access Denied:</strong> {tabError}
              </div>
            </div>
          )}

          {/* TAB 1: SECRETS MANAGER */}
          {activeTab === 'secrets' && (
            <div>
              {/* Form to create secret (requires secrets:create) */}
              {can('secrets:create') ? (
                <form onSubmit={handleCreateSecret} className="card" style={{ marginBottom: '2rem', border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '1rem' }}>Provision New Cryptographic Secret</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Secret Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. STRIPE_API_KEY" 
                        value={secretForm.name}
                        onChange={e => setSecretForm({ ...secretForm, name: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Secret Value</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="Paste value to encrypt at rest" 
                        value={secretForm.value}
                        onChange={e => setSecretForm({ ...secretForm, value: e.target.value })}
                        required
                      />
                    </div>
                  </div>
                  <button type="submit" className="btn btn-primary">Encrypt & Store Secret</button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  Your role (<strong>{userContext.role}</strong>) does not have write/create permissions for Secrets. Displaying read-only view.
                </div>
              )}

              {/* Secrets Table */}
              <div className="card" style={{ border: '1px solid #27272a' }}>
                <h3 style={{ marginBottom: '1rem' }}>Active Vault Items</h3>
                {secrets.length === 0 ? (
                  <p style={{ color: '#71717a', fontSize: '0.875rem' }}>No secrets stored for this organization.</p>
                ) : (
                  <div className="table-container">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Secret Name</th>
                          <th>Encrypted Value</th>
                          <th>Version</th>
                          <th>Last Updated</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {secrets.map((sec) => (
                          <tr key={sec.id}>
                            <td style={{ fontWeight: 600, fontFamily: 'monospace' }}>{sec.name}</td>
                            <td>
                              <span style={{ 
                                fontFamily: 'monospace', 
                                backgroundColor: '#18181b', 
                                padding: '0.2rem 0.5rem', 
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                border: '1px solid #27272a',
                                color: revealedSecrets[sec.id] ? '#10b981' : '#71717a'
                              }}>
                                {revealedSecrets[sec.id] || '••••••••••••••••'}
                              </span>
                            </td>
                            <td>
                              <span className="badge badge-cyan">v{sec.version}</span>
                            </td>
                            <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                              {new Date(sec.updatedAt).toLocaleString()}
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                                <button 
                                  onClick={() => handleRevealSecret(sec.id)}
                                  className="btn btn-secondary btn-sm"
                                >
                                  {revealedSecrets[sec.id] ? 'Hide' : 'Decrypt'}
                                </button>
                                {can('secrets:rotate') && (
                                  <button 
                                    onClick={() => handleRotateSecret(sec.id)}
                                    className="btn btn-secondary btn-sm"
                                    style={{ color: '#f59e0b', borderColor: 'rgba(245, 158, 11, 0.2)' }}
                                  >
                                    Rotate
                                  </button>
                                )}
                                {can('secrets:delete') && (
                                  <button 
                                    onClick={() => handleDeleteSecret(sec.id)}
                                    className="btn btn-danger btn-sm"
                                  >
                                    Delete
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: CERTIFICATE LIFECYCLE */}
          {activeTab === 'certs' && (
            <div>
              {/* Form to import cert (requires certs:import) */}
              {can('certs:import') ? (
                <form onSubmit={handleImportCert} className="card" style={{ marginBottom: '2rem', border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '1rem' }}>Import TLS Certificate</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Friendly Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. Acme Web SSL" 
                        value={certForm.name}
                        onChange={e => setCertForm({ ...certForm, name: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Domain Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. *.acme.com" 
                        value={certForm.domain}
                        onChange={e => setCertForm({ ...certForm, domain: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Expiration Date</label>
                      <input 
                        type="date" 
                        className="input" 
                        value={certForm.expiresAt}
                        onChange={e => setCertForm({ ...certForm, expiresAt: e.target.value })}
                        required
                      />
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Certificate PEM Data</label>
                    <textarea 
                      className="input" 
                      style={{ fontFamily: 'monospace', height: '80px', fontSize: '0.75rem' }} 
                      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" 
                      value={certForm.data}
                      onChange={e => setCertForm({ ...certForm, data: e.target.value })}
                      required
                    />
                  </div>
                  <button type="submit" className="btn btn-primary">Import & Register Certificate</button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  Your role (<strong>{userContext.role}</strong>) does not have import permissions for TLS certificates.
                </div>
              )}

              {/* Certificates Table */}
              <div className="card" style={{ border: '1px solid #27272a' }}>
                <h3 style={{ marginBottom: '1rem' }}>Registered Certificates</h3>
                {certs.length === 0 ? (
                  <p style={{ color: '#71717a', fontSize: '0.875rem' }}>No TLS certificates registered.</p>
                ) : (
                  <div className="table-container">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Domain Name</th>
                          <th>Status</th>
                          <th>Expiration Date</th>
                          <th>Urgency</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {certs.map((cert) => {
                          const expiryDate = new Date(cert.expiresAt);
                          const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                          const isExpired = daysLeft <= 0;
                          const isExpiringSoon = daysLeft > 0 && daysLeft <= 30;
                          
                          let badgeType = 'badge-green';
                          let statusText = 'ACTIVE';
                          if (isExpired) {
                            badgeType = 'badge-red';
                            statusText = 'EXPIRED';
                          } else if (isExpiringSoon) {
                            badgeType = 'badge-amber';
                            statusText = 'EXPIRING';
                          }

                          return (
                            <tr key={cert.id}>
                              <td style={{ fontWeight: 600 }}>{cert.name}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '0.8125rem' }}>{cert.domain}</td>
                              <td>
                                <span className={`badge ${badgeType}`}>{statusText}</span>
                              </td>
                              <td style={{ fontSize: '0.75rem' }}>
                                {expiryDate.toLocaleDateString()}
                              </td>
                              <td>
                                {isExpired ? (
                                  <span style={{ color: '#ef4444', fontSize: '0.75rem', fontWeight: 600 }}>Expired</span>
                                ) : isExpiringSoon ? (
                                  <span style={{ color: '#f59e0b', fontSize: '0.75rem', fontWeight: 600 }}>Expiring in {daysLeft} days!</span>
                                ) : (
                                  <span style={{ color: '#10b981', fontSize: '0.75rem' }}>Healthy ({daysLeft} days)</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                                  {can('certs:renew') && (
                                    <button 
                                      onClick={() => handleRenewCert(cert.id)}
                                      className="btn btn-secondary btn-sm"
                                      style={{ color: '#06b6d4', borderColor: 'rgba(6, 182, 212, 0.2)' }}
                                    >
                                      Auto-Renew
                                    </button>
                                  )}
                                  {can('certs:delete') && (
                                    <button 
                                      onClick={() => handleDeleteCert(cert.id)}
                                      className="btn btn-danger btn-sm"
                                    >
                                      Remove
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: AI EXPOSURE SCANNER */}
          {activeTab === 'scanner' && (
            <div>
              <div className="card" style={{ border: '1px solid #27272a', marginBottom: '2rem' }}>
                <h3 style={{ marginBottom: '0.5rem' }}>Scan Code for Secrets & Exposed Credentials</h3>
                <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
                  Analyze source files, environment configs, or scripts for hardcoded secrets, private keys, and API tokens. A deterministic regex/entropy pre-filter finds candidates, then <span style={{ color: '#8b5cf6', fontWeight: 600 }}>Anthropic Claude</span> classifies each one — only a masked snippet ever leaves this process.
                </p>

                <form onSubmit={handleAiScan}>
                  <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Filename Context</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. src/utils/db.ts" 
                        value={scanFilename}
                        onChange={e => setScanFilename(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Code / File Content to Scan</label>
                    <textarea 
                      className="input" 
                      style={{ fontFamily: 'monospace', height: '200px', fontSize: '0.8125rem' }} 
                      placeholder="Paste code or config text here... (e.g. const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE')" 
                      value={scanText}
                      onChange={e => setScanText(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" disabled={scanning} className="btn btn-primary">
                    {scanning ? 'Analyzing Exposures...' : 'Run Security Audit'}
                  </button>
                </form>
              </div>

              {/* Scan Results */}
              {scanResult && (
                <div className="card" style={{ border: '1px solid #27272a' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', borderBottom: '1px solid #27272a', paddingBottom: '1rem' }}>
                    <div>
                      <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        Scan Summary
                        <span className={`badge ${scanResult.safe ? 'badge-green' : 'badge-red'}`}>
                          {scanResult.safe ? 'COMPLIANT' : 'EXPOSED'}
                        </span>
                      </h3>
                      <p style={{ color: '#a1a1aa', fontSize: '0.8125rem', marginTop: '0.25rem' }}>
                        {scanResult.isMocked
                          ? 'Executed via local regex/entropy pre-filter only — live LLM classification was unavailable for this scan.'
                          : `Classified by ${scanResult.modelUsed || 'Anthropic Claude'} after the deterministic pre-filter stage.`}
                      </p>
                    </div>
                  </div>

                  <p style={{ fontWeight: 500, marginBottom: '1rem' }}>{scanResult.summary}</p>

                  {scanResult.findings.length === 0 ? (
                    <div style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '1rem', borderRadius: '8px', color: '#10b981', fontSize: '0.875rem' }}>
                      🟢 No credentials, private keys, or API tokens were found in the scanned text.
                    </div>
                  ) : (
                    <div className="table-container">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Line</th>
                            <th>Exposure Type</th>
                            <th>Matched Signature</th>
                            <th>Risk Level</th>
                            <th>Remediation Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanResult.findings.map((f: any, idx: number) => (
                            <tr key={idx}>
                              <td style={{ fontWeight: 600, fontFamily: 'monospace' }}>L{f.line}</td>
                              <td style={{ color: '#ef4444', fontWeight: 600 }}>{f.type}</td>
                              <td>
                                <code style={{ backgroundColor: '#1c1917', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#fdba74' }}>
                                  {f.evidence}
                                </code>
                              </td>
                              <td>
                                <span className={`badge ${
                                  f.risk === 'HIGH' ? 'badge-red' : f.risk === 'MEDIUM' ? 'badge-amber' : 'badge-cyan'
                                }`}>
                                  {f.risk}
                                </span>
                              </td>
                              <td style={{ fontSize: '0.8125rem', color: '#a1a1aa' }}>{f.remediation}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: IMMUTABLE AUDIT TRAIL */}
          {activeTab === 'audit' && (
            <div>
              {/* Integrity Checker Panel */}
              <div className="card" style={{ border: '1px solid #27272a', marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <svg style={{ width: '20px', height: '20px', color: '#8b5cf6' }} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"></path>
                    </svg>
                    Audit Log Chain Verification
                  </h3>
                  <p style={{ color: '#a1a1aa', fontSize: '0.8125rem', marginTop: '0.25rem' }}>
                    Scan all historic audit records. Validates the hash link pointer of the cryptographic block chain and checks signatures.
                  </p>
                </div>
                <button 
                  onClick={handleVerifyAuditLogsChain} 
                  disabled={validatingChain} 
                  className="btn btn-primary"
                >
                  {validatingChain ? 'Validating Chain...' : 'Verify Chain Integrity'}
                </button>
              </div>

              {/* Chain validation result alert */}
              {chainValidationResult && (
                <div style={{ marginBottom: '2rem' }}>
                  {chainValidationResult.valid ? (
                    <div className="alert alert-success" style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span>✅ Cryptographic Verification Successful</span>
                      </div>
                      <p style={{ fontSize: '0.8125rem' }}>
                        Verified total of <strong>{chainValidationResult.totalRecords}</strong> entries. Hash linkage is continuous and all records match their original HMAC signatures. No database modifications detected.
                      </p>
                    </div>
                  ) : (
                    <div className="alert alert-error" style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span>🚨 WARNING: Database Tampering Detected!</span>
                      </div>
                      <p style={{ fontSize: '0.8125rem' }}>
                        Auditor discovered invalid links in the log ledger! Details of the failure:
                      </p>
                      <ul style={{ paddingLeft: '1.25rem', marginTop: '0.5rem', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                        {chainValidationResult.errors.map((err: any, idx: number) => (
                          <li key={idx} style={{ color: '#fca5a5' }}>
                            Record #{err.index} (ID: {err.id.substring(0, 8)}...): {err.error}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Audit Table */}
              <div className="card" style={{ border: '1px solid #27272a' }}>
                <h3 style={{ marginBottom: '1rem' }}>Ledger Stream</h3>
                <p style={{ color: '#71717a', fontSize: '0.75rem', marginTop: '-0.5rem', marginBottom: '1rem' }}>
                  Every row below is a link in the cryptographic hash chain — each entry&apos;s hash covers the previous
                  entry&apos;s hash, so this is the actual chain &quot;Verify Chain Integrity&quot; checks.
                </p>
                <div className="table-container">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Action</th>
                        <th>Resource</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log) => (
                        <tr key={log.id}>
                          <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td style={{ fontWeight: 600 }}>{log.action}</td>
                          <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {log.resourceType}
                            {log.resourceId ? `:${log.resourceId.slice(0, 8)}…` : ''}
                          </td>
                          <td style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#a1a1aa', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {log.details}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: USER ROLES AND RBAC */}
          {activeTab === 'users' && (
            <div>
              {/* Form to invite user (requires users:invite) */}
              {can('users:invite') ? (
                <form onSubmit={handleInviteUser} className="card" style={{ marginBottom: '2rem', border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '1rem' }}>Add User to Organization</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Email Address</label>
                      <input 
                        type="email" 
                        className="input" 
                        placeholder="e.g. engineer@acme.com" 
                        value={userForm.email}
                        onChange={e => setUserForm({ ...userForm, email: e.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Full Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. Robert Smith" 
                        value={userForm.name}
                        onChange={e => setUserForm({ ...userForm, name: e.target.value })}
                      />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label className="form-label">Assign Role</label>
                      <select 
                        className="select"
                        value={userForm.role}
                        onChange={e => setUserForm({ ...userForm, role: e.target.value })}
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
                  <button type="submit" className="btn btn-primary">Add Member</button>
                </form>
              ) : (
                <div className="alert alert-warning">
                  Your role (<strong>{userContext.role}</strong>) does not have invite permissions.
                </div>
              )}

              {/* Members Table */}
              <div className="card" style={{ border: '1px solid #27272a' }}>
                <h3 style={{ marginBottom: '1rem' }}>Organization Membership</h3>
                <div className="table-container">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Email Address</th>
                        <th>Active Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {teamMembers.map((member) => (
                        <tr key={member.id}>
                          <td style={{ fontWeight: 600 }}>{member.name}</td>
                          <td style={{ fontSize: '0.8125rem', fontFamily: 'monospace' }}>{member.email}</td>
                          <td>
                            {can('users:update-role') && member.id !== userContext.id ? (
                              <select 
                                className="select" 
                                style={{ padding: '0.2rem 0.5rem', width: 'auto', fontSize: '0.75rem' }}
                                value={member.role}
                                onChange={(e) => handleUpdateUserRole(member.id, e.target.value)}
                              >
                                <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                                <option value="ORG_ADMIN">ORG_ADMIN</option>
                                <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
                                <option value="DEVELOPER">DEVELOPER</option>
                                <option value="AUDITOR">AUDITOR</option>
                                <option value="READ_ONLY">READ_ONLY</option>
                                <option value="SERVICE_ACCOUNT">SERVICE_ACCOUNT</option>
                              </select>
                            ) : (
                              <span className="badge badge-purple">{member.role}</span>
                            )}
                          </td>
                          <td>
                            <span className={`badge ${member.status === 'ACTIVE' ? 'badge-green' : 'badge-red'}`}>
                              {member.status}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                            {new Date(member.lastLogin).toLocaleString()}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            {can('users:remove') && member.id !== userContext.id && (
                              <button 
                                onClick={() => handleRemoveUser(member.id)}
                                className="btn btn-danger btn-sm"
                              >
                                Remove
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: AI RISK-BASED ROTATION */}
          {activeTab === 'rotation' && (
            <div>
              {/* Sub-tab navigation */}
              <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', borderBottom: '1px solid #27272a', paddingBottom: '0.5rem' }}>
                <button 
                  onClick={() => setRotationSubTab('metrics')} 
                  className={`btn ${rotationSubTab === 'metrics' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                >
                  📊 Postures & Health Metrics
                </button>
                <button 
                  onClick={() => setRotationSubTab('logs')} 
                  className={`btn ${rotationSubTab === 'logs' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                >
                  📜 Rotation Audit Ledger
                </button>
              </div>

              {rotationSubTab === 'metrics' ? (
                <div>
                  {/* Summary Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '1rem', marginBottom: '2rem' }}>
                    <div className="card" style={{ border: '1px solid #27272a', textAlign: 'center' }}>
                      <h4 style={{ color: '#a1a1aa', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Overall Security Score</h4>
                      <div style={{ fontSize: '2.5rem', fontWeight: 800, color: rotationDashboard?.overallScore >= 80 ? '#10b981' : rotationDashboard?.overallScore >= 50 ? '#eab308' : '#ef4444' }}>
                        {rotationDashboard?.overallScore || 100}%
                      </div>
                      <p style={{ fontSize: '0.75rem', color: '#a1a1aa', marginTop: '0.25rem' }}>Calculated from active risks</p>
                    </div>
                    <div className="card" style={{ border: '1px solid #27272a', textAlign: 'center' }}>
                      <h4 style={{ color: '#a1a1aa', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Critical Secrets</h4>
                      <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#ef4444' }}>
                        {rotationDashboard?.riskDistribution?.critical || 0}
                      </div>
                      <p style={{ fontSize: '0.75rem', color: '#a1a1aa', marginTop: '0.25rem' }}>Require immediate rotation</p>
                    </div>
                    <div className="card" style={{ border: '1px solid #27272a', textAlign: 'center' }}>
                      <h4 style={{ color: '#a1a1aa', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>High & Medium Risks</h4>
                      <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#eab308' }}>
                        {(rotationDashboard?.riskDistribution?.high || 0) + (rotationDashboard?.riskDistribution?.medium || 0)}
                      </div>
                      <p style={{ fontSize: '0.75rem', color: '#a1a1aa', marginTop: '0.25rem' }}>Scheduled for review</p>
                    </div>
                    <div className="card" style={{ border: '1px solid #27272a', textAlign: 'center' }}>
                      <h4 style={{ color: '#a1a1aa', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Low Risk Compliance</h4>
                      <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#10b981' }}>
                        {rotationDashboard?.riskDistribution?.low || 0}
                      </div>
                      <p style={{ fontSize: '0.75rem', color: '#a1a1aa', marginTop: '0.25rem' }}>Healthy secure baseline</p>
                    </div>
                  </div>

                  {/* Main Action Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
                    {/* Left: Secrets Risk Table */}
                    <div className="card" style={{ border: '1px solid #27272a' }}>
                      <h3 style={{ marginBottom: '1rem' }}>Evaluate & Manage Secrets Security Posture</h3>
                      <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.5rem' }}>
                        Continuously audit telemetry. Triggering evaluations with high-risk events (like leak alerts) will automatically fire the autonomous rotation pipeline.
                      </p>
                      
                      {secrets.length === 0 ? (
                        <p style={{ color: '#a1a1aa', fontStyle: 'italic' }}>No secrets registered. Add secrets under Secrets Manager.</p>
                      ) : (
                        <div className="table-container">
                          <table className="table">
                            <thead>
                              <tr>
                                <th>Secret Name</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Last Rotated</th>
                                <th style={{ textAlign: 'right' }}>Actions</th>
                              </tr>
                            </thead>
                            <tbody>
                              {secrets.map((s) => {
                                // Find if this secret has current metrics in the dashboard
                                const dashSec = rotationDashboard?.criticalSecrets?.find((cs: any) => cs.id === s.id) || s;
                                return (
                                  <tr key={s.id}>
                                    <td style={{ fontWeight: 600 }}>{s.name}</td>
                                    <td>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <div style={{ width: '60px', backgroundColor: '#27272a', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
                                          <div style={{ width: `${dashSec.riskScore || 0}%`, backgroundColor: dashSec.riskScore >= 70 ? '#ef4444' : dashSec.riskScore >= 40 ? '#eab308' : '#10b981', height: '100%' }}></div>
                                        </div>
                                        <span style={{ fontSize: '0.8125rem', fontFamily: 'monospace' }}>{dashSec.riskScore || 0}/100</span>
                                      </div>
                                    </td>
                                    <td>
                                      <span className={`badge ${dashSec.riskLevel === 'CRITICAL' ? 'badge-red' : dashSec.riskLevel === 'HIGH' ? 'badge-red' : dashSec.riskLevel === 'MEDIUM' ? 'badge-purple' : 'badge-green'}`}>
                                        {dashSec.riskLevel || 'LOW'}
                                      </span>
                                    </td>
                                    <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                                      {dashSec.lastRotationTime ? new Date(dashSec.lastRotationTime).toLocaleDateString() : 'Never'}
                                    </td>
                                    <td style={{ textAlign: 'right' }}>
                                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                                        <button 
                                          onClick={() => {
                                            setEvaluatingSecretId(s.id);
                                            setRiskEvaluationResult(null);
                                          }}
                                          className="btn btn-secondary btn-sm"
                                        >
                                          🔍 Audit
                                        </button>
                                        <button 
                                          onClick={() => handleManualRotate(s.id)}
                                          disabled={rotatingSecretId === s.id}
                                          className="btn btn-primary btn-sm"
                                        >
                                          {rotatingSecretId === s.id ? 'Rotating...' : '🔄 Rotate'}
                                        </button>
                                        {s.version > 1 && (
                                          <button 
                                            onClick={() => handleRollback(s.id)}
                                            disabled={rollingBackSecretId === s.id}
                                            className="btn btn-danger btn-sm"
                                            title="Rollback to previous version"
                                          >
                                            ⏪ Rollback
                                          </button>
                                        )}
                                      </div>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>

                    {/* Right: AI Audit panel */}
                    <div>
                      {evaluatingSecretId ? (
                        <div className="card" style={{ border: '1px solid #8b5cf6', background: 'rgba(139, 92, 246, 0.02)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                            <h3 style={{ margin: 0 }}>AI Posture Audit</h3>
                            <button onClick={() => setEvaluatingSecretId(null)} style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', fontSize: '1.25rem' }}>&times;</button>
                          </div>
                          <p style={{ color: '#a1a1aa', fontSize: '0.8125rem', marginBottom: '1.25rem' }}>
                            Configure telemetry signals to run risk analysis for: <strong>{secrets.find(s => s.id === evaluatingSecretId)?.name}</strong>
                          </p>

                          <div className="form-group">
                            <label className="form-label">Failed Login Attempts (Last 24h)</label>
                            <input 
                              type="number" 
                              className="input" 
                              value={failedLogins} 
                              onChange={e => setFailedLogins(Math.max(0, Number(e.target.value)))}
                            />
                          </div>

                          <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <input 
                              type="checkbox" 
                              id="travel" 
                              checked={travelAnomalies} 
                              onChange={e => setTravelAnomalies(e.target.checked)}
                            />
                            <label htmlFor="travel" className="form-label" style={{ marginBottom: 0, cursor: 'pointer' }}>Geographic impossible travel anomaly</label>
                          </div>

                          <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <input 
                              type="checkbox" 
                              id="leak" 
                              checked={leakAlerts} 
                              onChange={e => setLeakAlerts(e.target.checked)}
                            />
                            <label htmlFor="leak" className="form-label" style={{ marginBottom: 0, cursor: 'pointer' }}>Public Git repository leak detected</label>
                          </div>

                          <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
                            <input 
                              type="checkbox" 
                              id="insider" 
                              checked={insiderThreats} 
                              onChange={e => setInsiderThreats(e.target.checked)}
                            />
                            <label htmlFor="insider" className="form-label" style={{ marginBottom: 0, cursor: 'pointer' }}>Insider threat anomalies detected</label>
                          </div>

                          <button 
                            onClick={() => handleRiskEvaluate(evaluatingSecretId)}
                            className="btn btn-primary"
                            style={{ width: '100%', marginBottom: '1.5rem' }}
                          >
                            Execute AI Risk Audit
                          </button>

                          {/* Evaluation results */}
                          {riskEvaluationResult && (
                            <div style={{ marginTop: '1.5rem', borderTop: '1px solid #27272a', paddingTop: '1.5rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                <h4 style={{ fontWeight: 700, margin: 0 }}>AI Audit Report</h4>
                                <span className={`badge ${riskEvaluationResult.riskLevel === 'CRITICAL' ? 'badge-red' : riskEvaluationResult.riskLevel === 'HIGH' ? 'badge-red' : riskEvaluationResult.riskLevel === 'MEDIUM' ? 'badge-purple' : 'badge-green'}`}>
                                  {riskEvaluationResult.riskLevel} ({riskEvaluationResult.riskScore}/100)
                                </span>
                              </div>
                              <p style={{ fontSize: '0.875rem', marginBottom: '1rem', background: '#18181b', padding: '0.75rem', borderRadius: '6px', border: '1px solid #27272a', lineHeight: '1.4' }}>
                                💡 <strong>Explainability:</strong> {riskEvaluationResult.explanation}
                              </p>
                              <div style={{ fontSize: '0.75rem', color: '#a1a1aa', marginBottom: '1rem' }}>
                                🛡️ AI Confidence: <strong>{(riskEvaluationResult.confidence * 100).toFixed(0)}%</strong>
                              </div>
                              
                              {riskEvaluationResult.autoRotated && (
                                <div style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '0.75rem', borderRadius: '6px', color: '#10b981', fontSize: '0.8125rem' }}>
                                  🔄 <strong>Autonomous Rotation Fired:</strong> Risk score exceeded threshold (70+). A new credential has been generated, synced with Kubernetes / cloud secret vaults, and dependent workloads successfully restarted.
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="card" style={{ border: '1px solid #27272a', textAlign: 'center', padding: '3rem 1.5rem', color: '#a1a1aa' }}>
                          ℹ️ Select a secret and click "Audit" to run telemetry assessments or test autonomous rotation.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Recommendations and Trends */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                    <div className="card" style={{ border: '1px solid #27272a' }}>
                      <h3 style={{ marginBottom: '1rem' }}>AI Recommendations</h3>
                      {rotationDashboard?.aiRecommendations?.length === 0 ? (
                        <p style={{ color: '#10b981', fontSize: '0.875rem' }}>🟢 All secrets are healthy. No active rotation advisories.</p>
                      ) : (
                        <ul style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingLeft: '1.25rem', margin: 0 }}>
                          {rotationDashboard?.aiRecommendations?.map((rec: any, idx: number) => (
                            <li key={idx} style={{ fontSize: '0.875rem', color: rec.recommendation.includes('CRITICAL') ? '#ef4444' : '#eab308' }}>
                              {rec.recommendation}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                    <div className="card" style={{ border: '1px solid #27272a' }}>
                      <h3 style={{ marginBottom: '1rem' }}>Trending Platform Risks</h3>
                      <ul style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingLeft: '1.25rem', color: '#a1a1aa', fontSize: '0.875rem', margin: 0 }}>
                        {rotationDashboard?.trendingRisks?.map((t: string, idx: number) => (
                          <li key={idx}>{t}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                /* Rotation logs */
                <div className="card" style={{ border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '1rem' }}>Secret Rotation Audit History</h3>
                  <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.5rem' }}>
                    Tamper-proof ledger showing trigger types, version shifts, pre-rotation threat scores, and the detailed deployment rolling restart timeline.
                  </p>

                  {rotationLogs.length === 0 ? (
                    <p style={{ color: '#a1a1aa', fontStyle: 'italic' }}>No rotation logs registered on the ledger.</p>
                  ) : (
                    <div className="table-container">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Secret Name</th>
                            <th>Trigger Type</th>
                            <th>Version Shift</th>
                            <th>Risk Score Before</th>
                            <th>Reason</th>
                            <th>Timestamp</th>
                          </tr>
                        </thead>
                        <tbody>
                          {rotationLogs.map((log: any) => {
                            const name = secrets.find(s => s.id === log.secretId)?.name || 'Unknown Secret';
                            return (
                              <tr key={log.id}>
                                <td style={{ fontWeight: 600 }}>{name}</td>
                                <td>
                                  <span className={`badge ${log.triggerType === 'AUTO' ? 'badge-purple' : 'badge-blue'}`}>
                                    {log.triggerType}
                                  </span>
                                </td>
                                <td style={{ fontSize: '0.8125rem', fontFamily: 'monospace' }}>
                                  v{log.oldVersion} &rarr; v{log.newVersion}
                                </td>
                                <td style={{ fontSize: '0.8125rem', fontFamily: 'monospace', color: log.riskScoreBefore >= 70 ? '#ef4444' : '#eab308' }}>
                                  {log.riskScoreBefore}/100
                                </td>
                                <td style={{ fontSize: '0.8125rem', color: '#a1a1aa', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.rotationReason}>
                                  {log.rotationReason}
                                </td>
                                <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                                  {new Date(log.createdAt).toLocaleString()}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 7: ENTERPRISE SECRET SANDBOX */}
          {activeTab === 'sandbox' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
                
                {/* Left: Provisioning Sandbox */}
                <div className="card" style={{ border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '0.5rem' }}>Orchestrate Isolated Test Sandbox</h3>
                  <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
                    Enter testing specifications naturally. The AI will provision temporary schemas, disposable credentials, and network namespaces that expire automatically.
                  </p>

                  <form onSubmit={handleSandboxProvision}>
                    <div className="form-group">
                      <label className="form-label">Natural Language Environment Prompt</label>
                      <textarea 
                        className="input" 
                        style={{ fontFamily: 'monospace', height: '100px', fontSize: '0.8125rem' }} 
                        placeholder="e.g. I need a test database to verify payments integration with mock Stripe API keys." 
                        value={sandboxPrompt}
                        onChange={e => setSandboxPrompt(e.target.value)}
                        required
                      />
                    </div>
                    <div className="form-group" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                      <div>
                        <label className="form-label">Auto-Expiry Window</label>
                        <select 
                          className="select"
                          value={sandboxExpiresIn}
                          onChange={e => setSandboxExpiresIn(Number(e.target.value))}
                        >
                          <option value={1}>1 Hour</option>
                          <option value={2}>2 Hours</option>
                          <option value={4}>4 Hours</option>
                          <option value={8}>8 Hours</option>
                          <option value={24}>24 Hours</option>
                        </select>
                      </div>
                    </div>
                    <button type="submit" disabled={provisioningSandbox} className="btn btn-primary">
                      {provisioningSandbox ? 'Orchestrating Environment...' : 'Deploy disposable Secret Sandbox'}
                    </button>
                  </form>

                  {/* Provisioned Sandbox Result */}
                  {createdSandboxSession && (
                    <div style={{ marginTop: '1.5rem', borderTop: '1px solid #27272a', paddingTop: '1.5rem' }}>
                      <h4 style={{ color: '#10b981', fontWeight: 700, marginBottom: '0.5rem' }}>🟢 Sandbox Successfully Deployed</h4>
                      <p style={{ fontSize: '0.875rem', marginBottom: '1rem' }}>
                        Environment: <strong>{createdSandboxSession.name}</strong> (Active until: {new Date(createdSandboxSession.expiresAt).toLocaleString()})
                      </p>
                      
                      <div className="table-container">
                        <table className="table">
                          <thead>
                            <tr>
                              <th>Resource</th>
                              <th>Type</th>
                              <th>Disposable Secret / Mock Value</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(createdSandboxSession.resources as any[] || []).map((r, i) => (
                              <tr key={i}>
                                <td style={{ fontWeight: 600 }}>{r.name}</td>
                                <td><span className="badge badge-purple">{r.type.toUpperCase()}</span></td>
                                <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#22d3ee' }}>{r.mockValue}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>

                {/* Right: Data Masking Utility */}
                <div className="card" style={{ border: '1px solid #27272a' }}>
                  <h3 style={{ marginBottom: '0.5rem' }}>Developer Data Masking</h3>
                  <p style={{ color: '#a1a1aa', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
                    Safely simulate production data masking. Enter raw parameters to verify tokenize and anonymization patterns.
                  </p>

                  <form onSubmit={handleMaskField}>
                    <div className="form-group">
                      <label className="form-label">Field Classification Name</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. credit_card, client_email, db_password" 
                        value={maskFieldName}
                        onChange={e => setMaskFieldName(e.target.value)}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Raw Production Value</label>
                      <input 
                        type="text" 
                        className="input" 
                        placeholder="e.g. admin@acme.com, 4111222233334444" 
                        value={maskRawValue}
                        onChange={e => setMaskRawValue(e.target.value)}
                        required
                      />
                    </div>
                    <button type="submit" disabled={maskingField} className="btn btn-secondary" style={{ width: '100%' }}>
                      {maskingField ? 'Processing...' : 'Run Anonymizer Masking'}
                    </button>
                  </form>

                  {maskedFieldResult && (
                    <div style={{ marginTop: '1.5rem', background: '#18181b', padding: '1rem', borderRadius: '8px', border: '1px solid #27272a' }}>
                      <div style={{ fontSize: '0.75rem', color: '#a1a1aa', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Anonymized Output:</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.875rem', color: '#f43f5e', fontWeight: 600 }}>{maskedFieldResult}</div>
                    </div>
                  )}
                </div>
              </div>

              {/* Active & Purged Sandboxes */}
              <div className="card" style={{ border: '1px solid #27272a' }}>
                <h3 style={{ marginBottom: '1rem' }}>Sandbox Deployment Orchestrator History</h3>
                <div className="table-container">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Environment Name</th>
                        <th>Created By</th>
                        <th>Expiry Target</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sandboxSessions.map((s) => (
                        <tr key={s.id}>
                          <td style={{ fontWeight: 600 }}>{s.name}</td>
                          <td style={{ fontSize: '0.8125rem' }}>{teamMembers.find(m => m.id === s.createdBy)?.name || 'System Auto-Job'}</td>
                          <td style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>
                            {new Date(s.expiresAt).toLocaleString()}
                          </td>
                          <td>
                            <span className={`badge ${s.status === 'ACTIVE' ? 'badge-green' : 'badge-red'}`}>
                              {s.status}
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                              {s.status === 'ACTIVE' ? (
                                <button 
                                  onClick={() => handleSandboxDestroy(s.id)}
                                  disabled={destroyingSandboxId === s.id}
                                  className="btn btn-danger btn-sm"
                                >
                                  {destroyingSandboxId === s.id ? 'Purging...' : '🗑| Destroy & Purge'}
                                </button>
                              ) : (
                                s.destructionCertificate && (
                                  <button 
                                    onClick={() => setViewingCertificate(s.destructionCertificate)}
                                    className="btn btn-secondary btn-sm"
                                  >
                                    📜 View Disposal Cert
                                  </button>
                                )
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Destruction Certificate Modal */}
              {viewingCertificate && (
                <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}>
                  <div className="card" style={{ maxWidth: '600px', width: '90%', maxHeight: '80vh', overflowY: 'auto', border: '1px solid #8b5cf6', background: '#09090b' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #27272a', paddingBottom: '0.5rem' }}>
                      <h3 style={{ color: '#a1a1aa', margin: 0 }}>Signed Compliance Certificate</h3>
                      <button onClick={() => setViewingCertificate(null)} style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', fontSize: '1.25rem' }}>&times;</button>
                    </div>
                    <pre style={{ fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap', color: '#10b981', background: '#020617', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                      {viewingCertificate}
                    </pre>
                    <button onClick={() => setViewingCertificate(null)} className="btn btn-secondary" style={{ width: '100%', marginTop: '1rem' }}>Close</button>
                  </div>
                </div>
              )}
            </div>
          )}

        </div>
      </main>
    </div>
  );
}
