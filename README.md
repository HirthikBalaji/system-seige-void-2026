# SovereignGuard 🛡️

## Amrita University Deployment Policy

SovereignGuard is deployed exclusively for **Amrita Vishwa Vidyapeetham** and integrates with **Cloudflare Access (Cloudflare Zero Trust)** for authentication.

### Access Policy

- Only authenticated users with an **@ch.amrita.edu** and **ch.students.amrita.edu** email address are allowed to access the platform.
- Email domain validation is performed immediately after successful Cloudflare Access authentication.
- Users whose email does **not** belong to the **@ch.amrita.edu** **ch.students.amrita.edu** domain are denied access before any application session is created.
- Every first-time authenticated user is automatically provisioned with the **DEVELOPER** role.
- Administrative privileges (**ORG_ADMIN**, **SECURITY_ADMIN**, **AUDITOR**, **SUPER_ADMIN**, and **SERVICE_ACCOUNT**) are assigned only by an existing administrator.
- The platform follows the **Principle of Least Privilege**, ensuring users receive only the permissions necessary to begin using the system.

---

# Architecture

SovereignGuard consists of two independent services:

- **Next.js Gateway**
  - Cloudflare Access authentication
  - Session management
  - User provisioning
  - RBAC enforcement
  - Dashboard UI
  - SQLite database

- **Backend Service**
  - Secrets Vault
  - TLS/SSL Certificate Lifecycle Management
  - Envelope Encryption
  - PostgreSQL Row-Level Security
  - Append-only Audit Logs
  - AI-powered Secret Exposure Scanner

The frontend authenticates users, provisions identities, and securely proxies requests to the backend using short-lived signed JWTs containing the verified identity, tenant, and role information.

---

# Security Architecture

## 1. Zero Trust Authentication

Authentication is handled exclusively through **Cloudflare Access**.

The gateway validates:

- JWT Signature
- Issuer
- Audience
- Expiration
- Not Before
- Identity Claims

Only identities with an **@ch.amrita.edu** **ch.students.amrita.edu** email address are permitted.

---

## 2. Session Management

After successful authentication:

- Secure server-side session created
- Database-backed session storage
- Secure cookies
  - HttpOnly
  - Secure (Production)
  - SameSite=Strict
  - 2 Hour Expiry

Administrators can revoke sessions at any time.

---

## 3. Identity Provisioning

When a user signs in for the first time:

- User account is automatically created
- Default organization is **Amrita Vishwa Vidyapeetham**
- Default role assigned is **DEVELOPER**
- User profile is synchronized from Cloudflare Access claims

Subsequent logins reuse the existing account.

---

## 4. Role-Based Access Control

Default Role

```
DEVELOPER
```

Elevated roles:

- ORG_ADMIN
- SECURITY_ADMIN
- AUDITOR
- SUPER_ADMIN
- SERVICE_ACCOUNT

Only administrators may assign elevated privileges.

Permissions are enforced by both:

- Gateway
- Backend

ensuring defense in depth.

---

## 5. Audit Trail

The backend maintains an append-only SHA-256 hash chain.

Features include:

- Immutable audit events
- Tamper detection
- Chain verification
- Append-only database triggers

Authentication events are also recorded separately within the gateway.

---

## 6. Secret Encryption

Secrets are protected using envelope encryption.

Each secret receives:

- Random Data Encryption Key (DEK)
- AES-256-GCM encryption
- DEK encrypted by a Master Key Encryption Key (KEK)

No encryption key is shared between secrets.

---

## AI Security Scanner

The backend includes an AI-powered credential exposure scanner.

Pipeline:

1. Regex detection
2. Entropy analysis
3. LLM verification
4. Severity classification
5. Remediation recommendation

Only masked snippets are transmitted to the LLM.

Complete secret values never leave the backend.

---

# Default User Flow

1. User authenticates using Cloudflare Access.
2. Email domain is validated.
3. Non-Amrita users are rejected.
4. First-time users are automatically provisioned.
5. User receives the **DEVELOPER** role.
6. Secure session is created.
7. Access to the dashboard is granted.
8. Backend independently verifies every proxied request.

---

# Authorization Policy

| User Type | Access |
|-----------|--------|
| @am.amrita.edu | ✅ Allowed |
| Gmail | ❌ Denied |
| Outlook | ❌ Denied |
| Yahoo | ❌ Denied |
| Any External Domain | ❌ Denied |

---

# Least Privilege Model

Every authenticated user starts as:

```
DEVELOPER
```

Administrative privileges require explicit approval and assignment.

This minimizes unnecessary privilege escalation while allowing immediate access for legitimate users.

---

# Security Principles

- Zero Trust Authentication
- Cloudflare Access Integration
- Strict Email Domain Validation
- Least Privilege Access
- Automatic Developer Provisioning
- Secure Session Management
- Backend Authorization Verification
- Row-Level Security
- Envelope Encryption
- Hash-Chained Audit Logs
- Defense in Depth
- Tamper-Evident Logging
- AI-Assisted Secret Exposure Detection

---

# Deployment Summary

SovereignGuard is intended for internal use within **Amrita Vishwa Vidyapeetham**.

The deployment guarantees that:

- Only **@ch.amrita.edu** **ch.students.amrita.edu** users can authenticate.
- Every newly authenticated user automatically receives the **DEVELOPER** role.
- Administrative roles require explicit approval.
- All backend operations remain protected by independent authorization checks, encryption, audit logging, and PostgreSQL Row-Level Security.
