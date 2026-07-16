# SovereignGuard 🛡️

SovereignGuard is a highly secure, enterprise-grade multi-tenant secrets and TLS/SSL certificate lifecycle control plane. It integrates directly with **Cloudflare Access (Cloudflare Zero Trust)** for identity verification and implements strict application-level RBAC, tenant isolation, dual-protected audit logs, and AI-powered credentials exposure scanning.

---

## 🚀 AI / LLM Integration Disclosure (BYOK)

As required by the System Siege problem guidelines, the AI-powered scanner utilizes:
- **LLM Provider**: NVIDIA NIM (NVIDIA Inference Microservices)
- **Model Version**: `meta/llama-3.3-70b-instruct`
- **Purpose**: Automate deep security scanning of code scripts, configuration files, and files to detect hardcoded API keys, database connection strings, passwords, and private certificates.
- **Key Configuration**: Provide your key via the `NVIDIA_API_KEY` environment variable. A local heuristic-based regex fallback is automatically used if the API key is not present.

---

## 🔒 Security Architecture

1. **Zero Trust Authentication**:
   - Single Source of Truth: Cloudflare Access.
   - Strictly validates `CF-Access-Jwt-Assertion` signatures against Cloudflare's JWKS certificates.
   - Verifies issuer (`iss`), audience (`aud`), expiration (`exp`), and nbf claims.
   - Extracts identity claims (Email, Subject, Groups, Identity Provider).
   
2. **Session Management**:
   - Validates Cloudflare assertion to create a secure, server-side database-backed Session.
   - Uses strict browser cookies: `HttpOnly`, `Secure` (production), `SameSite=Strict`, `2h MaxAge`.
   - Allows administrators to revoke sessions in real-time.
   
3. **Strict Multi-Tenant Isolation**:
   - Users are dynamically resolved to a Tenant (organization) on first login via Cloudflare groups (`tenant-<org>`), Identity Provider name, or email domain.
   - Every database query automatically filters by `tenantId`. Users cannot access resources across boundaries.
   
4. **Role-Based Access Control (RBAC)**:
   - Defined roles: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ADMIN`, `DEVELOPER`, `AUDITOR`, `READ_ONLY`, `SERVICE_ACCOUNT`.
   - Checked at the API handler level before executing any read/write operations.
   
5. **Dual-Protected Audit Logging**:
   - **Hash Chaining**: Each audit record is cryptographically linked to the previous record using a SHA-256 hash.
   - **HMAC Signatures**: Each record's hash is signed with `AUDIT_HMAC_SECRET` (HMAC-SHA256).
   - Tamper Evidence: On-demand validation scans the database chain and reports any modifications, deletions, or insertions.

6. **Secrets Encryption**:
   - Encrypts vault values at rest using AES-256-GCM.

---

## 🛠️ Getting Started

### 1. Prerequisites
- Node.js (v18+)
- npm

### 2. Environment Setup
Configure the environment variables in a `.env` file in the root directory:

```env
DATABASE_URL="file:./dev.db"

# AES-256 encryption key (32-character string/hex)
ENCRYPTION_SECRET="0123456789abcdef0123456789abcdef"

# Secret key for signing audit logs
AUDIT_HMAC_SECRET="super-secure-hmac-signing-key-for-audit-logs-validation"

# Local Developer Sandbox switch
NEXT_PUBLIC_MOCK_CF_ACCESS="true"
CF_TEAM_DOMAIN="system-seige.cloudflareaccess.com"
CF_AUDIENCE_TAG="mock-audience-tag-for-cloudflare-access"

# NVIDIA NIM LLM API configuration
NVIDIA_API_KEY="your-nvidia-nim-api-key-here"
```

### 3. Database Initialization
Generate the Prisma Client and run the SQLite migrations:
```bash
npx prisma generate
npx prisma migrate dev --name init
```

### 4. Run Development Server
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the landing page.
- In **Sandbox Mode** (`NEXT_PUBLIC_MOCK_CF_ACCESS=true`), you will see the **Developer Sandbox Login Portal**. Select any pre-defined persona (e.g. Org Admin, Developer, Auditor, or a different organization) to test RBAC and tenant isolation instantly.
- In **Production Mode**, you will be redirected to authenticate through Cloudflare Access.
