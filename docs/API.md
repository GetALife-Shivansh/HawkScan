# API Specifications: HawkScan Autonomous Pentester & ApexPortal Target

This document outlines the API contracts for the HawkScan Pentester Control Plane (Port 9090) and the ApexPortal Corporate Target Application (Port 8000).

---

## 1. HawkScan Pentester Control Plane API (`http://127.0.0.1:9090`)

### 1.1 System & Health

#### `GET /api/health`
Returns the operational health and default target/repository configuration of HawkScan.
- **Response (200 OK)**:
  ```json
  {
    "status": "healthy",
    "service": "HawkScan AI Pentester Core",
    "version": "1.0.0",
    "default_target": "http://127.0.0.1:8000",
    "default_repo": "/Users/shivansh/Documents/HawkScan"
  }
  ```

### 1.2 Telemetry & Real-Time Streaming

#### `GET /api/stream` (Alias: `GET /api/scan/stream`)
Real-time Server-Sent Events (SSE) feed delivering live Phase 1-5 agent telemetry.
- **Media Type**: `text/event-stream`
- **Event Format**:
  ```json
  {
    "timestamp": 1729135800.12,
    "stage": "exploitation",
    "event_type": "log",
    "message": "Testing target endpoint /api/records/REC-9001 for cross-tenant access...",
    "details": {}
  }
  ```

### 1.3 Scan Execution & Dossier

#### `POST /api/scan/start`
Triggers an autonomous 5-phase penetration testing pipeline in a background task.
- **Request Body**:
  ```json
  {
    "target_url": "http://127.0.0.1:8000",
    "repo_path": "target_app"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "status": "started",
    "target_url": "http://127.0.0.1:8000",
    "repo_path": "target_app",
    "message": "HawkScan AI Pentester launched against http://127.0.0.1:8000 with repo target_app."
  }
  ```

#### `GET /api/scan/report`
Retrieves the latest penetration testing dossier, including verified breaches, discarded false positives, attack surface map, SARIF schema, Markdown report, and Git diff patches.
- **Response (200 OK)**:
  ```json
  {
    "status": "COMPLETED",
    "metadata": {
      "scan_id": "hawkscan-86d11c41",
      "target_url": "http://127.0.0.1:8000",
      "repo_path": "target_app",
      "duration_seconds": 0.2,
      "status": "COMPLETED"
    },
    "summary": {
      "verified_vulnerabilities": 2,
      "discarded_false_positives": 1,
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0,
      "live_endpoints_count": 14,
      "static_routes_count": 12
    },
    "verified_vulnerabilities": [
      {
        "vulnerability_id": "HAWKSCAN-BOLA-001",
        "title": "Broken Object Level Authorization (IDOR / BOLA)",
        "severity": "CRITICAL",
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "target_endpoint": "/api/records/REC-9001",
        "http_method": "GET",
        "status": "VERIFIED_EXPLOIT",
        "proof_of_concept": {
          "exploit_command": "curl -X GET 'http://127.0.0.1:8000/api/records/REC-9001' ...",
          "http_status": 200,
          "leaked_payload": { "id": "REC-9001", "owner_id": 2 },
          "evidence_summary": "Retrieved Record ID REC-9001..."
        }
      }
    ],
    "discarded_false_positives": [ ... ],
    "attack_surface": { ... },
    "sarif": { ... },
    "markdown_report": "# 🦅 HawkScan Autonomous ...",
    "code_patches": { ... }
  }
  ```

### 1.4 Artifact Exports

#### `GET /api/export/sarif`
Exports the OASIS SARIF 2.1.0 schema for direct ingestion by GitHub Security or CI/CD pipelines (`hawkscan-pentest-report.sarif`).
- **Media Type**: `application/sarif+json`

#### `GET /api/export/markdown`
Exports the executive Markdown pentesting report (`hawkscan-pentest-report.md`).
- **Media Type**: `text/markdown`

### 1.5 Target Application Control

#### `POST /api/target/toggle-security?target_url=...&secure=true|false`
Sets target application to Insecure (vulnerable) or Secure (defended) mode via admin API proxy.

#### `GET /api/target/security-status?target_url=...`
Queries target application's active patch states.

### 1.6 Process Termination

#### `POST /api/system/shutdown`
Cleanly terminates HawkScan and target background processes via process group signal dispatch.

---

## 2. ApexPortal Target Application API (`http://127.0.0.1:8000`)

### 2.1 Authentication

#### `POST /api/auth/login`
Authenticates a user and sets the `apex_session` cookie.
- **Request Body**:
  ```json
  {
    "email": "alice@apex.local",
    "password": "password123"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "status": "success",
    "message": "Authenticated as Alice Johnson",
    "user": {
      "id": 1,
      "email": "alice@apex.local",
      "full_name": "Alice Johnson",
      "department": "Corporate Strategy & M&A",
      "token": "apex_token_alice_sec_99182"
    }
  }
  ```

#### `GET /api/auth/me`
Retrieves the current authenticated profile.
- **Headers**: `Cookie: apex_session=...` OR `Authorization: Bearer <token>`

### 2.2 Confidential Records (IDOR / BOLA Endpoint)

#### `GET /api/records`
Returns records owned by the current authenticated user.

#### `GET /api/records/{record_id}`
Retrieves details for a specific confidential acquisition record.
- **Vulnerability**: When unpatched, fails to verify tenancy ownership. Any user can access other tenants' confidential portfolios (e.g. Alice requesting Bob's `REC-9001`).
- **Response when unpatched (200 OK - Breach Proven)**:
  ```json
  {
    "id": "REC-9001",
    "owner_id": 2,
    "title": "Q3 Strategic Acquisition & Valuation Portfolio",
    "category": "M&A Financial",
    "confidential_data": "CONFIDENTIAL: Proposed acquisition of FinTech Corp for $42,500,000 USD...",
    "amount": 42500000.0,
    "security_warning": "DATA_LEAK_CONFIRMED"
  }
  ```
- **Response when patched (403 Forbidden - Access Denied)**:
  ```json
  {
    "detail": "Access Denied: You do not have permission to view this confidential record"
  }
  ```

### 2.3 Search (SQLi Endpoint)

#### `GET /api/search?q={query}`
Searches corporate records.
- **Vulnerability**: When unpatched, concatenates input into raw SQL: `SELECT ... WHERE title LIKE '%{q}%'`.
- **Payload**: `' OR '1'='1`
- **Response when unpatched (200 OK - Breach Proven)**: Dumps all records across all tenants.
- **Response when patched (200 OK - Secure Filter)**: Evaluates query via parameterized ORM bindings without syntax breakout.

### 2.4 Security Administration & Dynamic Patching

#### `GET /api/admin/status`
Returns current patch states:
```json
{
  "idor_protection_enabled": false,
  "sqli_protection_enabled": false,
  "cors_protection_enabled": false
}
```

#### `POST /api/admin/toggle-patch?feature={idor|sqli|cors}&enabled={true|false}`
Dynamically enables or disables security fixes at runtime without restarting the server.
