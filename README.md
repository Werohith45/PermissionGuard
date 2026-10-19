
# PermissionGuard — Permission Lifecycle & Permission Creep Detection System

> **A realistic, functional cybersecurity engineering prototype built for access governance, permission lifecycle control, and explainable permission creep detection.**


## 1. Problem Statement & Innovation Direction

In enterprise environments, user access permissions inevitably accumulate over time through project rotations, ad-hoc task assignments, emergency debug requests, and organizational shifts. This phenomenon, known as **Permission Creep**, leaves accounts with permissions far broader than necessary, violating the **Principle of Least Privilege (PoLP)** and creating severe privilege-escalation and lateral-movement risks.

### The Innovation Direction
PermissionGuard provides an end-to-end access governance engine that:
1. **Tracks the full permission lifecycle**: Role-based access (RBAC) baseline → Access Request → Reasoned Approval → Active Monitoring → Inactivity Detection → Revalidation → Automatic Expiry.
2. **Transparent Rules-Based Detection Engine**: Evaluates permission creep using 8 clear cybersecurity rules with deterministic risk scoring (0–100) and actionable explanations instead of opaque black-box AI scores.
3. **60-Day Inactivity Governance**: Unused permissions transition to an `INACTIVE` state requiring managerial revalidation rather than abrupt account deletion.
4. **Immutable Audit Trails**: Captures file operations, permission transitions, version updates, and administrative decisions in a relational audit log.
5. **Formal Executive Audit Reports**: Generates downloadable PDF reports with executive summaries, metrics tables, and remediation guidance.


## 2. Core Architecture & Technology Stack

```
permissionguard/
│
├── frontend/                     # Clean, responsive single-page application
│   ├── index.html                # App shell, navigation sidebar, and modals
│   └── static/
│       ├── css/main.css          # Professional cybersecurity operations styling
│       └── js/app.js             # Client SPA router, Chart.js views, and API calls
│
├── backend/
│   ├── api/
│   │   └── main.py               # REST API endpoints & static SPA delivery
│   ├── models/
│   │   └── schemas.py            # Pydantic request & response models
│   ├── services/
│   │   ├── audit_service.py      # Audit logging & notification service
│   │   └── report_generator.py   # ReportLab PDF audit generator
│   ├── detectors/
│   │   └── permission_detector.py# Rules-based Permission Creep Detection Engine
│   ├── database/
│   │   └── schema.py             # SQLite schema (14 tables, foreign keys, indexes)
│   ├── auth/
│   │   └── security.py           # PBKDF2 password hashing, JWT tokens, RBAC guard
│   └── utils/
│       └── config.py             # Environment configurations & reference time
│
├── scripts/
│   └── seed_database.py          # Synthetic dataset generator (18 users, 22 files, 65+ perms)
├── tests/
│   └── test_permissionguard.py   # Automated pytest suite (100% passing)
├── reports/                      # Generated PDF security audit reports
├── README.md
└── .env.example
```

### Technologies Used
- **Backend**: Python 3.12, FastAPI, Uvicorn, Pydantic v2
- **Security & Auth**: JWT (PyJWT), PBKDF2-SHA256 password hashing, RBAC middleware
- **Database**: SQLite3 (designed for easy migration to PostgreSQL) with Foreign Key constraints & WAL mode
- **Reporting**: ReportLab PDF Generation engine
- **Frontend**: Clean vanilla JavaScript (ES6+), CSS3, HTML5, Chart.js (interactive telemetry visualizations)
- **Testing**: Pytest & FastAPI TestClient


## 3. Database Schema (14 Relational Tables)

1. `departments`: Engineering, Finance, Human Resources, Security, Operations, Marketing.
2. `roles`: System Administrator, Department Manager, Developer, Finance, HR, Analyst, Intern.
3. `users`: Enterprise user accounts with hashed passwords and departmental assignments.
4. `resources`: Protected assets with sensitivity levels (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
5. `role_permissions`: Least-privilege baseline permissions per role and department.
6. `permissions`: Grants with lifecycle status (`ACTIVE`, `INACTIVE`, `REVALIDATED`, `EXPIRED`, `REVOKED`), timestamps, and extension counters.
7. `permission_requests`: Request workflows with duration, justification, and approval status (`PENDING`, `APPROVED`, `REJECTED`).
8. `permission_history`: Immutable timeline of every transition on a permission.
9. `access_events`: Synthetic file access telemetry (`OPEN`, `READ`, `EDIT`, `DOWNLOAD`, `SHARE`).
10. `resource_versions`: Document version history (`v1.0`, `v1.1`, `v1.2`) with author and change summary.
11. `security_findings`: Creep engine outputs with deterministic risk scores and remediation actions.
12. `audit_logs`: Enterprise-grade audit trail with actor, action, timestamp, IP, and reference codes.
13. `notifications`: In-app security alerts and workflow notifications.
14. `system_settings`: Configurable policy thresholds (inactivity window, grant durations, risk boundaries).


## 4. Detection Engine & Risk Scoring Model

The `permission_detector` module evaluates active grants against 8 transparent rules:

| Rule ID | Detection Policy | Risk Score | Explanation |
| :--- | :--- | :---: | :--- |
| **RULE 1** | **Role Mismatch** | `+30` | Permission is outside the user's role profile / department baseline |
| **RULE 2** | **Inactivity > 60 Days** | `+20` | Zero file usage recorded during the inactivity threshold |
| **RULE 3** | **Excessive Permission Level** | `+20` | User holds EDIT/WRITE where role baseline permits only READ |
| **RULE 4** | **Expired Temporary Grant** | `+25` | Permission has reached expiry date but requires lifecycle audit |
| **RULE 5** | **Repeated Temporary Access** | `+10` | Identity holds 3 or more temporary permission allocations |
| **RULE 6** | **Repeated Extension** | `+15` | Permission has been renewed/extended 2 or more times |
| **RULE 7** | **Cross-Department Sprawl** | `+25` | User holds permissions across 3 or more distinct departments |
| **RULE 8** | **High-Impact Sensitive Access**| `+20` | High-impact WRITE/EDIT access on `CONFIDENTIAL` or `RESTRICTED` resources |

### Transparent Severity Boundaries
- **0 – 24**: `LOW`
- **25 – 49**: `MEDIUM`
- **50 – 74**: `HIGH`
- **75 – 100**: `CRITICAL` (capped at 100)

*Every finding displays the exact arithmetic breakdown of points added.*


## 5. Five Pre-Configured Demonstration Scenarios

| Scenario | User & Role | Resource & Sensitivity | Permission | Finding & Expected Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **1. Inactivity Dormancy** | Arun Kumar (Developer) | `Financial_Report_Q3.xlsx` | READ | Last used 70 days ago → **Flagged INACTIVE (Medium Risk)**. Account preserved, revalidation required. |
| **2. Role Mismatch** | Rohan Joshi (Intern) | `Security_Audit_Report.pdf` | EDIT | Engineering intern has EDIT on Security audit doc → **HIGH RISK (Role Mismatch + Excessive Level)**. |
| **3. Automatic Expiry** | Siddharth Nair (Analyst) | `Vendor_Contracts_2026.pdf` | READ | Expiry was yesterday → **Automatically transitioned to EXPIRED**. History preserved. |
| **4. Repeated Extension** | Arun Kumar (Developer) | `Database_Disaster_Recovery.pdf`| EDIT | Extended 3 times → **MEDIUM/HIGH RISK (Repeated Extension Rule)**. |
| **5. High-Impact Sensitive** | Rohan Joshi (Intern) | `Executive_Payroll_2026.xlsx` | EDIT | Non-permanent intern holds edit access on RESTRICTED HR payroll → **CRITICAL RISK**. |


## 6. Demo Accounts & Credentials

*All demo accounts use the standard demonstration password:* **`DemoPassword123!`**

| Username | Role | Department | Demo Purpose |
| :--- | :--- | :--- | :--- |
| **`admin`** | System Administrator | Security | Full system oversight, governance approvals, settings, and demo reset |
| **`manager`** | Department Manager | Operations | Access reviews, approval workflows, and revalidation |
| **`developer`** | Developer | Engineering | Technical resources, version commits, and access requests |
| **`finance`** | Finance | Finance | Financial reports, budget management, and ledger access |
| **`hr`** | HR | Human Resources | Employee records, onboarding, and payroll governance |
| **`intern`** | Intern | Engineering | Strictly restricted access, role mismatch testing, and request submissions |


## 7. Step-by-Step Presentation Demonstration Flow

1. **Sign In**: Launch the console at `http://127.0.0.1:8000` and click the `admin (Admin)` button to log in.
2. **Dashboard Overview**: Inspect the 6 metric cards, departmental distribution chart, lifecycle status doughnut chart, and priority risk findings.
3. **Approve an Access Request**:
   - Navigate to **Access Requests**.
   - Inspect request **`REQ-1024`** submitted by intern Rohan Joshi for `Project_Architecture.pdf`.
   - Click **Approve** and enter justification. Notice the status turns to `APPROVED` and a corresponding `ACTIVE` permission is provisioned.
4. **Inspect Active Permissions & Timeline**:
   - Navigate to **Permissions** to observe the newly created grant.
   - Click **Timeline** to view the end-to-end historical audit log for that permission.
5. **Inspect Explainable Security Finding**:
   - Navigate to **Security Findings**.
   - Click **Inspect** on finding **`FND-0005`** (Intern with EDIT on `Executive_Payroll_2026.xlsx`).
   - Show the judges the transparent score calculation: `+30 Role Mismatch`, `+20 Sensitive Resource EDIT`.
6. **Revalidate Inactive Permission (60-Day Rule)**:
   - Navigate to **Access Reviews**.
   - Show `Financial_Report_Q3.xlsx` flagged as **INACTIVE** due to >65 days of dormancy.
   - Click **Revalidate**, enter *"Still required for monthly financial reconciliation"*, and confirm. Observe the permission transition to `REVALIDATED`.
7. **Verify Automatic Expiry Without Account Deletion**:
   - Filter **Permissions** by status `EXPIRED`.
   - Highlight that the temporary access was revoked, but the user's account remains active.
8. **Inspect Resource Version History**:
   - Navigate to **Resources & Files** and click on `Project_Architecture.pdf`.
   - Show the version history (`v1.0`, `v1.1`, `v1.2`) with exact modifier names and change notes.
   - Click **+ Publish New Version** to demonstrate live version creation.
9. **Inspect Immutable Audit Logs**:
   - Navigate to **Audit Logs** to view the chronological trail of logins, approvals, revalidations, and file telemetry.
10. **Export Formal PDF Audit Report**:
    - Navigate to **Audit Reports** and click **📥 Download Formal Audit PDF**.
    - Open the generated PDF showing executive metrics, tables of critical findings, and remediation advice.
11. **Demo Data Reset**:
    - Under **Settings**, click **Reset All Demo Data** to restore the initial test state.


## 8. Installation & Running Locally

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Modern web browser (Chrome, Edge, Firefox)

### Setup Instructions
```bash
# 1. Clone or open the project folder
cd "d:\HACKOTON\SECURITY PROJECT"

# 2. Install required dependencies
pip install fastapi uvicorn pydantic python-multipart pyjwt passlib[bcrypt] email-validator pytest httpx reportlab

# 3. Initialize and seed the synthetic database
python -c "from backend.database.schema import init_db; from scripts.seed_database import seed_demo_database; init_db(); seed_demo_database()"

# 4. Start the application server
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser and navigate to: **`http://127.0.0.1:8000`**

### Running the Test Suite
```bash
python -m pytest tests/test_permissionguard.py -v
```

## 9. Important Prototype Limitations

- **Synthetic Telemetry**: Resource files and user access telemetry are synthetic simulations for safe demonstration and do not touch real enterprise file systems.
- **Standalone IAM**: This is a security engineering prototype and does not automatically configure live cloud IAM providers (such as AWS IAM, Okta, or Azure AD) without external connector plugins.
- **Single-Node SQLite**: Built with SQLite for zero-setup local demonstration; the data access layer is structured for straightforward migration to PostgreSQL in production.


## 10. Future Engineering Scope

1. **Enterprise Identity Connectors**: SCIM and SAML 2.0 integration with Okta, Ping Identity, and Microsoft Entra ID.
2. **SIEM / SOAR Forwarding**: Real-time event streaming into Splunk, Microsoft Sentinel, and Elastic Security via CEF/Syslog.
3. **Continuous Access Evaluation (CAE)**: Real-time session revocation upon immediate role changes.
4. **Cloud Storage Adapters**: Direct read/write auditing on AWS S3 buckets, Google Cloud Storage, and SharePoint.
5. **Policy-as-Code Integration**: Open Policy Agent (OPA) / Rego policy evaluation for automated compliance enforcement.
=======
# PermissionGuard
>>>>>>> 6b243c9eb94f197b890787c12eeddc3e08cb1259
