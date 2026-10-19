import sqlite3
import os
from contextlib import contextmanager
from backend.utils.config import DB_PATH

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = dict_factory
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Departments table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        );
        """)

        # 2. Roles table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            department_id TEXT,
            FOREIGN KEY (department_id) REFERENCES departments(id)
        );
        """)

        # 3. Users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role_id TEXT NOT NULL,
            department_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, INACTIVE
            created_at TEXT NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        );
        """)

        # 4. Resources table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL, -- FILE, REPOSITORY, DATASET, DOCUMENT
            department_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            sensitivity TEXT NOT NULL, -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
            created_at TEXT NOT NULL,
            current_version TEXT NOT NULL DEFAULT 'v1.0',
            status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, ARCHIVED, RESTRICTED
            FOREIGN KEY (department_id) REFERENCES departments(id),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """)

        # 5. Role Default Allowed Resources/Scope (RBAC Baseline)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id TEXT NOT NULL,
            department_id TEXT NOT NULL,
            max_permission TEXT NOT NULL, -- READ, WRITE, EDIT
            allowed_sensitivity TEXT NOT NULL, -- comma separated e.g. PUBLIC,INTERNAL,CONFIDENTIAL
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        );
        """)

        # 6. Permissions Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            permission_type TEXT NOT NULL, -- READ, WRITE, EDIT, DOWNLOAD, SHARE
            start_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            reason TEXT NOT NULL,
            approver_id TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, REVALIDATED, EXPIRED, REVOKED
            last_used_at TEXT,
            extension_count INTEGER NOT NULL DEFAULT 0,
            revalidation_due_date TEXT,
            revalidation_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id),
            FOREIGN KEY (approver_id) REFERENCES users(id)
        );
        """)

        # 7. Permission Requests Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS permission_requests (
            id TEXT PRIMARY KEY,
            request_code TEXT NOT NULL UNIQUE, -- e.g. REQ-1024
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            permission_type TEXT NOT NULL,
            duration_days INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, MORE_INFO_REQUESTED
            reviewed_by TEXT,
            reviewed_at TEXT,
            review_comments TEXT,
            permission_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id),
            FOREIGN KEY (reviewed_by) REFERENCES users(id),
            FOREIGN KEY (permission_id) REFERENCES permissions(id)
        );
        """)

        # 8. Permission History (Timeline of changes)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS permission_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            permission_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            event_type TEXT NOT NULL, -- REQUESTED, APPROVED, REJECTED, GRANTED, ACCESSED, EXTENDED, INACTIVE_FLAGGED, REVALIDATED, EXPIRED, REVOKED
            details TEXT NOT NULL,
            performed_by TEXT, -- user_id or SYSTEM
            created_at TEXT NOT NULL,
            FOREIGN KEY (permission_id) REFERENCES permissions(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id)
        );
        """)

        # 9. Access Events (File Activity Tracking)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            action TEXT NOT NULL, -- OPEN, READ, EDIT, DOWNLOAD, SHARE, UPLOAD, RENAME, VERSION_UPDATE
            ip_address TEXT NOT NULL,
            device TEXT NOT NULL,
            result TEXT NOT NULL, -- SUCCESS, DENIED
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id)
        );
        """)

        # 10. Resource Versions Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS resource_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resource_id TEXT NOT NULL,
            version_number TEXT NOT NULL, -- e.g. v1.0, v1.1
            modified_by TEXT NOT NULL,
            action TEXT NOT NULL,
            change_summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (resource_id) REFERENCES resources(id),
            FOREIGN KEY (modified_by) REFERENCES users(id)
        );
        """)

        # 11. Security Findings (Permission Creep Detector Output)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id TEXT PRIMARY KEY,
            finding_code TEXT NOT NULL UNIQUE, -- e.g. FND-0042
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            permission_id TEXT,
            rule_id TEXT NOT NULL, -- e.g. RULE_ROLE_MISMATCH, RULE_INACTIVE_60D, etc.
            risk_level TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
            risk_score INTEGER NOT NULL,
            what_happened TEXT NOT NULL,
            why_risky TEXT NOT NULL,
            evidence TEXT NOT NULL, -- JSON or formatted string
            recommended_action TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN', -- OPEN, REVALIDATED, REVOKED, DISMISSED
            detected_at TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT,
            resolution_notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id),
            FOREIGN KEY (permission_id) REFERENCES permissions(id),
            FOREIGN KEY (resolved_by) REFERENCES users(id)
        );
        """)

        # 12. Audit Logs Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT,
            action TEXT NOT NULL,
            resource_id TEXT,
            result TEXT NOT NULL, -- SUCCESS, FAILURE, WARNING
            reason TEXT,
            performed_by TEXT NOT NULL,
            reference_id TEXT,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resource_id) REFERENCES resources(id)
        );
        """)

        # 13. System Notifications
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT, -- NULL for all admins or targeted user
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL, -- EXPIRY_WARNING, INACTIVITY_ALERT, REQUEST_PENDING, HIGH_RISK, EXPIRED_AUTO
            link TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)

        # 14. System Settings
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT
        );
        """)

        # Indexes for fast lookup and relational integrity
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_perm_user ON permissions(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_perm_resource ON permissions(resource_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_perm_status ON permissions(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON security_findings(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_risk ON security_findings(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_user_res ON access_events(user_id, resource_id);")
