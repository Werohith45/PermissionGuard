import json
import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Optional, List

from backend.database.schema import get_db, init_db
from backend.auth.security import (
    verify_password, create_access_token, get_current_user, require_roles
)
from backend.models.schemas import (
    LoginRequest, Token, PermissionRequestCreate, RequestReview,
    PermissionRevalidate, PermissionExtend, FindingResolution,
    SystemSettingsUpdate, SimulateActivityRequest, ResourceCreate, ResourceUpdate
)
from backend.services.audit_service import (
    log_audit_event, record_permission_history, create_notification, get_system_settings
)
from backend.detectors.permission_detector import run_permission_creep_detector
from backend.services.report_generator import generate_pdf_audit_report
from scripts.seed_database import seed_demo_database

app = FastAPI(
    title="PermissionGuard Security API",
    description="Permission Lifecycle & Rules-Based Permission Creep Detection System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- AUTHENTICATION -----------------

@app.post("/api/auth/login", response_model=Token)
def login(credentials: LoginRequest):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.*, r.name as role_name, d.name as department_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN departments d ON u.department_id = d.id
            WHERE u.email = ? OR u.username = ?
        """, (credentials.username, credentials.username))
        user = cursor.fetchone()

        if not user or not verify_password(credentials.password, user["password_hash"]):
            log_audit_event(
                action="LOGIN_FAILED",
                performed_by=credentials.username,
                result="FAILURE",
                reason="Invalid credentials supplied",
                ip_address="192.168.1.50"
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user["status"] != "ACTIVE":
            raise HTTPException(status_code=403, detail="Account is suspended or inactive")

        token = create_access_token(data={"sub": user["id"], "role": user["role_name"]})

        log_audit_event(
            action="LOGIN",
            performed_by=user["id"],
            user_id=user["id"],
            result="SUCCESS",
            reason="User session authenticated",
            reference_id=f"SES-{user['id']}"
        )

        user_safe = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role_id": user["role_id"],
            "role_name": user["role_name"],
            "department_id": user["department_id"],
            "department_name": user["department_name"],
            "status": user["status"]
        }
        return {"access_token": token, "token_type": "bearer", "user": user_safe}

@app.get("/api/auth/me")
def get_current_user_profile(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role_id": user["role_id"],
        "role_name": user["role_name"],
        "department_id": user["department_id"],
        "department_name": user["department_name"],
        "status": user["status"]
    }

# ----------------- DASHBOARD METRICS -----------------

@app.get("/api/dashboard")
def get_dashboard_metrics(current_user: dict = Depends(get_current_user)):
    # Run detector to ensure freshness
    run_permission_creep_detector()

    with get_db() as conn:
        cursor = conn.cursor()

        # Top summary counters
        cursor.execute("SELECT count(*) as cnt FROM users WHERE status = 'ACTIVE'")
        total_users = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'ACTIVE'")
        active_permissions = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM permission_requests WHERE status = 'PENDING'")
        pending_requests = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'INACTIVE'")
        inactive_permissions = cursor.fetchone()["cnt"]

        # Expiring soon: active permissions with expiry <= 7 days from now (2026-10-19)
        cursor.execute("""
            SELECT count(*) as cnt FROM permissions 
            WHERE status = 'ACTIVE' 
              AND date(expiry_date) <= date('2026-10-19', '+7 days')
              AND date(expiry_date) >= date('2026-10-19')
        """)
        expiring_soon = cursor.fetchone()["cnt"]

        cursor.execute("""
            SELECT count(*) as cnt FROM security_findings 
            WHERE status = 'OPEN' AND risk_level IN ('HIGH', 'CRITICAL')
        """)
        high_risk_findings = cursor.fetchone()["cnt"]

        # Chart 1: Permissions by Department
        cursor.execute("""
            SELECT d.name as department, count(p.id) as count
            FROM departments d
            LEFT JOIN resources r ON r.department_id = d.id
            LEFT JOIN permissions p ON p.resource_id = r.id AND p.status IN ('ACTIVE', 'INACTIVE')
            GROUP BY d.name
            ORDER BY count DESC
        """)
        perms_by_dept = cursor.fetchall()

        # Chart 2: Permission Status Breakdown
        cursor.execute("""
            SELECT status, count(*) as count
            FROM permissions
            GROUP BY status
        """)
        status_breakdown = {r["status"]: r["count"] for r in cursor.fetchall()}

        # Chart 3: Risk Distribution
        cursor.execute("""
            SELECT risk_level, count(*) as count
            FROM security_findings
            WHERE status = 'OPEN'
            GROUP BY risk_level
        """)
        risk_dist = {r["risk_level"]: r["count"] for r in cursor.fetchall()}

        # Chart 4: Permission Lifecycle Events Over Time (Last 14 days)
        cursor.execute("""
            SELECT substr(timestamp, 1, 10) as day, count(*) as count
            FROM audit_logs
            WHERE action LIKE 'PERMISSION_%' OR action LIKE 'ACCESS_%'
            GROUP BY day
            ORDER BY day DESC
            LIMIT 10
        """)
        events_timeline = cursor.fetchall()

        # Chart 5: Top Resources with Excessive Access (Most active/inactive permissions)
        cursor.execute("""
            SELECT r.id, r.name, r.sensitivity, d.name as department_name, count(p.id) as perm_count
            FROM resources r
            JOIN departments d ON r.department_id = d.id
            LEFT JOIN permissions p ON p.resource_id = r.id AND p.status IN ('ACTIVE', 'INACTIVE')
            GROUP BY r.id
            ORDER BY perm_count DESC
            LIMIT 5
        """)
        top_resources = cursor.fetchall()

        # Recent high risk alerts
        cursor.execute("""
            SELECT f.id, f.finding_code, f.risk_level, f.risk_score, f.what_happened, f.detected_at,
                   u.full_name, u.username, res.name as resource_name
            FROM security_findings f
            JOIN users u ON f.user_id = u.id
            JOIN resources res ON f.resource_id = res.id
            WHERE f.status = 'OPEN' AND f.risk_level IN ('HIGH', 'CRITICAL')
            ORDER BY f.risk_score DESC, f.detected_at DESC
            LIMIT 5
        """)
        recent_critical = cursor.fetchall()

        return {
            "summary": {
                "total_users": total_users,
                "active_permissions": active_permissions,
                "pending_requests": pending_requests,
                "inactive_permissions": inactive_permissions,
                "expiring_soon": expiring_soon,
                "high_risk_findings": high_risk_findings
            },
            "charts": {
                "permissions_by_department": perms_by_dept,
                "status_breakdown": status_breakdown,
                "risk_distribution": risk_dist,
                "events_timeline": list(reversed(events_timeline)),
                "top_resources": top_resources
            },
            "recent_findings": recent_critical
        }

# ----------------- USERS -----------------

@app.get("/api/users")
def get_users(
    search: Optional[str] = None,
    department: Optional[str] = None,
    role: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT u.id, u.username, u.email, u.full_name, u.status, u.created_at,
                   r.id as role_id, r.name as role_name,
                   d.id as department_id, d.name as department_name,
                   (SELECT count(*) FROM permissions WHERE user_id = u.id AND status = 'ACTIVE') as active_perms,
                   (SELECT count(*) FROM permissions WHERE user_id = u.id AND status = 'INACTIVE') as inactive_perms,
                   (SELECT count(*) FROM security_findings WHERE user_id = u.id AND status = 'OPEN') as open_findings,
                   (SELECT coalesce(max(risk_score), 0) FROM security_findings WHERE user_id = u.id AND status = 'OPEN') as max_risk_score
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN departments d ON u.department_id = d.id
            WHERE 1=1
        """
        params = []
        if search:
            query += " AND (u.full_name LIKE ? OR u.email LIKE ? OR u.username LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param])
        if department:
            query += " AND d.name = ?"
            params.append(department)
        if role:
            query += " AND r.name = ?"
            params.append(role)
            
        query += " ORDER BY max_risk_score DESC, u.full_name ASC"
        cursor.execute(query, params)
        return cursor.fetchall()

@app.get("/api/users/{user_id}")
def get_user_detail(user_id: str, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.*, r.name as role_name, d.name as department_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN departments d ON u.department_id = d.id
            WHERE u.id = ?
        """, (user_id,))
        user_info = cursor.fetchone()
        if not user_info:
            raise HTTPException(status_code=404, detail="User not found")

        # Permissions held by user
        cursor.execute("""
            SELECT p.*, res.name as resource_name, res.type as resource_type,
                   res.sensitivity, d.name as resource_dept_name,
                   coalesce(f.risk_score, 0) as risk_score,
                   coalesce(f.risk_level, 'LOW') as risk_level
            FROM permissions p
            JOIN resources res ON p.resource_id = res.id
            JOIN departments d ON res.department_id = d.id
            LEFT JOIN security_findings f ON f.permission_id = p.id AND f.status = 'OPEN'
            WHERE p.user_id = ?
            ORDER BY risk_score DESC, p.start_date DESC
        """, (user_id,))
        permissions = cursor.fetchall()

        # Access Requests by user
        cursor.execute("""
            SELECT req.*, res.name as resource_name, res.sensitivity,
                   rev.full_name as reviewer_name
            FROM permission_requests req
            JOIN resources res ON req.resource_id = res.id
            LEFT JOIN users rev ON req.reviewed_by = rev.id
            WHERE req.user_id = ?
            ORDER BY req.created_at DESC
        """, (user_id,))
        requests = cursor.fetchall()

        # Recent File Activity
        cursor.execute("""
            SELECT a.*, res.name as resource_name
            FROM access_events a
            JOIN resources res ON a.resource_id = res.id
            WHERE a.user_id = ?
            ORDER BY a.created_at DESC LIMIT 20
        """, (user_id,))
        activity = cursor.fetchall()

        # Security Findings for this user
        cursor.execute("""
            SELECT f.*, res.name as resource_name
            FROM security_findings f
            JOIN resources res ON f.resource_id = res.id
            WHERE f.user_id = ? AND f.status = 'OPEN'
            ORDER BY f.risk_score DESC
        """, (user_id,))
        findings = cursor.fetchall()

        # Audit events performed on/by this user
        cursor.execute("""
            SELECT * FROM audit_logs
            WHERE user_id = ? OR performed_by = ?
            ORDER BY timestamp DESC LIMIT 20
        """, (user_id, user_id))
        audit = cursor.fetchall()

        return {
            "profile": user_info,
            "permissions": permissions,
            "requests": requests,
            "activity": activity,
            "findings": findings,
            "audit_trail": audit
        }

# ----------------- RESOURCES -----------------

@app.get("/api/resources")
def get_resources(
    search: Optional[str] = None,
    department: Optional[str] = None,
    sensitivity: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT r.*, d.name as department_name, u.full_name as owner_name,
                   (SELECT count(*) FROM permissions WHERE resource_id = r.id AND status = 'ACTIVE') as active_grants,
                   (SELECT count(*) FROM permissions WHERE resource_id = r.id AND status = 'INACTIVE') as inactive_grants,
                   (SELECT count(*) FROM security_findings WHERE resource_id = r.id AND status = 'OPEN') as open_findings
            FROM resources r
            JOIN departments d ON r.department_id = d.id
            JOIN users u ON r.owner_id = u.id
            WHERE 1=1
        """
        params = []
        if search:
            query += " AND (r.name LIKE ? OR r.type LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s])
        if department:
            query += " AND d.name = ?"
            params.append(department)
        if sensitivity:
            query += " AND r.sensitivity = ?"
            params.append(sensitivity)

        query += " ORDER BY r.name ASC"
        cursor.execute(query, params)
        return cursor.fetchall()

@app.get("/api/resources/{resource_id}")
def get_resource_detail(resource_id: str, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, d.name as department_name, u.full_name as owner_name, u.email as owner_email
            FROM resources r
            JOIN departments d ON r.department_id = d.id
            JOIN users u ON r.owner_id = u.id
            WHERE r.id = ?
        """, (resource_id,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="Resource not found")

        # Who can access it?
        cursor.execute("""
            SELECT p.*, u.full_name, u.username, u.email, ro.name as role_name,
                   d.name as user_department, app.full_name as approver_name
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN departments d ON u.department_id = d.id
            LEFT JOIN users app ON p.approver_id = app.id
            WHERE p.resource_id = ?
            ORDER BY p.status ASC, p.expiry_date DESC
        """, (resource_id,))
        accessors = cursor.fetchall()

        # Version History
        cursor.execute("""
            SELECT rv.*, u.full_name as modifier_name
            FROM resource_versions rv
            JOIN users u ON rv.modified_by = u.id
            WHERE rv.resource_id = ?
            ORDER BY rv.created_at DESC
        """, (resource_id,))
        versions = cursor.fetchall()

        # Access Activity log
        cursor.execute("""
            SELECT ae.*, u.full_name as user_name
            FROM access_events ae
            JOIN users u ON ae.user_id = u.id
            WHERE ae.resource_id = ?
            ORDER BY ae.created_at DESC LIMIT 30
        """, (resource_id,))
        activity = cursor.fetchall()

        # Findings on this resource
        cursor.execute("""
            SELECT f.*, u.full_name as user_name
            FROM security_findings f
            JOIN users u ON f.user_id = u.id
            WHERE f.resource_id = ? AND f.status = 'OPEN'
            ORDER BY f.risk_score DESC
        """, (resource_id,))
        findings = cursor.fetchall()

        return {
            "resource": res,
            "access_list": accessors,
            "versions": versions,
            "activity": activity,
            "findings": findings
        }

@app.post("/api/resources/{resource_id}/version")
def create_resource_version(
    resource_id: str,
    payload: dict,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager", "Developer", "Finance", "HR"))
):
    summary = payload.get("change_summary", "Updated document content and specification details")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE id = ?", (resource_id,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="Resource not found")

        # Increment version number
        old_v = res["current_version"]
        try:
            v_num = float(old_v.replace("v", ""))
            new_v = f"v{v_num + 0.1:.1f}"
        except Exception:
            new_v = "v2.0"

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE resources SET current_version = ? WHERE id = ?
        """, (new_v, resource_id))

        cursor.execute("""
            INSERT INTO resource_versions (resource_id, version_number, modified_by, action, change_summary, created_at)
            VALUES (?, ?, ?, 'VERSION_UPDATE', ?, ?)
        """, (resource_id, new_v, current_user["id"], summary, now_ts))

        cursor.execute("""
            INSERT INTO access_events (user_id, resource_id, action, ip_address, device, result, created_at)
            VALUES (?, ?, 'VERSION_UPDATE', '192.168.10.25', 'Management Console', 'SUCCESS', ?)
        """, (current_user["id"], resource_id, now_ts))

        log_audit_event(
            action="RESOURCE_EDITED",
            performed_by=current_user["id"],
            user_id=current_user["id"],
            resource_id=resource_id,
            result="SUCCESS",
            reason=f"Resource upgraded to {new_v}: {summary}",
            reference_id=new_v,
            conn=conn
        )

        return {"message": f"Resource updated to {new_v}", "version": new_v}

# ----------------- PERMISSIONS & LIFECYCLE -----------------

@app.get("/api/permissions")
def get_permissions(
    search: Optional[str] = None,
    status: Optional[str] = None,
    risk: Optional[str] = None,
    department: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT p.*, u.full_name, u.username, u.email, ro.name as role_name,
                   res.name as resource_name, res.type as resource_type,
                   res.sensitivity, d.name as resource_dept_name,
                   app.full_name as approver_name,
                   coalesce(f.risk_score, 0) as risk_score,
                   coalesce(f.risk_level, 'LOW') as risk_level
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN resources res ON p.resource_id = res.id
            JOIN departments d ON res.department_id = d.id
            LEFT JOIN users app ON p.approver_id = app.id
            LEFT JOIN security_findings f ON f.permission_id = p.id AND f.status = 'OPEN'
            WHERE 1=1
        """
        params = []
        if search:
            query += " AND (u.full_name LIKE ? OR res.name LIKE ? OR p.reason LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])
        if status:
            query += " AND p.status = ?"
            params.append(status)
        if risk:
            query += " AND f.risk_level = ?"
            params.append(risk)
        if department:
            query += " AND d.name = ?"
            params.append(department)

        # Non-admins only see their own permissions
        if current_user["role_name"] in ("Developer", "Finance", "HR", "Analyst", "Intern"):
            query += " AND p.user_id = ?"
            params.append(current_user["id"])

        query += " ORDER BY p.created_at DESC"
        cursor.execute(query, params)
        return cursor.fetchall()

@app.get("/api/permissions/{permission_id}")
def get_permission_detail(permission_id: str, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.*, u.full_name, u.username, u.email, ro.name as role_name,
                   res.name as resource_name, res.type as resource_type,
                   res.sensitivity, d.name as resource_dept_name,
                   app.full_name as approver_name
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN resources res ON p.resource_id = res.id
            JOIN departments d ON res.department_id = d.id
            LEFT JOIN users app ON p.approver_id = app.id
            WHERE p.id = ?
        """, (permission_id,))
        perm = cursor.fetchone()
        if not perm:
            raise HTTPException(status_code=404, detail="Permission record not found")

        # History timeline
        cursor.execute("""
            SELECT ph.*, u.full_name as performer_name
            FROM permission_history ph
            LEFT JOIN users u ON ph.performed_by = u.id
            WHERE ph.permission_id = ?
            ORDER BY ph.created_at ASC
        """, (permission_id,))
        timeline = cursor.fetchall()

        # Findings on this permission
        cursor.execute("""
            SELECT * FROM security_findings
            WHERE permission_id = ?
        """, (permission_id,))
        findings = cursor.fetchall()

        return {
            "permission": perm,
            "timeline": timeline,
            "findings": findings
        }

@app.post("/api/permissions/{permission_id}/revalidate")
def revalidate_permission(
    permission_id: str,
    payload: PermissionRevalidate,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM permissions WHERE id = ?", (permission_id,))
        perm = cursor.fetchone()
        if not perm:
            raise HTTPException(status_code=404, detail="Permission not found")

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE permissions 
            SET status = 'REVALIDATED', revalidation_reason = ?, updated_at = ?
            WHERE id = ?
        """, (payload.reason, now_ts, permission_id))

        record_permission_history(
            permission_id=permission_id,
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            event_type="REVALIDATED",
            details=f"Permission revalidated by {current_user['full_name']}. Business justification: {payload.reason}",
            performed_by=current_user["id"],
            created_at=now_ts,
            conn=conn
        )

        log_audit_event(
            action="REVALIDATION_APPROVED",
            performed_by=current_user["id"],
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            result="SUCCESS",
            reason=f"Revalidation confirmed: {payload.reason}",
            reference_id=permission_id,
            conn=conn
        )

        # Resolve or update associated findings
        cursor.execute("""
            UPDATE security_findings
            SET status = 'REVALIDATED', resolved_at = ?, resolved_by = ?, resolution_notes = ?
            WHERE permission_id = ? AND status = 'OPEN' AND rule_id = 'RULE_INACTIVE_60D'
        """, (now_ts, current_user["id"], f"Revalidated: {payload.reason}", permission_id))

        return {"message": "Permission successfully revalidated"}

@app.post("/api/permissions/{permission_id}/revoke")
def revoke_permission(
    permission_id: str,
    payload: dict = None,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    reason = (payload or {}).get("reason", "Revoked by administrator during access governance review.")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM permissions WHERE id = ?", (permission_id,))
        perm = cursor.fetchone()
        if not perm:
            raise HTTPException(status_code=404, detail="Permission not found")

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE permissions 
            SET status = 'REVOKED', updated_at = ?
            WHERE id = ?
        """, (now_ts, permission_id))

        record_permission_history(
            permission_id=permission_id,
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            event_type="REVOKED",
            details=f"Revoked by {current_user['full_name']}. Reason: {reason}",
            performed_by=current_user["id"],
            created_at=now_ts,
            conn=conn
        )

        log_audit_event(
            action="PERMISSION_REVOKED",
            performed_by=current_user["id"],
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            result="SUCCESS",
            reason=reason,
            reference_id=permission_id,
            conn=conn
        )

        # Close any open finding for this permission
        cursor.execute("""
            UPDATE security_findings
            SET status = 'REVOKED', resolved_at = ?, resolved_by = ?, resolution_notes = ?
            WHERE permission_id = ? AND status = 'OPEN'
        """, (now_ts, current_user["id"], f"Permission revoked: {reason}", permission_id))

        create_notification(
            title="Permission Revoked",
            message=f"Your permission has been revoked: {reason}",
            notif_type="REVOKED_NOTICE",
            user_id=perm["user_id"],
            link="/permissions",
            conn=conn
        )

        return {"message": "Permission successfully revoked"}

@app.post("/api/permissions/{permission_id}/extend")
def extend_permission(
    permission_id: str,
    payload: PermissionExtend,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM permissions WHERE id = ?", (permission_id,))
        perm = cursor.fetchone()
        if not perm:
            raise HTTPException(status_code=404, detail="Permission not found")

        # Parse expiry date
        try:
            curr_exp = datetime.strptime(perm["expiry_date"][:10], "%Y-%m-%d")
        except Exception:
            curr_exp = datetime.now(timezone.utc)

        new_exp = (curr_exp + timedelta(days=payload.additional_days)).strftime("%Y-%m-%d")
        new_ext_count = perm["extension_count"] + 1
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE permissions
            SET expiry_date = ?, extension_count = ?, updated_at = ?
            WHERE id = ?
        """, (new_exp, new_ext_count, now_ts, permission_id))

        record_permission_history(
            permission_id=permission_id,
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            event_type="EXTENDED",
            details=f"Extended by {payload.additional_days} days to {new_exp} (Extension #{new_ext_count}). Reason: {payload.reason}",
            performed_by=current_user["id"],
            created_at=now_ts
        )

        log_audit_event(
            action="PERMISSION_EXTENDED",
            performed_by=current_user["id"],
            user_id=perm["user_id"],
            resource_id=perm["resource_id"],
            result="SUCCESS",
            reason=f"Extension #{new_ext_count} granted: {payload.reason}",
            reference_id=permission_id
        )

        # Re-run detector to adjust risk scoring
        run_permission_creep_detector()

        return {"message": f"Permission extended to {new_exp}", "new_expiry": new_exp}

# ----------------- ACCESS REQUEST WORKFLOW -----------------

@app.get("/api/requests")
def get_requests(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT req.*, u.full_name as requester_name, u.email as requester_email,
                   ro.name as requester_role, ud.name as requester_dept,
                   res.name as resource_name, res.type as resource_type,
                   res.sensitivity as resource_sensitivity, rd.name as resource_dept,
                   rev.full_name as reviewer_name
            FROM permission_requests req
            JOIN users u ON req.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN departments ud ON u.department_id = ud.id
            JOIN resources res ON req.resource_id = res.id
            JOIN departments rd ON res.department_id = rd.id
            LEFT JOIN users rev ON req.reviewed_by = rev.id
            WHERE 1=1
        """
        params = []
        if status:
            query += " AND req.status = ?"
            params.append(status)

        # Standard employees see only their requests
        if current_user["role_name"] in ("Developer", "Finance", "HR", "Analyst", "Intern"):
            query += " AND req.user_id = ?"
            params.append(current_user["id"])

        query += " ORDER BY req.created_at DESC"
        cursor.execute(query, params)
        return cursor.fetchall()

@app.post("/api/requests")
def create_access_request(
    payload: PermissionRequestCreate,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE id = ?", (payload.resource_id,))
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=404, detail="Resource not found")

        cursor.execute("SELECT count(*) as cnt FROM permission_requests")
        req_num = cursor.fetchone()["cnt"] + 1025
        req_code = f"REQ-{req_num}"
        req_id = f"req_{int(datetime.now().timestamp())}"
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO permission_requests (
                id, request_code, user_id, resource_id, permission_type, duration_days,
                reason, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
        """, (req_id, req_code, current_user["id"], payload.resource_id, payload.permission_type, payload.duration_days, payload.reason, now_ts))

        log_audit_event(
            action="ACCESS_REQUEST",
            performed_by=current_user["id"],
            user_id=current_user["id"],
            resource_id=payload.resource_id,
            result="SUCCESS",
            reason=f"Request submitted: {payload.reason}",
            reference_id=req_code,
            conn=conn
        )

        create_notification(
            title="New Access Request Pending",
            message=f"{current_user['full_name']} requested {payload.permission_type} on {res['name']}.",
            notif_type="REQUEST_PENDING",
            user_id=None, # Global admin notification
            link="/access-requests",
            conn=conn
        )

        return {"message": "Access request submitted successfully", "request_code": req_code, "request_id": req_id}

@app.post("/api/requests/{request_id}/approve")
def approve_request(
    request_id: str,
    payload: dict = None,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    comments = (payload or {}).get("comments", "Approved in line with project authorization.")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,))
        req = cursor.fetchone()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
        if req["status"] != "PENDING":
            raise HTTPException(status_code=400, detail=f"Request is already {req['status']}")

        now_dt = datetime.now(timezone.utc)
        now_ts = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        start_date = now_dt.strftime("%Y-%m-%d")
        expiry_date = (now_dt + timedelta(days=req["duration_days"])).strftime("%Y-%m-%d")

        perm_id = f"perm_{int(now_dt.timestamp())}"

        # 1. Create permission
        cursor.execute("""
            INSERT INTO permissions (
                id, user_id, resource_id, permission_type, start_date, expiry_date,
                reason, approver_id, status, last_used_at, extension_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 0, ?, ?)
        """, (
            perm_id, req["user_id"], req["resource_id"], req["permission_type"],
            start_date, expiry_date, req["reason"], current_user["id"],
            now_ts, now_ts, now_ts
        ))

        # 2. Update request
        cursor.execute("""
            UPDATE permission_requests
            SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ?, review_comments = ?, permission_id = ?
            WHERE id = ?
        """, (current_user["id"], now_ts, comments, perm_id, request_id))

        # 3. Record timeline and audit
        record_permission_history(
            permission_id=perm_id,
            user_id=req["user_id"],
            resource_id=req["resource_id"],
            event_type="APPROVED",
            details=f"Request {req['request_code']} approved by {current_user['full_name']}. {comments}",
            performed_by=current_user["id"],
            created_at=now_ts,
            conn=conn
        )

        record_permission_history(
            permission_id=perm_id,
            user_id=req["user_id"],
            resource_id=req["resource_id"],
            event_type="GRANTED",
            details=f"{req['permission_type']} granted from {start_date} to {expiry_date}",
            performed_by=current_user["id"],
            created_at=now_ts,
            conn=conn
        )

        log_audit_event(
            action="ACCESS_APPROVED",
            performed_by=current_user["id"],
            user_id=req["user_id"],
            resource_id=req["resource_id"],
            result="SUCCESS",
            reason=f"Approved: {comments}",
            reference_id=req["request_code"],
            conn=conn
        )

        log_audit_event(
            action="PERMISSION_GRANTED",
            performed_by=current_user["id"],
            user_id=req["user_id"],
            resource_id=req["resource_id"],
            result="SUCCESS",
            reason=f"Permission {perm_id} active until {expiry_date}",
            reference_id=perm_id,
            conn=conn
        )

        create_notification(
            title="Access Request Approved",
            message=f"Your request {req['request_code']} has been approved. Access is now ACTIVE.",
            notif_type="REQUEST_APPROVED",
            user_id=req["user_id"],
            link=f"/permissions/{perm_id}",
            conn=conn
        )

    # Trigger detection engine
    run_permission_creep_detector()

    return {"message": "Request approved and permission activated", "permission_id": perm_id}

@app.post("/api/requests/{request_id}/reject")
def reject_request(
    request_id: str,
    payload: dict = None,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    comments = (payload or {}).get("comments", "Request does not meet least-privilege necessity criteria.")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM permission_requests WHERE id = ?", (request_id,))
        req = cursor.fetchone()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE permission_requests
            SET status = 'REJECTED', reviewed_by = ?, reviewed_at = ?, review_comments = ?
            WHERE id = ?
        """, (current_user["id"], now_ts, comments, request_id))

        log_audit_event(
            action="ACCESS_REJECTED",
            performed_by=current_user["id"],
            user_id=req["user_id"],
            resource_id=req["resource_id"],
            result="SUCCESS",
            reason=f"Rejected: {comments}",
            reference_id=req["request_code"]
        )

        create_notification(
            title="Access Request Rejected",
            message=f"Request {req['request_code']} was rejected. Reason: {comments}",
            notif_type="REQUEST_REJECTED",
            user_id=req["user_id"],
            link="/access-requests"
        )

        return {"message": "Request rejected"}

# ----------------- SECURITY FINDINGS -----------------

@app.get("/api/findings")
def get_security_findings(
    risk: Optional[str] = None,
    status: Optional[str] = "OPEN",
    rule: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT f.*, u.full_name, u.username, ro.name as role_name,
                   res.name as resource_name, res.type as resource_type,
                   res.sensitivity, d.name as department_name,
                   p.permission_type, p.last_used_at, p.start_date, p.expiry_date
            FROM security_findings f
            JOIN users u ON f.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN resources res ON f.resource_id = res.id
            JOIN departments d ON res.department_id = d.id
            LEFT JOIN permissions p ON f.permission_id = p.id
            WHERE 1=1
        """
        params = []
        if status and status != "ALL":
            query += " AND f.status = ?"
            params.append(status)
        if risk and risk != "ALL":
            query += " AND f.risk_level = ?"
            params.append(risk)
        if rule:
            query += " AND f.rule_id = ?"
            params.append(rule)

        query += " ORDER BY f.risk_score DESC, f.detected_at DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        for r in rows:
            try:
                r["evidence_data"] = json.loads(r["evidence"])
            except Exception:
                r["evidence_data"] = {}
        return rows

@app.post("/api/findings/{finding_id}/resolve")
def resolve_security_finding(
    finding_id: str,
    payload: FindingResolution,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    action = payload.action.upper()
    notes = payload.notes or payload.reason or "Finding resolved by administrator"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_findings WHERE id = ?", (finding_id,))
        fnd = cursor.fetchone()
        if not fnd:
            raise HTTPException(status_code=404, detail="Finding not found")

        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Update finding status
        cursor.execute("""
            UPDATE security_findings
            SET status = ?, resolved_at = ?, resolved_by = ?, resolution_notes = ?
            WHERE id = ?
        """, (action, now_ts, current_user["id"], notes, finding_id))

        # If action is REVOKE, revoke the permission
        if action == "REVOKE" and fnd["permission_id"]:
            cursor.execute("""
                UPDATE permissions SET status = 'REVOKED', updated_at = ?
                WHERE id = ?
            """, (now_ts, fnd["permission_id"]))

            record_permission_history(
                permission_id=fnd["permission_id"],
                user_id=fnd["user_id"],
                resource_id=fnd["resource_id"],
                event_type="REVOKED",
                details=f"Revoked via Security Finding {fnd['finding_code']}: {notes}",
                performed_by=current_user["id"],
                created_at=now_ts
            )

        # If action is REVALIDATE, mark permission revalidated
        elif action == "REVALIDATE" and fnd["permission_id"]:
            cursor.execute("""
                UPDATE permissions SET status = 'REVALIDATED', revalidation_reason = ?, updated_at = ?
                WHERE id = ?
            """, (notes, now_ts, fnd["permission_id"]))

            record_permission_history(
                permission_id=fnd["permission_id"],
                user_id=fnd["user_id"],
                resource_id=fnd["resource_id"],
                event_type="REVALIDATED",
                details=f"Revalidated via Security Finding {fnd['finding_code']}: {notes}",
                performed_by=current_user["id"],
                created_at=now_ts
            )

        log_audit_event(
            action=f"FINDING_{action}",
            performed_by=current_user["id"],
            user_id=fnd["user_id"],
            resource_id=fnd["resource_id"],
            result="SUCCESS",
            reason=f"Finding {fnd['finding_code']} resolved as {action}: {notes}",
            reference_id=fnd["finding_code"]
        )

        return {"message": f"Finding {fnd['finding_code']} updated to {action}"}

# ----------------- ACCESS REVIEWS (Dormancy / Inactivity Review) -----------------

@app.get("/api/access-reviews")
def get_access_reviews(
    category: Optional[str] = None,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT p.*, u.full_name, u.username, ro.name as role_name,
                   res.name as resource_name, res.sensitivity, d.name as resource_dept_name,
                   coalesce(f.risk_score, 0) as risk_score,
                   coalesce(f.risk_level, 'LOW') as risk_level,
                   f.recommended_action
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN roles ro ON u.role_id = ro.id
            JOIN resources res ON p.resource_id = res.id
            JOIN departments d ON res.department_id = d.id
            LEFT JOIN security_findings f ON f.permission_id = p.id AND f.status = 'OPEN'
            WHERE p.status IN ('ACTIVE', 'INACTIVE')
        """
        if category == "inactive":
            query += " AND p.status = 'INACTIVE'"
        elif category == "expiring_soon":
            query += " AND date(p.expiry_date) <= date('2026-10-19', '+7 days') AND date(p.expiry_date) >= date('2026-10-19')"
        elif category == "high_risk":
            query += " AND f.risk_level IN ('HIGH', 'CRITICAL')"

        query += " ORDER BY f.risk_score DESC, p.last_used_at ASC"
        cursor.execute(query)
        return cursor.fetchall()

# ----------------- FILE ACTIVITY SIMULATION (Interactive Demo) -----------------

@app.post("/api/activity/simulate")
def simulate_activity(
    payload: SimulateActivityRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Demonstration tool: simulates an actual user file operation (OPEN, READ, EDIT)
    which updates last_used_at on the permission, logs access_events, and updates audit trail.
    """
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM permissions 
            WHERE user_id = ? AND resource_id = ? AND status IN ('ACTIVE', 'INACTIVE', 'REVALIDATED')
        """, (current_user["id"], payload.resource_id))
        perm = cursor.fetchone()

        result_flag = "SUCCESS" if perm else "DENIED"

        cursor.execute("""
            INSERT INTO access_events (user_id, resource_id, action, ip_address, device, result, created_at)
            VALUES (?, ?, ?, '192.168.10.25', 'Interactive Client Session', ?, ?)
        """, (current_user["id"], payload.resource_id, payload.action, result_flag, now_ts))

        if perm:
            # Refresh last used timestamp and reset to ACTIVE if it was INACTIVE
            new_status = "ACTIVE" if perm["status"] == "INACTIVE" else perm["status"]
            cursor.execute("""
                UPDATE permissions SET last_used_at = ?, status = ?, updated_at = ?
                WHERE id = ?
            """, (now_ts, new_status, now_ts, perm["id"]))

            record_permission_history(
                permission_id=perm["id"],
                user_id=current_user["id"],
                resource_id=payload.resource_id,
                event_type="ACCESSED",
                details=f"Resource {payload.action} operation executed successfully",
                performed_by=current_user["id"],
                created_at=now_ts
            )

        log_audit_event(
            action=f"RESOURCE_{payload.action}",
            performed_by=current_user["id"],
            user_id=current_user["id"],
            resource_id=payload.resource_id,
            result=result_flag,
            reason="User interactive session invocation",
            reference_id="SIM-EXEC"
        )

    # Re-run detector
    run_permission_creep_detector()

    return {
        "status": result_flag,
        "message": f"Operation '{payload.action}' executed with result {result_flag}",
        "timestamp": now_ts
    }

# ----------------- AUDIT LOGS -----------------

@app.get("/api/audit-logs")
def get_audit_logs(
    action: Optional[str] = None,
    user: Optional[str] = None,
    result: Optional[str] = None,
    current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))
):
    with get_db() as conn:
        cursor = conn.cursor()
        query = """
            SELECT a.*, u.full_name as user_full_name, p.full_name as performer_full_name,
                   res.name as resource_name
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN users p ON a.performed_by = p.id
            LEFT JOIN resources res ON a.resource_id = res.id
            WHERE 1=1
        """
        params = []
        if action and action != "ALL":
            query += " AND a.action = ?"
            params.append(action)
        if user:
            query += " AND (u.full_name LIKE ? OR a.performed_by LIKE ?)"
            s = f"%{user}%"
            params.extend([s, s])
        if result and result != "ALL":
            query += " AND a.result = ?"
            params.append(result)

        query += " ORDER BY a.timestamp DESC LIMIT 150"
        cursor.execute(query, params)
        return cursor.fetchall()

# ----------------- NOTIFICATIONS -----------------

@app.get("/api/notifications")
def get_notifications(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM notifications
            WHERE user_id = ? OR user_id IS NULL
            ORDER BY created_at DESC LIMIT 30
        """, (current_user["id"],))
        return cursor.fetchall()

@app.post("/api/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
        return {"status": "success"}

# ----------------- REPORTS -----------------

@app.get("/api/reports/summary")
def get_report_data(current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) as cnt FROM users")
        total_users = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM resources")
        total_resources = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'ACTIVE'")
        active_perms = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'INACTIVE'")
        inactive_perms = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM permissions WHERE status = 'EXPIRED'")
        expired_perms = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM security_findings WHERE status = 'OPEN'")
        open_findings = cursor.fetchone()["cnt"]
        cursor.execute("SELECT count(*) as cnt FROM security_findings WHERE status = 'OPEN' AND risk_level IN ('HIGH', 'CRITICAL')")
        critical_findings = cursor.fetchone()["cnt"]

        cursor.execute("""
            SELECT f.finding_code, u.full_name, res.name as resource_name,
                   f.risk_level, f.risk_score, f.what_happened, f.recommended_action
            FROM security_findings f
            JOIN users u ON f.user_id = u.id
            JOIN resources res ON f.resource_id = res.id
            WHERE f.status = 'OPEN'
            ORDER BY f.risk_score DESC LIMIT 10
        """)
        findings = cursor.fetchall()

        cursor.execute("""
            SELECT u.full_name, res.name as resource_name, p.permission_type, p.last_used_at, p.reason
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN resources res ON p.resource_id = res.id
            WHERE p.status = 'INACTIVE' LIMIT 10
        """)
        inactives = cursor.fetchall()

        return {
            "meta": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "total_users": total_users,
                "total_resources": total_resources,
                "active_permissions": active_perms,
                "inactive_permissions": inactive_perms,
                "expired_permissions": expired_perms,
                "open_findings": open_findings,
                "critical_findings": critical_findings
            },
            "findings": findings,
            "inactive_list": inactives
        }

@app.get("/api/reports/download-pdf")
def download_pdf_report(current_user: dict = Depends(require_roles("System Administrator", "Department Manager"))):
    pdf_path = generate_pdf_audit_report()
    filename = os.path.basename(pdf_path)
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=filename
    )

# ----------------- SETTINGS & DEMO RESET -----------------

@app.get("/api/settings")
def get_settings(current_user: dict = Depends(require_roles("System Administrator"))):
    return get_system_settings()

@app.put("/api/settings")
def update_settings(
    settings: SystemSettingsUpdate,
    current_user: dict = Depends(require_roles("System Administrator"))
):
    with get_db() as conn:
        cursor = conn.cursor()
        updates = [
            ("inactivity_threshold_days", str(settings.inactivity_threshold_days)),
            ("default_permission_days", str(settings.default_permission_days)),
            ("expiring_soon_days", str(settings.expiring_soon_days)),
            ("low_risk_threshold", str(settings.low_risk_threshold)),
            ("medium_risk_threshold", str(settings.medium_risk_threshold)),
            ("high_risk_threshold", str(settings.high_risk_threshold)),
            ("critical_risk_threshold", str(settings.critical_risk_threshold))
        ]
        cursor.executemany("UPDATE system_settings SET value = ? WHERE key = ?", updates)

        log_audit_event(
            action="SYSTEM_SETTINGS_UPDATED",
            performed_by=current_user["id"],
            result="SUCCESS",
            reason="Security policies and thresholds recalibrated",
            reference_id="POLICY-UPDATE"
        )

    # Re-evaluate detector with new threshold
    run_permission_creep_detector()
    return {"message": "Settings updated and detector policies recalibrated successfully"}

@app.post("/api/admin/reset-demo-data")
def reset_demo_database_endpoint(current_user: dict = Depends(require_roles("System Administrator"))):
    """Clean reset of synthetic demo state for live presentations"""
    seed_demo_database()
    log_audit_event(
        action="DEMO_DATABASE_RESET",
        performed_by=current_user["id"],
        result="SUCCESS",
        reason="Demonstration dataset restored to canonical baseline",
        reference_id="RESET-ALL"
    )
    return {"message": "Database and demonstration scenarios reset successfully"}

# ----------------- STATIC FRONTEND ROUTING -----------------

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/{full_path:path}")
def serve_frontend_spa(full_path: str):
    # If API call, don't serve index.html
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found")
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return Response("PermissionGuard API is running. Frontend index.html not yet installed.", media_type="text/plain")
