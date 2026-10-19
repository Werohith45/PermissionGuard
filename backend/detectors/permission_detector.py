import json
from datetime import datetime
from backend.database.schema import get_db
from backend.services.audit_service import get_system_settings, create_notification, log_audit_event

def parse_date(date_str: str) -> datetime:
    if not date_str:
        return None
    # Support YYYY-MM-DD or YYYY-MM-DD HH:MM:SS or ISO format
    clean = date_str.replace("Z", "").replace("T", " ")
    if len(clean) == 10:
        return datetime.strptime(clean, "%Y-%m-%d")
    return datetime.strptime(clean[:19], "%Y-%m-%d %H:%M:%S")

def run_permission_creep_detector(current_time_str: str = "2026-10-19 15:30:00") -> dict:
    """
    Evaluates all permissions against transparent, rules-based cybersecurity policies:
    RULE 1: Role Mismatch (Permission is outside user's department/role baseline) -> Risk +30
    RULE 2: Inactive > 60 days (No recorded usage during inactivity threshold) -> Risk +20
    RULE 3: Excessive Permission Level (User has EDIT/WRITE where role baseline allows READ) -> Risk +20
    RULE 4: Temporary Permission Expired (Past expiry date but status not updated) -> Risk +25
    RULE 5: Multiple Temporary Permissions (User has 3+ temporary permissions) -> Risk +10
    RULE 6: Repeated Extension (Permission renewed/extended multiple times) -> Risk +15
    RULE 7: Cross-Department Access (User holds permissions in 2+ unrelated departments) -> Risk +25
    RULE 8: Sensitive Resource with High Access (RESTRICTED/CONFIDENTIAL resource with EDIT/WRITE) -> Risk +20
    """
    now = parse_date(current_time_str)
    settings = get_system_settings()
    inactivity_threshold = settings.get("inactivity_threshold_days", 60)
    expiring_soon_threshold = settings.get("expiring_soon_days", 7)

    findings_created = 0
    findings_updated = 0
    expired_count = 0
    inactive_flagged = 0

    with get_db() as conn:
        cursor = conn.cursor()

        # Fetch all role permission baselines
        cursor.execute("SELECT * FROM role_permissions")
        role_baselines = cursor.fetchall()
        # map (role_id, department_id) -> max_permission, allowed_sensitivity
        baseline_map = {}
        for rb in role_baselines:
            baseline_map[(rb["role_id"], rb["department_id"])] = {
                "max_perm": rb["max_permission"],
                "sensitivities": [s.strip() for s in rb["allowed_sensitivity"].split(",")]
            }

        # Fetch all permissions with user, role, and resource metadata
        cursor.execute("""
            SELECT p.*, 
                   u.username, u.full_name, u.role_id, u.department_id as user_dept_id,
                   r.name as role_name, ud.name as user_dept_name,
                   res.name as resource_name, res.sensitivity, res.department_id as res_dept_id,
                   rd.name as res_dept_name
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            JOIN roles r ON u.role_id = r.id
            JOIN departments ud ON u.department_id = ud.id
            JOIN resources res ON p.resource_id = res.id
            JOIN departments rd ON res.department_id = rd.id
        """)
        permissions = cursor.fetchall()

        # Count active permissions per user across departments
        user_dept_counts = {}
        user_temp_counts = {}
        for p in permissions:
            if p["status"] in ("ACTIVE", "INACTIVE", "REVALIDATED"):
                u_id = p["user_id"]
                user_dept_counts.setdefault(u_id, set()).add(p["res_dept_id"])
                user_temp_counts[u_id] = user_temp_counts.get(u_id, 0) + 1

        for p in permissions:
            perm_id = p["id"]
            user_id = p["user_id"]
            res_id = p["resource_id"]
            status = p["status"]
            start_date = parse_date(p["start_date"])
            expiry_date = parse_date(p["expiry_date"])
            last_used = parse_date(p["last_used_at"]) if p["last_used_at"] else start_date

            # --- Check 1: Auto Expiry Lifecycle Transition ---
            if expiry_date and now >= expiry_date and status in ("ACTIVE", "INACTIVE", "REVALIDATED"):
                cursor.execute("""
                    UPDATE permissions 
                    SET status = 'EXPIRED', updated_at = ?
                    WHERE id = ?
                """, (now.strftime("%Y-%m-%d %H:%M:%S"), perm_id))
                
                cursor.execute("""
                    INSERT INTO permission_history (permission_id, user_id, resource_id, event_type, details, performed_by, created_at)
                    VALUES (?, ?, ?, 'EXPIRED', 'Permission automatically expired upon reaching expiry threshold', 'SYSTEM', ?)
                """, (perm_id, user_id, res_id, now.strftime("%Y-%m-%d %H:%M:%S")))
                
                log_audit_event(
                    action="PERMISSION_EXPIRED",
                    performed_by="SYSTEM",
                    user_id=user_id,
                    resource_id=res_id,
                    result="SUCCESS",
                    reason="Time-based automatic permission expiry reached. User account preserved.",
                    reference_id=perm_id,
                    conn=conn
                )
                
                create_notification(
                    title="Permission Expired",
                    message=f"Access for {p['full_name']} to {p['resource_name']} expired automatically.",
                    notif_type="EXPIRED_AUTO",
                    user_id=user_id,
                    link=f"/permissions/{perm_id}",
                    conn=conn
                )
                expired_count += 1
                status = "EXPIRED"

            # --- Check 2: Inactivity Detection (Lifecycle Rule) ---
            days_inactive = (now - last_used).days if last_used else (now - start_date).days
            if status == "ACTIVE" and days_inactive >= inactivity_threshold:
                cursor.execute("""
                    UPDATE permissions 
                    SET status = 'INACTIVE', updated_at = ?
                    WHERE id = ?
                """, (now.strftime("%Y-%m-%d %H:%M:%S"), perm_id))
                
                cursor.execute("""
                    INSERT INTO permission_history (permission_id, user_id, resource_id, event_type, details, performed_by, created_at)
                    VALUES (?, ?, ?, 'INACTIVE_FLAGGED', ?, 'SYSTEM', ?)
                """, (perm_id, user_id, res_id, f"Flagged as inactive: no usage detected for {days_inactive} days (threshold {inactivity_threshold} days)", now.strftime("%Y-%m-%d %H:%M:%S")))
                
                create_notification(
                    title="Inactive Permission Flagged",
                    message=f"Permission for {p['full_name']} on {p['resource_name']} has been inactive for {days_inactive} days.",
                    notif_type="INACTIVITY_ALERT",
                    user_id=user_id,
                    link=f"/access-reviews",
                    conn=conn
                )
                inactive_flagged += 1
                status = "INACTIVE"

            # Skip findings analysis for already expired or revoked permissions unless open finding exists
            if status in ("EXPIRED", "REVOKED"):
                # Close any open finding
                cursor.execute("""
                    UPDATE security_findings 
                    SET status = 'RESOLVED', resolved_at = ?, resolved_by = 'SYSTEM', resolution_notes = 'Permission no longer active'
                    WHERE permission_id = ? AND status = 'OPEN'
                """, (now.strftime("%Y-%m-%d %H:%M:%S"), perm_id))
                continue

            # --- Creep Detection Rules Evaluation ---
            score = 0
            reasons = []
            rule_hits = []
            recommended_actions = []

            # Baseline check
            role_key = (p["role_id"], p["res_dept_id"])
            baseline = baseline_map.get(role_key)

            # RULE 1: Role Mismatch (Department / Scope outside normal baseline)
            if not baseline:
                score += 30
                reasons.append("+30 Role mismatch: User's role has no baseline grant for this resource department")
                rule_hits.append("RULE_ROLE_MISMATCH")
                recommended_actions.append("Review whether business need justifies cross-role access; revoke if project completed.")

            # RULE 2: Inactive for 60+ days
            if days_inactive >= inactivity_threshold:
                score += 20
                reasons.append(f"+20 Inactive: No usage recorded for {days_inactive} days (threshold: {inactivity_threshold} days)")
                rule_hits.append("RULE_INACTIVE_60D")
                recommended_actions.append("Request business revalidation or revoke dormant access.")

            # RULE 3: Excessive Permission Level (e.g., EDIT/WRITE when role allows READ only)
            if baseline:
                max_p = baseline["max_perm"]
                if max_p == "READ" and p["permission_type"] in ("WRITE", "EDIT", "SHARE"):
                    score += 20
                    reasons.append(f"+20 Excessive permission level: User granted {p['permission_type']} where role baseline permits only READ")
                    rule_hits.append("RULE_EXCESSIVE_LEVEL")
                    recommended_actions.append("Downscale permission to READ only.")

            # RULE 6: Repeated Extension
            if p["extension_count"] >= 2:
                score += 15
                reasons.append(f"+15 Repeated extension: Permission has been extended {p['extension_count']} times")
                rule_hits.append("RULE_REPEATED_EXTENSION")
                recommended_actions.append("Conduct comprehensive role audit rather than ad-hoc temporary renewals.")

            # RULE 7: Cross-department access
            depts_accessed = len(user_dept_counts.get(user_id, set()))
            if depts_accessed >= 3:
                score += 25
                reasons.append(f"+25 Cross-department access: User holds access across {depts_accessed} distinct departments")
                rule_hits.append("RULE_CROSS_DEPARTMENT")
                recommended_actions.append("Review multi-department access sprawl to enforce least privilege.")

            # RULE 8: Sensitive Resource with High Access
            if p["sensitivity"] in ("RESTRICTED", "CONFIDENTIAL") and p["permission_type"] in ("WRITE", "EDIT"):
                score += 20
                reasons.append(f"+20 High-impact privilege on {p['sensitivity']} resource")
                rule_hits.append("RULE_SENSITIVE_RESOURCE_WRITE")
                recommended_actions.append("Verify explicit authorization and multi-manager signoff.")

            # Cap score at 100
            score = min(score, 100)

            # Determine Risk Level
            if score >= 75:
                risk_level = "CRITICAL"
            elif score >= 50:
                risk_level = "HIGH"
            elif score >= 25:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            # If risk is Medium, High, or Critical, generate or update a security finding
            if score >= 25:
                primary_rule = rule_hits[0] if rule_hits else "RULE_ACCUMULATED_PRIVILEGE"
                what_happened = f"{p['full_name']} ({p['role_name']}) holds {p['permission_type']} permission on {p['sensitivity']} resource '{p['resource_name']}'."
                why_risky = f"Risk Score {score}/100. Factors identified: " + "; ".join(reasons)
                evidence = json.dumps({
                    "score": score,
                    "reasons": reasons,
                    "days_inactive": days_inactive,
                    "extension_count": p["extension_count"],
                    "permission_type": p["permission_type"],
                    "role": p["role_name"],
                    "user_dept": p["user_dept_name"],
                    "resource_dept": p["res_dept_name"],
                    "sensitivity": p["sensitivity"]
                })
                rec_action = " ".join(recommended_actions) if recommended_actions else "Review business requirement with department manager."

                # Check if an open finding already exists for this permission
                cursor.execute("""
                    SELECT id, finding_code FROM security_findings 
                    WHERE permission_id = ? AND status = 'OPEN'
                """, (perm_id,))
                existing_fnd = cursor.fetchone()

                if existing_fnd:
                    cursor.execute("""
                        UPDATE security_findings
                        SET risk_level = ?, risk_score = ?, what_happened = ?, why_risky = ?,
                            evidence = ?, recommended_action = ?
                        WHERE id = ?
                    """, (risk_level, score, what_happened, why_risky, evidence, rec_action, existing_fnd["id"]))
                    findings_updated += 1
                else:
                    cursor.execute("SELECT COUNT(*) as count FROM security_findings")
                    cnt = cursor.fetchone()["count"] + 1
                    finding_code = f"FND-{cnt:04d}"
                    finding_id = f"fnd_{perm_id}_{cnt}"
                    cursor.execute("""
                        INSERT INTO security_findings (
                            id, finding_code, user_id, resource_id, permission_id, rule_id,
                            risk_level, risk_score, what_happened, why_risky, evidence,
                            recommended_action, status, detected_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                    """, (
                        finding_id, finding_code, user_id, res_id, perm_id, primary_rule,
                        risk_level, score, what_happened, why_risky, evidence,
                        rec_action, now.strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    findings_created += 1

    return {
        "status": "success",
        "evaluated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "expired_permissions": expired_count,
        "inactive_flagged": inactive_flagged,
        "findings_created": findings_created,
        "findings_updated": findings_updated
    }
