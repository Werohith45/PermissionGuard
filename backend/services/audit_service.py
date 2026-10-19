from backend.database.schema import get_db

def log_audit_event(
    action: str,
    performed_by: str,
    user_id: str = None,
    resource_id: str = None,
    result: str = "SUCCESS",
    reason: str = None,
    reference_id: str = None,
    ip_address: str = "192.168.1.50",
    timestamp: str = None,
    conn = None
):
    """Write an immutable audit log entry into the database"""
    from datetime import datetime, timezone
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, user_id, action, resource_id, result, reason, performed_by, reference_id, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, user_id, action, resource_id, result, reason, performed_by, reference_id, ip_address))
    else:
        with get_db() as c:
            cursor = c.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, user_id, action, resource_id, result, reason, performed_by, reference_id, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, user_id, action, resource_id, result, reason, performed_by, reference_id, ip_address))

def record_permission_history(
    permission_id: str,
    user_id: str,
    resource_id: str,
    event_type: str,
    details: str,
    performed_by: str = None,
    created_at: str = None,
    conn = None
):
    from datetime import datetime, timezone
    ts = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO permission_history (permission_id, user_id, resource_id, event_type, details, performed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (permission_id, user_id, resource_id, event_type, details, performed_by, ts))
    else:
        with get_db() as c:
            cursor = c.cursor()
            cursor.execute("""
                INSERT INTO permission_history (permission_id, user_id, resource_id, event_type, details, performed_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (permission_id, user_id, resource_id, event_type, details, performed_by, ts))

def create_notification(
    title: str,
    message: str,
    notif_type: str,
    user_id: str = None,
    link: str = None,
    created_at: str = None,
    conn = None
):
    from datetime import datetime, timezone
    ts = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type, link, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, title, message, notif_type, link, ts))
    else:
        with get_db() as c:
            cursor = c.cursor()
            cursor.execute("""
                INSERT INTO notifications (user_id, title, message, type, link, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, title, message, notif_type, link, ts))

def get_system_settings() -> dict:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM system_settings")
        rows = cursor.fetchall()
        settings = {}
        for r in rows:
            try:
                settings[r["key"]] = int(r["value"])
            except ValueError:
                settings[r["key"]] = r["value"]
        # Defaults if not present
        if "inactivity_threshold_days" not in settings:
            settings["inactivity_threshold_days"] = 60
        if "default_permission_days" not in settings:
            settings["default_permission_days"] = 90
        if "expiring_soon_days" not in settings:
            settings["expiring_soon_days"] = 7
        return settings
