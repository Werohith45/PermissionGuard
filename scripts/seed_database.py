import os
import json
from datetime import datetime
from backend.database.schema import get_db
from backend.auth.security import hash_password
from backend.detectors.permission_detector import run_permission_creep_detector

def seed_demo_database():
    """Populates realistic enterprise synthetic datasets and scenarios"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = OFF;")

        # Clean existing tables
        tables = [
            "notifications", "security_findings", "resource_versions", "access_events",
            "permission_history", "permission_requests", "permissions", "role_permissions",
            "resources", "users", "roles", "departments", "audit_logs", "system_settings"
        ]
        for t in tables:
            cursor.execute(f"DELETE FROM {t}")
        cursor.execute("PRAGMA foreign_keys = ON;")

        # 1. System Settings
        settings = [
            ("inactivity_threshold_days", "60", "Days before unused permission is flagged as inactive"),
            ("default_permission_days", "90", "Default duration for granted permissions"),
            ("expiring_soon_days", "7", "Threshold in days to flag permissions expiring soon"),
            ("low_risk_threshold", "24", "Maximum score for LOW risk"),
            ("medium_risk_threshold", "49", "Maximum score for MEDIUM risk"),
            ("high_risk_threshold", "74", "Maximum score for HIGH risk"),
            ("critical_risk_threshold", "100", "Maximum score for CRITICAL risk")
        ]
        cursor.executemany("INSERT INTO system_settings (key, value, description) VALUES (?, ?, ?)", settings)

        # 2. Departments
        departments = [
            ("dept_eng", "Engineering", "Software development, architecture, DevOps, QA"),
            ("dept_fin", "Finance", "Accounting, budget planning, treasury, financial analysis"),
            ("dept_hr", "Human Resources", "Recruitment, payroll, employee relations, onboarding"),
            ("dept_sec", "Security", "Cybersecurity operations, audit, compliance, vulnerability assessment"),
            ("dept_ops", "Operations", "Business analytics, facilities, logistics, customer operations"),
            ("dept_mkt", "Marketing", "Brand management, customer outreach, market strategy")
        ]
        cursor.executemany("INSERT INTO departments (id, name, description) VALUES (?, ?, ?)", departments)

        # 3. Roles
        roles = [
            ("role_admin", "System Administrator", "Full system oversight, authorization and policy configuration", "dept_sec"),
            ("role_mgr", "Department Manager", "Departmental supervisory and permission review authority", "dept_ops"),
            ("role_dev", "Developer", "Software engineering, source code and architecture development", "dept_eng"),
            ("role_fin", "Finance", "Financial ledger, budget planning and fiscal auditing", "dept_fin"),
            ("role_hr", "HR", "Employee lifecycle management and confidential personnel files", "dept_hr"),
            ("role_analyst", "Analyst", "Data analysis, business intelligence and performance reporting", "dept_ops"),
            ("role_intern", "Intern", "Limited temporary apprentice with strictly restricted scope", "dept_eng")
        ]
        cursor.executemany("INSERT INTO roles (id, name, description, department_id) VALUES (?, ?, ?, ?)", roles)

        # 4. Role Permissions (Least Privilege Baseline)
        role_perms = [
            ("role_admin", "dept_sec", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED"),
            ("role_admin", "dept_eng", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED"),
            ("role_admin", "dept_fin", "READ", "PUBLIC,INTERNAL,CONFIDENTIAL"),
            ("role_admin", "dept_hr", "READ", "PUBLIC,INTERNAL,CONFIDENTIAL"),
            ("role_mgr", "dept_ops", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL"),
            ("role_dev", "dept_eng", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL"),
            ("role_fin", "dept_fin", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED"),
            ("role_hr", "dept_hr", "EDIT", "PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED"),
            ("role_analyst", "dept_ops", "READ", "PUBLIC,INTERNAL,CONFIDENTIAL"),
            ("role_intern", "dept_eng", "READ", "PUBLIC,INTERNAL")
        ]
        cursor.executemany("INSERT INTO role_permissions (role_id, department_id, max_permission, allowed_sensitivity) VALUES (?, ?, ?, ?)", role_perms)

        # 5. Users (18 Realistic Enterprise Users)
        default_pwd_hash = hash_password("DemoPassword123!")
        users = [
            ("usr_admin", "admin", "admin@example.local", default_pwd_hash, "Vikram Malhotra", "role_admin", "dept_sec", "ACTIVE", "2026-01-10 09:00:00"),
            ("usr_mgr", "manager", "manager@example.local", default_pwd_hash, "Priya Sharma", "role_mgr", "dept_ops", "ACTIVE", "2026-01-15 09:30:00"),
            ("usr_dev1", "developer", "developer@example.local", default_pwd_hash, "Arun Kumar", "role_dev", "dept_eng", "ACTIVE", "2026-02-01 10:00:00"),
            ("usr_fin1", "finance", "finance@example.local", default_pwd_hash, "Ananya Patel", "role_fin", "dept_fin", "ACTIVE", "2026-02-10 10:00:00"),
            ("usr_hr1", "hr", "hr@example.local", default_pwd_hash, "Deepak Verma", "role_hr", "dept_hr", "ACTIVE", "2026-02-15 10:00:00"),
            ("usr_intern1", "intern", "intern@example.local", default_pwd_hash, "Rohan Joshi", "role_intern", "dept_eng", "ACTIVE", "2026-08-01 10:00:00"),
            
            # Additional Realistic Colleagues
            ("usr_dev2", "karthik", "karthik.s@example.local", default_pwd_hash, "Karthik Subramanian", "role_dev", "dept_eng", "ACTIVE", "2026-02-15 11:00:00"),
            ("usr_dev3", "neha", "neha.r@example.local", default_pwd_hash, "Neha Reddy", "role_dev", "dept_eng", "ACTIVE", "2026-03-01 11:00:00"),
            ("usr_fin2", "rajesh", "rajesh.m@example.local", default_pwd_hash, "Rajesh Mehra", "role_fin", "dept_fin", "ACTIVE", "2026-03-10 09:00:00"),
            ("usr_hr2", "kavita", "kavita.s@example.local", default_pwd_hash, "Kavita Singh", "role_hr", "dept_hr", "ACTIVE", "2026-03-15 09:00:00"),
            ("usr_analyst1", "analyst", "analyst@example.local", default_pwd_hash, "Siddharth Nair", "role_analyst", "dept_ops", "ACTIVE", "2026-04-01 10:00:00"),
            ("usr_analyst2", "meera", "meera.k@example.local", default_pwd_hash, "Meera Krishnan", "role_analyst", "dept_ops", "ACTIVE", "2026-04-15 10:00:00"),
            ("usr_intern2", "sneha", "sneha.b@example.local", default_pwd_hash, "Sneha Bhat", "role_intern", "dept_eng", "ACTIVE", "2026-08-15 10:00:00"),
            ("usr_dev4", "alok", "alok.g@example.local", default_pwd_hash, "Alok Gupta", "role_dev", "dept_eng", "ACTIVE", "2026-05-01 10:00:00"),
            ("usr_fin3", "tanya", "tanya.d@example.local", default_pwd_hash, "Tanya Das", "role_fin", "dept_fin", "ACTIVE", "2026-05-15 10:00:00"),
            ("usr_ops1", "suresh", "suresh.v@example.local", default_pwd_hash, "Suresh Varma", "role_mgr", "dept_ops", "ACTIVE", "2026-01-20 09:00:00"),
            ("usr_sec2", "aditi", "aditi.p@example.local", default_pwd_hash, "Aditi Prasad", "role_admin", "dept_sec", "ACTIVE", "2026-02-01 09:00:00"),
            ("usr_intern3", "rahul", "rahul.t@example.local", default_pwd_hash, "Rahul Tiwari", "role_intern", "dept_eng", "ACTIVE", "2026-09-01 10:00:00")
        ]
        cursor.executemany("INSERT INTO users (id, username, email, password_hash, full_name, role_id, department_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", users)

        # 6. Resources (22 Realistic Enterprise Resources)
        resources = [
            ("res_01", "Financial_Report_Q3.xlsx", "DOCUMENT", "dept_fin", "usr_fin1", "CONFIDENTIAL", "2026-07-01 10:00:00", "v1.3", "ACTIVE"),
            ("res_02", "Annual_Budget_2026.xlsx", "DOCUMENT", "dept_fin", "usr_fin1", "RESTRICTED", "2026-01-10 10:00:00", "v2.0", "ACTIVE"),
            ("res_03", "Employee_Policy.pdf", "DOCUMENT", "dept_hr", "usr_hr1", "INTERNAL", "2026-01-05 09:00:00", "v1.1", "ACTIVE"),
            ("res_04", "Employee_Onboarding.pdf", "DOCUMENT", "dept_hr", "usr_hr1", "INTERNAL", "2026-01-05 09:00:00", "v1.0", "ACTIVE"),
            ("res_05", "Project_Architecture.pdf", "DOCUMENT", "dept_eng", "usr_dev1", "INTERNAL", "2026-02-10 11:00:00", "v1.2", "ACTIVE"),
            ("res_06", "Source_Code_Repository", "REPOSITORY", "dept_eng", "usr_dev1", "CONFIDENTIAL", "2026-01-01 08:00:00", "v3.4", "ACTIVE"),
            ("res_07", "Security_Audit_Report.pdf", "DOCUMENT", "dept_sec", "usr_admin", "RESTRICTED", "2026-06-15 14:00:00", "v1.1", "ACTIVE"),
            ("res_08", "Marketing_Plan.docx", "DOCUMENT", "dept_mkt", "usr_mgr", "INTERNAL", "2026-03-01 10:00:00", "v1.0", "ACTIVE"),
            ("res_09", "Customer_Analytics.csv", "DATASET", "dept_ops", "usr_analyst1", "CONFIDENTIAL", "2026-04-10 12:00:00", "v2.1", "ACTIVE"),
            ("res_10", "Product_Roadmap.pdf", "DOCUMENT", "dept_eng", "usr_dev1", "INTERNAL", "2026-02-01 10:00:00", "v1.4", "ACTIVE"),
            ("res_11", "Internal_API_Documentation.pdf", "DOCUMENT", "dept_eng", "usr_dev2", "INTERNAL", "2026-03-12 11:00:00", "v1.0", "ACTIVE"),
            ("res_12", "Training_Material.pdf", "DOCUMENT", "dept_hr", "usr_hr2", "PUBLIC", "2026-01-10 09:00:00", "v1.0", "ACTIVE"),
            ("res_13", "Executive_Payroll_2026.xlsx", "DOCUMENT", "dept_hr", "usr_hr1", "RESTRICTED", "2026-01-02 09:00:00", "v1.0", "ACTIVE"),
            ("res_14", "Q3_Expense_Records.xlsx", "DOCUMENT", "dept_fin", "usr_fin2", "CONFIDENTIAL", "2026-07-15 10:00:00", "v1.0", "ACTIVE"),
            ("res_15", "Vulnerability_Scan_Q3.json", "DOCUMENT", "dept_sec", "usr_sec2", "RESTRICTED", "2026-08-01 15:00:00", "v1.0", "ACTIVE"),
            ("res_16", "Cloud_Infrastructure_Terraform", "REPOSITORY", "dept_eng", "usr_dev3", "RESTRICTED", "2026-03-01 09:00:00", "v2.2", "ACTIVE"),
            ("res_17", "Customer_Retention_Model.py", "REPOSITORY", "dept_ops", "usr_analyst2", "CONFIDENTIAL", "2026-05-10 14:00:00", "v1.3", "ACTIVE"),
            ("res_18", "Recruitment_Pipeline_Q4.xlsx", "DOCUMENT", "dept_hr", "usr_hr2", "CONFIDENTIAL", "2026-08-20 11:00:00", "v1.0", "ACTIVE"),
            ("res_19", "Corporate_Travel_Policy.pdf", "DOCUMENT", "dept_ops", "usr_mgr", "PUBLIC", "2026-01-15 10:00:00", "v1.0", "ACTIVE"),
            ("res_20", "Database_Disaster_Recovery.pdf", "DOCUMENT", "dept_eng", "usr_dev1", "RESTRICTED", "2026-04-12 16:00:00", "v1.1", "ACTIVE"),
            ("res_21", "Vendor_Contracts_2026.pdf", "DOCUMENT", "dept_fin", "usr_fin1", "RESTRICTED", "2026-02-18 13:00:00", "v1.0", "ACTIVE"),
            ("res_22", "Brand_Guidelines_2026.pdf", "DOCUMENT", "dept_mkt", "usr_mgr", "PUBLIC", "2026-01-20 10:00:00", "v1.0", "ACTIVE")
        ]
        cursor.executemany("INSERT INTO resources (id, name, type, department_id, owner_id, sensitivity, created_at, current_version, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", resources)

        # 7. Resource Version History (Rich realistic file versions)
        versions = [
            ("res_05", "v1.0", "usr_dev1", "CREATE", "Initial microservices architecture document", "2026-02-10 11:00:00"),
            ("res_05", "v1.1", "usr_dev2", "VERSION_UPDATE", "Added message queue event pipeline specifications", "2026-04-15 14:22:00"),
            ("res_05", "v1.2", "usr_dev1", "VERSION_UPDATE", "Added zero trust authentication architecture section", "2026-07-20 16:45:00"),
            ("res_01", "v1.0", "usr_fin1", "CREATE", "Initial draft of Q3 financial statements", "2026-07-01 10:00:00"),
            ("res_01", "v1.1", "usr_fin2", "VERSION_UPDATE", "Updated tax depreciation models", "2026-08-12 11:30:00"),
            ("res_01", "v1.2", "usr_fin1", "VERSION_UPDATE", "Consolidated regional division revenues", "2026-09-05 09:15:00"),
            ("res_01", "v1.3", "usr_fin3", "VERSION_UPDATE", "Executive signoff modifications", "2026-09-28 17:00:00"),
            ("res_02", "v1.0", "usr_fin1", "CREATE", "Annual corporate budget framework", "2026-01-10 10:00:00"),
            ("res_02", "v2.0", "usr_fin1", "VERSION_UPDATE", "Mid-year budget variance revision", "2026-06-30 15:00:00"),
            ("res_07", "v1.0", "usr_admin", "CREATE", "Comprehensive pentest and IAM vulnerability findings", "2026-06-15 14:00:00"),
            ("res_07", "v1.1", "usr_sec2", "VERSION_UPDATE", "Added remediation milestone checkpoints", "2026-07-02 10:00:00"),
            ("res_09", "v1.0", "usr_analyst1", "CREATE", "Customer churn and cohort analysis raw extract", "2026-04-10 12:00:00"),
            ("res_09", "v2.1", "usr_analyst2", "VERSION_UPDATE", "Enriched with lifetime value scoring", "2026-08-14 13:20:00"),
            ("res_16", "v1.0", "usr_dev3", "CREATE", "AWS VPC and Kubernetes cluster definitions", "2026-03-01 09:00:00"),
            ("res_16", "v2.2", "usr_dev1", "VERSION_UPDATE", "Hardened security groups and IAM role mappings", "2026-08-25 18:00:00")
        ]
        cursor.executemany("INSERT INTO resource_versions (resource_id, version_number, modified_by, action, change_summary, created_at) VALUES (?, ?, ?, ?, ?, ?)", versions)

        # 8. Permissions (70+ permissions covering all lifecycle states and demo scenarios)
        # DEMO SCENARIO 1: Arun (Developer) has READ on Financial_Report_Q3.xlsx with last_used 65 days ago (Inactive)
        # DEMO SCENARIO 2: Rohan (Intern) has EDIT on Security_Audit_Report.pdf (Role Mismatch & Excessive Level)
        # DEMO SCENARIO 3: Siddharth (Analyst) has READ on Vendor_Contracts_2026.pdf with expiry yesterday (Expired)
        # DEMO SCENARIO 4: Arun (Developer) on Database_Disaster_Recovery.pdf extended 3 times (Repeated Extension)
        # DEMO SCENARIO 5: Rohan (Intern) has EDIT on Executive_Payroll_2026.xlsx (Sensitive RESTRICTED resource)
        # Plus active, expiring soon, and clean role permissions.
        permissions_data = [
            # ID, user_id, res_id, type, start, expiry, reason, approver, status, last_used, extensions, created_at
            ("perm_01", "usr_dev1", "res_01", "READ", "2026-07-01", "2026-11-01", "Required for cross-team ERP billing integration", "usr_admin", "ACTIVE", "2026-08-10 14:00:00", 0, "2026-07-01 09:00:00"), # SCENARIO 1: Inactive >65d (today 2026-10-19)
            ("perm_02", "usr_intern1", "res_07", "EDIT", "2026-09-01", "2026-11-30", "Internship documentation review task", "usr_mgr", "ACTIVE", "2026-10-12 11:00:00", 0, "2026-09-01 10:00:00"), # SCENARIO 2: Role Mismatch & Excessive
            ("perm_03", "usr_analyst1", "res_21", "READ", "2026-07-15", "2026-10-18", "Vendor spend analytics modeling", "usr_admin", "ACTIVE", "2026-10-10 16:00:00", 0, "2026-07-15 10:00:00"), # SCENARIO 3: Expired Yesterday
            ("perm_04", "usr_dev1", "res_20", "EDIT", "2026-04-01", "2026-11-15", "Standby engineer for infrastructure migration", "usr_admin", "ACTIVE", "2026-10-14 09:30:00", 3, "2026-04-01 09:00:00"), # SCENARIO 4: Repeated Extension (3 times)
            ("perm_05", "usr_intern1", "res_13", "EDIT", "2026-08-15", "2026-11-15", "Temporary payroll data clean up support", "usr_hr1", "ACTIVE", "2026-10-15 10:00:00", 0, "2026-08-15 09:00:00"), # SCENARIO 5: Intern on Restricted HR file
            
            # Additional Expiring Soon Permissions (< 7 days from Oct 19, 2026)
            ("perm_06", "usr_dev2", "res_09", "READ", "2026-08-20", "2026-10-22", "Customer cohort data pipeline development", "usr_admin", "ACTIVE", "2026-10-18 10:00:00", 1, "2026-08-20 09:00:00"),
            ("perm_07", "usr_fin2", "res_18", "READ", "2026-09-01", "2026-10-24", "Headcount compensation reconciliation", "usr_mgr", "ACTIVE", "2026-10-17 11:30:00", 0, "2026-09-01 10:00:00"),
            ("perm_08", "usr_analyst2", "res_08", "READ", "2026-09-10", "2026-10-21", "Campaign conversion attribution report", "usr_mgr", "ACTIVE", "2026-10-16 14:00:00", 0, "2026-09-10 10:00:00"),

            # Cross-Department Sprawl User (Karthik has 4 departments)
            ("perm_09", "usr_dev2", "res_01", "READ", "2026-06-01", "2026-12-01", "Ad-hoc budget check", "usr_admin", "ACTIVE", "2026-09-15 11:00:00", 1, "2026-06-01 09:00:00"),
            ("perm_10", "usr_dev2", "res_03", "READ", "2026-06-10", "2026-12-10", "Policy portal sync", "usr_admin", "ACTIVE", "2026-09-20 12:00:00", 0, "2026-06-10 09:00:00"),
            ("perm_11", "usr_dev2", "res_09", "EDIT", "2026-06-15", "2026-12-15", "Analytics integration", "usr_admin", "ACTIVE", "2026-10-05 15:00:00", 0, "2026-06-15 09:00:00"),
            ("perm_12", "usr_dev2", "res_06", "EDIT", "2026-02-01", "2026-12-31", "Core codebase repository commit rights", "usr_admin", "ACTIVE", "2026-10-18 16:00:00", 0, "2026-02-01 09:00:00"),

            # Normal Baseline Role Permissions (Clean / Validated)
            ("perm_13", "usr_dev1", "res_06", "EDIT", "2026-02-01", "2026-12-31", "Lead Developer repository master rights", "usr_admin", "ACTIVE", "2026-10-19 11:00:00", 0, "2026-02-01 09:00:00"),
            ("perm_14", "usr_dev1", "res_05", "EDIT", "2026-02-10", "2026-12-31", "Architecture author and maintainer", "usr_admin", "ACTIVE", "2026-10-18 10:00:00", 0, "2026-02-10 10:00:00"),
            ("perm_15", "usr_dev1", "res_10", "EDIT", "2026-02-01", "2026-12-31", "Product technical roadmap ownership", "usr_admin", "ACTIVE", "2026-10-17 14:00:00", 0, "2026-02-01 09:00:00"),
            ("perm_16", "usr_fin1", "res_01", "EDIT", "2026-02-10", "2026-12-31", "Chief accountant and financial controller", "usr_admin", "ACTIVE", "2026-10-19 14:30:00", 0, "2026-02-10 09:00:00"),
            ("perm_17", "usr_fin1", "res_02", "EDIT", "2026-01-10", "2026-12-31", "Budget officer allocation permissions", "usr_admin", "ACTIVE", "2026-10-18 15:00:00", 0, "2026-01-10 09:00:00"),
            ("perm_18", "usr_fin1", "res_14", "EDIT", "2026-07-15", "2026-12-31", "Expense reconciliation manager", "usr_admin", "ACTIVE", "2026-10-17 11:00:00", 0, "2026-07-15 09:00:00"),
            ("perm_19", "usr_hr1", "res_03", "EDIT", "2026-02-15", "2026-12-31", "HR handbook management", "usr_admin", "ACTIVE", "2026-10-15 10:00:00", 0, "2026-02-15 09:00:00"),
            ("perm_20", "usr_hr1", "res_13", "EDIT", "2026-02-15", "2026-12-31", "Executive payroll administrator", "usr_admin", "ACTIVE", "2026-10-19 09:15:00", 0, "2026-02-15 09:00:00"),
            ("perm_21", "usr_hr1", "res_18", "EDIT", "2026-02-15", "2026-12-31", "Recruitment pipeline supervisor", "usr_admin", "ACTIVE", "2026-10-18 16:30:00", 0, "2026-02-15 09:00:00"),
            ("perm_22", "usr_analyst1", "res_09", "READ", "2026-04-10", "2026-12-31", "BI Analyst customer data queries", "usr_mgr", "ACTIVE", "2026-10-19 12:00:00", 0, "2026-04-10 10:00:00"),
            ("perm_23", "usr_analyst1", "res_17", "READ", "2026-05-10", "2026-12-31", "Retention predictive model monitoring", "usr_mgr", "ACTIVE", "2026-10-16 11:00:00", 0, "2026-05-10 10:00:00"),
            ("perm_24", "usr_intern1", "res_12", "READ", "2026-08-01", "2026-11-01", "New hire engineering training curriculum", "usr_dev1", "ACTIVE", "2026-10-18 09:00:00", 0, "2026-08-01 09:00:00"),
            ("perm_25", "usr_intern1", "res_11", "READ", "2026-08-05", "2026-11-05", "Internal API reference for sandbox onboarding", "usr_dev1", "ACTIVE", "2026-10-19 10:30:00", 0, "2026-08-05 09:00:00"),
            
            # Already Expired Permissions from past cycles
            ("perm_26", "usr_intern2", "res_06", "READ", "2026-06-01", "2026-08-31", "Summer internship repository access", "usr_admin", "EXPIRED", "2026-08-28 14:00:00", 0, "2026-06-01 09:00:00"),
            ("perm_27", "usr_dev4", "res_01", "READ", "2026-05-01", "2026-07-31", "Quarterly audit API schema consultation", "usr_admin", "EXPIRED", "2026-07-20 10:00:00", 0, "2026-05-01 09:00:00"),
            ("perm_28", "usr_analyst2", "res_14", "READ", "2026-06-01", "2026-08-31", "Departmental cost attribution study", "usr_mgr", "EXPIRED", "2026-08-15 15:00:00", 0, "2026-06-01 09:00:00"),
            ("perm_29", "usr_fin3", "res_05", "READ", "2026-05-15", "2026-08-15", "Hardware budgeting spec review", "usr_admin", "EXPIRED", "2026-08-01 09:00:00", 0, "2026-05-15 09:00:00"),

            # Previously Revoked Permissions
            ("perm_30", "usr_intern3", "res_16", "EDIT", "2026-09-01", "2026-10-01", "Mistakenly granted infrastructure edit rights", "usr_admin", "REVOKED", "2026-09-02 11:00:00", 0, "2026-09-01 10:00:00"),
            ("perm_31", "usr_dev3", "res_13", "READ", "2026-04-01", "2026-05-01", "Temporary testing on HR payroll API connector", "usr_admin", "REVOKED", "2026-04-20 16:00:00", 0, "2026-04-01 10:00:00"),

            # Revalidated Permissions
            ("perm_32", "usr_fin2", "res_06", "READ", "2026-04-01", "2026-12-31", "Software license compliance tracking", "usr_admin", "REVALIDATED", "2026-10-10 10:00:00", 1, "2026-04-01 09:00:00")
        ]

        # Generate additional realistic active permissions across remaining users to reach 65+ total permissions
        for i in range(33, 68):
            user_target = users[i % len(users)][0]
            res_target = resources[(i * 3) % len(resources)][0]
            perm_t = "READ" if (i % 3 != 0) else "EDIT"
            status_t = "ACTIVE"
            p_id = f"perm_{i:02d}"
            permissions_data.append((
                p_id, user_target, res_target, perm_t,
                "2026-08-01", "2026-12-15", "Standard authorized project allocation",
                "usr_admin", status_t, "2026-10-15 10:00:00", 0, "2026-08-01 09:00:00"
            ))

        for p in permissions_data:
            cursor.execute("""
                INSERT INTO permissions (
                    id, user_id, resource_id, permission_type, start_date, expiry_date,
                    reason, approver_id, status, last_used_at, extension_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[11]))

        # 9. Permission Requests (30+ requests: pending, approved, rejected)
        requests_data = [
            # ID, Code, User, Resource, Type, Duration, Reason, Status, ReviewedBy, ReviewedAt, Comments, PermId, CreatedAt
            ("req_01", "REQ-1024", "usr_intern1", "res_05", "READ", 30, "Need Project Architecture to complete the assigned vulnerability assessment module.", "PENDING", None, None, None, None, "2026-10-19 11:30:00"),
            ("req_02", "REQ-1025", "usr_dev3", "res_07", "READ", 14, "Security review prior to production release v3.4.", "PENDING", None, None, None, None, "2026-10-19 13:15:00"),
            ("req_03", "REQ-1026", "usr_analyst1", "res_02", "READ", 45, "Quarterly OPEX variance correlation against telemetry.", "PENDING", None, None, None, None, "2026-10-19 14:00:00"),
            ("req_04", "REQ-1027", "usr_intern2", "res_11", "READ", 60, "Learning REST API design standards for frontend widget.", "PENDING", None, None, None, None, "2026-10-19 14:45:00"),
            ("req_05", "REQ-1028", "usr_dev4", "res_15", "READ", 7, "Urgent: triage log injection vulnerability flag.", "PENDING", None, None, None, None, "2026-10-19 15:10:00"),
            ("req_06", "REQ-1020", "usr_dev1", "res_01", "READ", 90, "Required for cross-team ERP billing integration.", "APPROVED", "usr_admin", "2026-07-01 10:00:00", "Approved for ERP project duration.", "perm_01", "2026-07-01 08:30:00"),
            ("req_07", "REQ-1021", "usr_intern1", "res_07", "EDIT", 90, "Internship documentation review task.", "APPROVED", "usr_mgr", "2026-09-01 10:15:00", "Approved temporarily by manager.", "perm_02", "2026-09-01 09:30:00"),
            ("req_08", "REQ-1022", "usr_intern1", "res_02", "EDIT", 180, "Assist in annual budget data entry.", "REJECTED", "usr_admin", "2026-09-05 14:00:00", "Rejected: Interns must not have EDIT access to RESTRICTED financial budgets.", None, "2026-09-05 11:00:00"),
            ("req_09", "REQ-1023", "usr_dev2", "res_13", "EDIT", 30, "Testing database export script.", "REJECTED", "usr_admin", "2026-09-10 16:30:00", "Rejected: Development testing must use synthetic data, not live payroll.", None, "2026-09-10 15:00:00")
        ]
        # Generate 20 more historical approved/rejected requests
        for i in range(10, 31):
            req_c = f"REQ-{1020+i}"
            u_t = users[i % len(users)][0]
            r_t = resources[i % len(resources)][0]
            st = "APPROVED" if i % 2 == 0 else "REJECTED"
            rev_by = "usr_admin" if i % 3 == 0 else "usr_mgr"
            requests_data.append((
                f"req_{i:02d}", req_c, u_t, r_t, "READ", 30,
                f"Historical operational project review requirement batch #{i}",
                st, rev_by, "2026-08-15 10:00:00",
                "Processed in regular governance cycle.", None, "2026-08-14 09:00:00"
            ))

        for r in requests_data:
            cursor.execute("""
                INSERT INTO permission_requests (
                    id, request_code, user_id, resource_id, permission_type, duration_days,
                    reason, status, reviewed_by, reviewed_at, review_comments, permission_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, r)

        # 10. Access Events (File Activity Tracking - 120+ events)
        actions = ["OPEN", "READ", "EDIT", "DOWNLOAD", "SHARE", "VERSION_UPDATE"]
        ips = ["192.168.10.25", "192.168.10.44", "192.168.20.12", "192.168.30.88", "192.168.10.105"]
        devices = ["Windows 11 Workstation", "macOS Developer Laptop", "Ubuntu Engineering Server", "Corporate Windows Desktop"]
        
        events = []
        # Specific events for Arun Kumar (usr_dev1)
        events.append(("usr_dev1", "res_05", "EDIT", "192.168.10.25", "Windows 11 Workstation", "SUCCESS", "2026-07-20 16:45:00"))
        events.append(("usr_dev1", "res_05", "READ", "192.168.10.25", "Windows 11 Workstation", "SUCCESS", "2026-10-18 10:00:00"))
        events.append(("usr_dev1", "res_01", "READ", "192.168.10.25", "Windows 11 Workstation", "SUCCESS", "2026-08-10 14:00:00")) # 70 days ago
        events.append(("usr_intern1", "res_07", "READ", "192.168.20.12", "Corporate Windows Desktop", "SUCCESS", "2026-10-12 11:00:00"))
        events.append(("usr_intern1", "res_13", "EDIT", "192.168.20.12", "Corporate Windows Desktop", "SUCCESS", "2026-10-15 10:00:00"))
        events.append(("usr_intern1", "res_02", "OPEN", "192.168.20.12", "Corporate Windows Desktop", "DENIED", "2026-10-16 11:20:00"))

        for i in range(1, 115):
            u_t = users[i % len(users)][0]
            r_t = resources[i % len(resources)][0]
            act = actions[i % len(actions)]
            ip = ips[i % len(ips)]
            dev = devices[i % len(devices)]
            res_flag = "DENIED" if (i % 17 == 0) else "SUCCESS"
            day = 10 + (i % 9)
            hour = 8 + (i % 10)
            events.append((u_t, r_t, act, ip, dev, res_flag, f"2026-10-{day:02d} {hour:02d}:15:00"))

        cursor.executemany("""
            INSERT INTO access_events (user_id, resource_id, action, ip_address, device, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, events)

        # 11. Permission History (Timeline audit trail for permissions)
        history = [
            ("perm_01", "usr_dev1", "res_01", "REQUESTED", "Requested READ access for ERP billing integration", "usr_dev1", "2026-07-01 08:30:00"),
            ("perm_01", "usr_dev1", "res_01", "APPROVED", "Approved by System Administrator", "usr_admin", "2026-07-01 10:00:00"),
            ("perm_01", "usr_dev1", "res_01", "GRANTED", "READ permission granted until 2026-11-01", "usr_admin", "2026-07-01 10:00:00"),
            ("perm_01", "usr_dev1", "res_01", "ACCESSED", "Resource opened and read by user", "usr_dev1", "2026-08-10 14:00:00"),
            ("perm_02", "usr_intern1", "res_07", "REQUESTED", "Requested EDIT access for documentation task", "usr_intern1", "2026-09-01 09:30:00"),
            ("perm_02", "usr_intern1", "res_07", "APPROVED", "Approved by Manager", "usr_mgr", "2026-09-01 10:15:00"),
            ("perm_02", "usr_intern1", "res_07", "GRANTED", "EDIT permission granted until 2026-11-30", "usr_mgr", "2026-09-01 10:15:00"),
            ("perm_04", "usr_dev1", "res_20", "GRANTED", "Initial permission granted for standby migration", "usr_admin", "2026-04-01 09:00:00"),
            ("perm_04", "usr_dev1", "res_20", "EXTENDED", "Permission extended by 30 days (Extension #1)", "usr_admin", "2026-06-01 10:00:00"),
            ("perm_04", "usr_dev1", "res_20", "EXTENDED", "Permission extended by 30 days (Extension #2)", "usr_admin", "2026-08-01 11:00:00"),
            ("perm_04", "usr_dev1", "res_20", "EXTENDED", "Permission extended by 45 days (Extension #3)", "usr_admin", "2026-10-01 11:30:00"),
            ("perm_26", "usr_intern2", "res_06", "GRANTED", "Internship codebase read permission granted", "usr_admin", "2026-06-01 09:00:00"),
            ("perm_26", "usr_intern2", "res_06", "EXPIRED", "Permission expired automatically. User account preserved.", "SYSTEM", "2026-08-31 23:59:59")
        ]
        cursor.executemany("""
            INSERT INTO permission_history (permission_id, user_id, resource_id, event_type, details, performed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, history)

        # 12. Audit Logs (100+ Enterprise Audit Trail Records)
        audit_records = [
            ("2026-10-19 09:00:00", "usr_admin", "LOGIN", None, "SUCCESS", "Administrator console session established", "usr_admin", "SES-901", "192.168.10.10"),
            ("2026-10-19 09:15:00", "usr_hr1", "RESOURCE_EDITED", "res_13", "SUCCESS", "Payroll salary bands calibrated", "usr_hr1", "res_13", "192.168.20.12"),
            ("2026-10-19 10:00:00", "usr_mgr", "ACCESS_APPROVED", "res_08", "SUCCESS", "Marketing plan read access authorized", "usr_mgr", "REQ-1019", "192.168.10.15"),
            ("2026-10-19 11:30:00", "usr_intern1", "ACCESS_REQUEST", "res_05", "SUCCESS", "Request submitted for project architecture review", "usr_intern1", "REQ-1024", "192.168.20.12"),
            ("2026-10-19 13:15:00", "usr_dev3", "ACCESS_REQUEST", "res_07", "SUCCESS", "Request submitted for security audit report", "usr_dev3", "REQ-1025", "192.168.10.25"),
            ("2026-10-19 14:00:00", "usr_analyst1", "ACCESS_REQUEST", "res_02", "SUCCESS", "Request submitted for budget analysis", "usr_analyst1", "REQ-1026", "192.168.30.88")
        ]
        actions_list = [
            "ACCESS_REQUEST", "ACCESS_APPROVED", "ACCESS_REJECTED", "PERMISSION_GRANTED",
            "PERMISSION_REVOKED", "PERMISSION_EXTENDED", "RESOURCE_OPENED", "RESOURCE_EDITED",
            "RESOURCE_DOWNLOADED", "REVALIDATION_REQUESTED", "REVALIDATION_APPROVED"
        ]
        for i in range(1, 105):
            u_t = users[i % len(users)][0]
            r_t = resources[i % len(resources)][0]
            act = actions_list[i % len(actions_list)]
            day = 1 + (i % 18)
            hour = 8 + (i % 10)
            audit_records.append((
                f"2026-10-{day:02d} {hour:02d}:20:00",
                u_t, act, r_t, "SUCCESS",
                f"Automated access governance audit milestone #{i}",
                u_t, f"REF-{i+2000}", ips[i % len(ips)]
            ))

        cursor.executemany("""
            INSERT INTO audit_logs (timestamp, user_id, action, resource_id, result, reason, performed_by, reference_id, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, audit_records)

        # 13. Notifications
        notifications = [
            ("usr_admin", "High Risk Permission Detected", "Intern Rohan Joshi has EDIT access to restricted HR file Executive_Payroll_2026.xlsx", "HIGH_RISK", "/findings", 0, "2026-10-19 09:30:00"),
            ("usr_admin", "Permission Inactivity Alert", "Arun Kumar has not used Financial_Report_Q3.xlsx in over 65 days.", "INACTIVITY_ALERT", "/access-reviews", 0, "2026-10-19 10:00:00"),
            ("usr_admin", "New Access Request Pending", "REQ-1024 submitted by Rohan Joshi for Project_Architecture.pdf", "REQUEST_PENDING", "/access-requests", 0, "2026-10-19 11:30:00"),
            ("usr_admin", "Permission Expiring Soon", "Permission for Karthik Subramanian on Customer_Analytics.csv expires in 3 days.", "EXPIRY_WARNING", "/permissions", 0, "2026-10-19 12:00:00"),
            ("usr_analyst1", "Permission Expired", "Your access to Vendor_Contracts_2026.pdf expired on 2026-10-18.", "EXPIRED_AUTO", "/permissions", 1, "2026-10-19 00:01:00")
        ]
        cursor.executemany("""
            INSERT INTO notifications (user_id, title, message, type, link, is_read, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, notifications)

    # Run the rules-based detection engine once to calculate all risk scores and seed findings
    res = run_permission_creep_detector("2026-10-19 15:30:00")
    print(f"Seed completed successfully: {res}")

if __name__ == "__main__":
    from backend.database.schema import init_db
    init_db()
    seed_demo_database()
