import pytest
from fastapi.testclient import TestClient
from backend.api.main import app
from scripts.seed_database import seed_demo_database

client = TestClient(app)

@pytest.fixture(autouse=True)
def run_before_and_after_tests():
    # Setup: ensure DB has fresh seed
    seed_demo_database()
    yield

def test_login_success():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "DemoPassword123!"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["role_name"] == "System Administrator"

def test_login_invalid_password():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword"})
    assert response.status_code == 401

def test_dashboard_metrics_authenticated():
    # Login as admin
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "DemoPassword123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["total_users"] >= 15
    assert data["summary"]["active_permissions"] > 0
    assert "permissions_by_department" in data["charts"]

def test_access_request_and_approval_workflow():
    # 1. Login as intern
    intern_login = client.post("/api/auth/login", json={"username": "intern", "password": "DemoPassword123!"})
    intern_token = intern_login.json()["access_token"]
    intern_headers = {"Authorization": f"Bearer {intern_token}"}

    # 2. Submit access request
    req_body = {
        "resource_id": "res_05",
        "permission_type": "READ",
        "duration_days": 30,
        "reason": "Test vulnerability assessment research."
    }
    submit_res = client.post("/api/requests", json=req_body, headers=intern_headers)
    assert submit_res.status_code == 200
    req_id = submit_res.json()["request_id"]

    # 3. Login as admin to approve
    admin_login = client.post("/api/auth/login", json={"username": "admin", "password": "DemoPassword123!"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    appr_res = client.post(f"/api/requests/{req_id}/approve", json={"comments": "Approved via automated test"}, headers=admin_headers)
    assert appr_res.status_code == 200
    perm_id = appr_res.json()["permission_id"]

    # 4. Verify permission is active
    perm_res = client.get(f"/api/permissions/{perm_id}", headers=admin_headers)
    assert perm_res.status_code == 200
    assert perm_res.json()["permission"]["status"] == "ACTIVE"

def test_revalidation_and_revocation():
    admin_login = client.post("/api/auth/login", json={"username": "admin", "password": "DemoPassword123!"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Revalidate perm_01 (the inactive one)
    reval_res = client.post("/api/permissions/perm_01/revalidate", json={"reason": "Still needed for monthly financial audit reconciliations."}, headers=admin_headers)
    assert reval_res.status_code == 200

    # Check status
    perm_res = client.get("/api/permissions/perm_01", headers=admin_headers)
    assert perm_res.json()["permission"]["status"] == "REVALIDATED"

    # Revoke perm_02
    rev_res = client.post("/api/permissions/perm_02/revoke", json={"reason": "Security review completed."}, headers=admin_headers)
    assert rev_res.status_code == 200
    perm_res2 = client.get("/api/permissions/perm_02", headers=admin_headers)
    assert perm_res2.json()["permission"]["status"] == "REVOKED"

def test_resource_versioning():
    dev_login = client.post("/api/auth/login", json={"username": "developer", "password": "DemoPassword123!"})
    token = dev_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/resources/res_05/version", json={"change_summary": "Added distributed cache sync spec"}, headers=headers)
    assert res.status_code == 200
    assert "version" in res.json()

    # Verify detail shows the new version
    detail_res = client.get("/api/resources/res_05", headers=headers)
    assert detail_res.status_code == 200
    versions = detail_res.json()["versions"]
    assert any("distributed cache" in v["change_summary"] for v in versions)

def test_pdf_report_generation():
    admin_login = client.post("/api/auth/login", json={"username": "admin", "password": "DemoPassword123!"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get("/api/reports/download-pdf", headers=admin_headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert len(res.content) > 1000
