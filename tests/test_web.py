import pytest
from fastapi.testclient import TestClient

from rdp_guard.auth import AuthenticationError, Dispatcher, RateLimitError
from rdp_guard.web.app import create_app
from rdp_guard.windows.ipc import RemoteError

PASSWORD = "test-only-long-password-987"
ORIGIN = {"origin": "http://127.0.0.1:8787"}


@pytest.fixture
def web(guard):
    dispatcher = Dispatcher(guard)
    dispatcher.auth.create_admin("operator", PASSWORD)
    class Client:
        def call(self, request):
            try:
                return dispatcher(request, {"role": "web", "sid": "service"})
            except RateLimitError as exc:
                raise RemoteError(str(exc), 429) from exc
            except AuthenticationError as exc:
                raise RemoteError(str(exc), 401) from exc
    with TestClient(create_app(Client()), base_url="http://127.0.0.1:8787", client=("127.0.0.1", 12345)) as client:
        yield client, dispatcher


def login(client):
    response = client.post("/api/login", headers=ORIGIN, json={"username": "operator", "password": PASSWORD})
    assert response.status_code == 200
    return client.get("/api/session").json()["csrf"]


def test_anonymous_rds_user_cannot_access_data_or_mutate(web):
    client, _ = web
    assert client.get("/api/session").status_code == 401
    for operation in ("status", "preflight", "events", "block", "export-config", "emergency-disable"):
        assert client.post("/api/rpc", headers=ORIGIN, json={"op": operation}).status_code == 401
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_password_hash_is_argon2id_and_cookie_is_httponly(web):
    client, dispatcher = web
    response = client.post("/api/login", headers=ORIGIN, json={"username": "operator", "password": PASSWORD})
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert dispatcher.guard.store.rows("SELECT password_hash FROM admins")[0]["password_hash"].startswith("$argon2id$")


def test_mutations_require_csrf_at_guard_boundary(web):
    client, _ = web
    csrf = login(client)
    request = {"op": "whitelist-add", "args": {"network": "198.51.100.7"}}
    assert client.post("/api/rpc", headers=ORIGIN, json=request).status_code == 401
    assert client.post("/api/rpc", headers=ORIGIN | {"x-csrf-token": csrf}, json=request).status_code == 200


def test_cross_origin_and_dns_rebinding_denied(web):
    client, _ = web
    login(client)
    assert client.post("/api/rpc", headers={"origin": "https://evil.example"}, json={"op": "status"}).status_code == 403
    assert client.get("/api/session", headers={"host": "evil.example"}).status_code == 403
    assert client.post("/api/login", json={}).status_code == 403


def test_external_address_denied_even_with_valid_host():
    with TestClient(create_app(), base_url="http://127.0.0.1:8787", client=("192.0.2.9", 40000)) as client:
        assert client.get("/login").status_code == 403


def test_logout_and_expiry_revoke_session(web):
    client, dispatcher = web
    csrf = login(client)
    assert client.post("/api/rpc", headers=ORIGIN | {"x-csrf-token": csrf}, json={"op": "logout"}).status_code == 200
    assert client.get("/api/session").status_code == 401
    login(client)
    dispatcher.guard.clock.now += 1801
    assert client.get("/api/session").status_code == 401


def test_login_rate_limit_is_persistent_and_global(web):
    client, _ = web
    for index in range(10):
        response = client.post("/api/login", headers=ORIGIN, json={"username": f"missing{index}", "password": "bad"})
        assert response.status_code == 401
    assert client.post("/api/login", headers=ORIGIN, json={"username": "operator", "password": PASSWORD}).status_code == 429


def test_security_headers_and_no_cdn(web):
    client, _ = web
    login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert 'src="https://' not in response.text
    assert client.get("/docs").status_code == 404


def test_ipc_actor_cannot_be_spoofed(web):
    _, dispatcher = web
    with pytest.raises(ValueError, match="envelope"):
        dispatcher({"op": "status", "role": "admin"}, {"role": "web", "sid": "service"})
    with pytest.raises(AuthenticationError):
        dispatcher({"op": "status"}, {"role": "user", "sid": "ordinary-rds-user"})


def test_export_never_contains_credentials(web):
    client, _ = web
    login(client)
    data = client.post("/api/rpc", headers=ORIGIN, json={"op": "export-config"}).text
    assert "password" not in data and "$argon2" not in data and "csrf" not in data
