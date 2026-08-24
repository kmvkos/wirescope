from auth.passwords import hash_password, verify_password
from auth.service import AuthError, AuthService
from tests.helpers import http_request


def test_password_hashes_are_salted_and_verified():
    first = hash_password("correct-horse")
    second = hash_password("correct-horse")
    assert first != second
    assert verify_password("correct-horse", first)
    assert not verify_password("wrong-horse", first)


def test_bootstrap_creates_auditor_and_viewer_once(database, durable_settings):
    service = AuthService(database, durable_settings)
    created = service.bootstrap()
    again = service.bootstrap()

    assert {user.role.value for user in created} == {"auditor", "viewer"}
    assert again == []
    auditor = service.authenticate("auditor", "auditor-pass")
    viewer = service.authenticate("viewer", "viewer-pass")
    assert auditor.can_mutate is True
    assert viewer.can_mutate is False


def test_unknown_user_does_not_reveal_existence(database, durable_settings):
    service = AuthService(database, durable_settings)
    try:
        service.authenticate("missing", "password12")
    except AuthError as exc:
        assert exc.code == "invalid_credentials"
    else:
        raise AssertionError("missing user must fail closed")


def test_health_is_public_but_environment_requires_login(api_context):
    app, _service, _evidence, _environment = api_context

    health = http_request(app, "GET", "/api/health", auth=False)
    environment = http_request(app, "GET", "/api/environment", auth=False)
    me = http_request(app, "GET", "/api/auth/me", auth=False)

    assert health.status_code == 200
    assert environment.status_code == 401
    assert environment.json()["detail"]["code"] == "unauthenticated"
    assert me.status_code == 401


def test_login_logout_revokes_session(api_context):
    app, _service, _evidence, _environment = api_context
    cookies = app.state.auth_cookies["auditor"]

    me = http_request(app, "GET", "/api/auth/me", cookies=cookies, auth=False)
    assert me.status_code == 200
    assert me.json()["role"] == "auditor"
    assert "start_audits" in me.json()["capabilities"]

    logout = http_request(
        app,
        "POST",
        "/api/auth/logout",
        cookies=cookies,
        auth=False,
    )
    assert logout.status_code == 204
    after = http_request(app, "GET", "/api/auth/me", cookies=cookies, auth=False)
    assert after.status_code == 401
