from auth.passwords import hash_password, verify_password
from auth.service import AttemptThrottle, AuthError, AuthService
from tests.helpers import http_request, login_role


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


def test_set_password_revokes_existing_sessions(database, durable_settings):
    service = AuthService(database, durable_settings)
    service.bootstrap()
    user = service.authenticate("auditor", "auditor-pass")
    token = service.create_session(user)
    assert service.resolve_token(token) is not None
    service.set_password("auditor", "replacement-pass")
    assert service.resolve_token(token) is None
    assert service.authenticate("auditor", "replacement-pass").id == user.id


def test_attempt_throttle_blocks_then_clears():
    throttle = AttemptThrottle(max_failures=2, window_seconds=60)
    now = 1_000.0
    assert throttle.blocked("user-1", now=now) is False
    throttle.record_failure("user-1", now=now)
    throttle.record_failure("user-1", now=now + 1)
    assert throttle.blocked("user-1", now=now + 2) is True
    throttle.clear("user-1")
    assert throttle.blocked("user-1", now=now + 3) is False


def test_change_password_keeps_current_session_and_revokes_others(api_context):
    app, _service, _evidence, _environment = api_context
    current = app.state.auth_cookies["auditor"]
    other = login_role(app, "auditor", "auditor-pass")
    new_secret = "replacement-pass"

    changed = http_request(
        app,
        "POST",
        "/api/auth/password",
        cookies=current,
        auth=False,
        json={
            "current_password": "auditor-pass",
            "new_password": new_secret,
        },
    )
    still_me = http_request(
        app, "GET", "/api/auth/me", cookies=current, auth=False
    )
    other_me = http_request(
        app, "GET", "/api/auth/me", cookies=other, auth=False
    )
    old_login = http_request(
        app,
        "POST",
        "/api/auth/login",
        auth=False,
        json={"username": "auditor", "password": "auditor-pass"},
    )
    new_login = http_request(
        app,
        "POST",
        "/api/auth/login",
        auth=False,
        json={"username": "auditor", "password": new_secret},
    )

    assert changed.status_code == 200
    assert changed.json()["username"] == "auditor"
    assert new_secret not in changed.text
    assert "auditor-pass" not in changed.text
    assert still_me.status_code == 200
    assert other_me.status_code == 401
    assert old_login.status_code == 401
    assert new_login.status_code == 200


def test_change_password_wrong_current_is_generic_401(api_context):
    app, _service, _evidence, _environment = api_context
    response = http_request(
        app,
        "POST",
        "/api/auth/password",
        json={
            "current_password": "wrong-current",
            "new_password": "replacement-pass",
        },
    )
    me = http_request(app, "GET", "/api/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_credentials"
    assert "wrong-current" not in response.text
    assert "replacement-pass" not in response.text
    assert me.status_code == 200
    assert app.state.auth.authenticate("auditor", "auditor-pass").username == "auditor"


def test_change_password_short_new_password_is_422(api_context):
    app, _service, _evidence, _environment = api_context
    response = http_request(
        app,
        "POST",
        "/api/auth/password",
        json={"current_password": "auditor-pass", "new_password": "short"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_password"
    assert app.state.auth.authenticate("auditor", "auditor-pass").username == "auditor"


def test_viewer_can_change_own_password(api_context):
    app, _service, _evidence, _environment = api_context
    cookies = app.state.auth_cookies["viewer"]
    new_secret = "viewer-next-pass"
    response = http_request(
        app,
        "POST",
        "/api/auth/password",
        cookies=cookies,
        auth=False,
        json={
            "current_password": "viewer-pass",
            "new_password": new_secret,
        },
    )
    me = http_request(app, "GET", "/api/auth/me", cookies=cookies, auth=False)
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    assert new_secret not in response.text
    assert me.status_code == 200
    assert app.state.auth.authenticate("viewer", new_secret).username == "viewer"


def test_change_password_requires_login(api_context):
    app, _service, _evidence, _environment = api_context
    response = http_request(
        app,
        "POST",
        "/api/auth/password",
        auth=False,
        json={
            "current_password": "auditor-pass",
            "new_password": "replacement-pass",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unauthenticated"


def test_change_password_rate_limit_stays_generic_401(api_context):
    app, _service, _evidence, _environment = api_context
    app.state.auth._password_throttle = AttemptThrottle(
        max_failures=1, window_seconds=60
    )
    first = http_request(
        app,
        "POST",
        "/api/auth/password",
        json={
            "current_password": "wrong-current",
            "new_password": "replacement-pass",
        },
    )
    second = http_request(
        app,
        "POST",
        "/api/auth/password",
        json={
            "current_password": "auditor-pass",
            "new_password": "replacement-pass",
        },
    )
    assert first.status_code == 401
    assert second.status_code == 401
    assert second.json()["detail"]["code"] == "invalid_credentials"
    assert app.state.auth.authenticate("auditor", "auditor-pass").username == "auditor"

