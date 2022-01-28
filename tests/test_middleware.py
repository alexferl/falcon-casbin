import casbin
import falcon
import pytest
from pretend import stub

from falcon_casbin import CasbinMiddleware

import falcon.testing

falcon.testing.create_req()


def create_req_stub(uri, method, context=None):
    req = falcon.testing.create_req(method=method)
    req.uri_template = uri
    req.context = context
    return req


def test_no_policy_or_adapter_raises():
    with pytest.raises(ValueError):
        CasbinMiddleware("tests/fixtures/model.conf")


def test_adapter():
    middleware = CasbinMiddleware("tests/fixtures/model.conf", adapter=casbin.Adapter())
    req_stub = create_req_stub("/", "GET", None)

    with pytest.raises(falcon.HTTPForbidden):
        middleware.process_resource(req_stub, None, None, None)


def test_success_callback():
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf",
        "tests/fixtures/policy.csv",
        success_callback=lambda role, obj, act: None,
    )
    req_stub = create_req_stub("/", "GET", None)

    middleware.process_resource(req_stub, None, None, None)


def test_failure_callback():
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf",
        "tests/fixtures/policy.csv",
        failure_callback=lambda roles, obj, act: None,
    )
    req_stub = create_req_stub("/unknown", "GET", None)

    with pytest.raises(falcon.HTTPForbidden):
        middleware.process_resource(req_stub, None, None, None)


def test_failover_to_default_role():
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf", "tests/fixtures/policy.csv"
    )
    req_stub = create_req_stub("/", "GET", None)

    middleware.process_resource(req_stub, None, None, None)


def test_failover_to_header():
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf",
        "tests/fixtures/policy.csv",
        enable_roles_header=True,
    )
    req_stub = create_req_stub("/", "GET", None)

    middleware.process_resource(req_stub, None, None, None)


def test_unknown_route_should_fail():
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf", "tests/fixtures/policy.csv"
    )
    context = stub(roles=["admin"])
    req_stub = create_req_stub("/unknown", "PUT", context)

    with pytest.raises(falcon.HTTPForbidden):
        middleware.process_resource(req_stub, None, None, None)


@pytest.mark.parametrize(
    "uri, method, roles",
    [
        ("/", "GET", ["any"]),
        ("/users", "POST", ["any"]),
        ("/", "GET", ["user"]),
        ("/users/1", "GET", ["user"]),
        ("/users/1", "PUT", ["user"]),
        ("/users/1", "DELETE", ["admin"]),
    ],
)
def test_with_valid_role(uri, method, roles):
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf", "tests/fixtures/policy.csv"
    )
    context = stub(roles=roles)
    req_stub = create_req_stub(uri, method, context)

    middleware.process_resource(req_stub, None, None, None)


@pytest.mark.parametrize(
    "uri, method, roles",
    [
        ("/users/1", "GET", ["any"]),
        ("/users/1", "PUT", ["any"]),
        ("/users/1", "DELETE", ["user"]),
    ],
)
def test_with_invalid_role(uri, method, roles):
    middleware = CasbinMiddleware(
        "tests/fixtures/model.conf", "tests/fixtures/policy.csv"
    )
    context = stub(roles=roles)
    req_stub = create_req_stub(uri, method, context)

    with pytest.raises(falcon.HTTPForbidden):
        middleware.process_resource(req_stub, None, None, None)
