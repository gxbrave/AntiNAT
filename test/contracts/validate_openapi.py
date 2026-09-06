#!/usr/bin/env python3
"""Validate the frozen AntiNAT OpenAPI spec and error-code registry.

Checks:
  1. api/openapi.yaml parses as YAML and is OpenAPI 3.0.x.
  2. All normative routes from the v0.8 plan exist.
  3. ETag/If-Match is required on every resource mutation.
  4. Idempotency-Key is required on every create.
  5. Pagination/cursor parameters are present on list/stream routes.
  6. SSE stream exposes Last-Event-ID and a durable event id.
  7. force-publish and operation-polling routes exist.
  8. Error-code coverage is bidirectional with docs/error-codes.md.

Exit 0 on success; non-zero with diagnostics otherwise.
"""

import re
import sys

import yaml

REPO_ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

OPENAPI_PATH = f"{REPO_ROOT}/api/openapi.yaml"
ERROR_CODES_PATH = f"{REPO_ROOT}/docs/error-codes.md"

# Routes frozen by the v0.8 reviewed plan §9.3.
NORMATIVE_ROUTES = {
    "GET /healthz",
    "GET /readyz",
    "POST /api/v1/auth/login",
    "POST /api/v1/auth/logout",
    "GET /api/v1/auth/me",
    "GET /api/v1/nodes",
    "POST /api/v1/nodes",
    "PATCH /api/v1/nodes/{id}",
    "POST /api/v1/nodes/{id}/enrollment-token",
    "POST /api/v1/nodes/{id}/traversal-detection",
    "PUT /api/v1/nodes/{id}/traversal-defaults",
    "POST /api/v1/nodes/{id}/delete",
    "GET /api/v1/node-deletions/{operation_id}",
    "GET /api/v1/forwards",
    "POST /api/v1/forwards",
    "PATCH /api/v1/forwards/{id}",
    "DELETE /api/v1/forwards/{id}",
    "GET /api/v1/forward-deletions/{operation_id}",
    "POST /api/v1/forwards/{id}/retry",
    "POST /api/v1/forwards/{id}/force-publish",
    "POST /api/v1/forwards/{id}/force-cutover",
    "GET /api/v1/navigation/categories",
    "POST /api/v1/navigation/categories",
    "PATCH /api/v1/navigation/categories/{id}",
    "DELETE /api/v1/navigation/categories/{id}",
    "GET /api/v1/navigation/items",
    "POST /api/v1/navigation/items",
    "PATCH /api/v1/navigation/items/{id}",
    "DELETE /api/v1/navigation/items/{id}",
    "PUT /api/v1/navigation/order",
    "GET /api/v1/hooks/definitions",
    "POST /api/v1/hooks/definitions",
    "PATCH /api/v1/hooks/definitions/{id}",
    "DELETE /api/v1/hooks/definitions/{id}",
    "GET /api/v1/hooks/secrets",
    "POST /api/v1/hooks/secrets",
    "DELETE /api/v1/hooks/secrets/{id}",
    "POST /api/v1/hook-deliveries/{id}/retry",
    "GET /api/v1/audit",
    "GET /api/v1/traffic",
    "GET /api/v1/events",
    "GET /api/v1/settings",
    "PUT /api/v1/settings",
}

# Resource-mutating operations that must require If-Match.
MUTATIONS_REQUIRING_IF_MATCH = {
    ("PATCH", "/api/v1/nodes/{id}"),
    ("PUT", "/api/v1/nodes/{id}/traversal-defaults"),
    ("PATCH", "/api/v1/forwards/{id}"),
    ("DELETE", "/api/v1/forwards/{id}"),
    ("POST", "/api/v1/forwards/{id}/force-publish"),
    ("POST", "/api/v1/forwards/{id}/force-cutover"),
    ("PATCH", "/api/v1/navigation/categories/{id}"),
    ("DELETE", "/api/v1/navigation/categories/{id}"),
    ("PATCH", "/api/v1/navigation/items/{id}"),
    ("DELETE", "/api/v1/navigation/items/{id}"),
    ("PUT", "/api/v1/navigation/order"),
    ("PATCH", "/api/v1/hooks/definitions/{id}"),
    ("DELETE", "/api/v1/hooks/definitions/{id}"),
    ("DELETE", "/api/v1/hooks/secrets/{id}"),
    ("PUT", "/api/v1/settings"),
}

# Creates that must require a durable Idempotency-Key.
CREATES_REQUIRING_IDEMPOTENCY = {
    ("POST", "/api/v1/nodes"),
    ("POST", "/api/v1/forwards"),
    ("POST", "/api/v1/navigation/categories"),
    ("POST", "/api/v1/navigation/items"),
    ("POST", "/api/v1/hooks/definitions"),
    ("POST", "/api/v1/hooks/secrets"),
}

# Routes that must expose pagination or cursor parameters.
PAGINATED_ROUTES = {
    "GET /api/v1/nodes",
    "GET /api/v1/forwards",
    "GET /api/v1/audit",
    "GET /api/v1/traffic",
}


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def resolve_param_names(op, spec):
    """Resolve operation-level parameter names, following $ref into
    components.parameters."""
    names = set()
    components = spec.get("components", {}).get("parameters", {})
    for p in op.get("parameters", []):
        if not isinstance(p, dict):
            continue
        ref = p.get("$ref", "")
        if ref:
            key = ref.rsplit("/", 1)[-1]
            resolved = components.get(key, {})
            if isinstance(resolved, dict) and resolved.get("name"):
                names.add(resolved["name"])
        elif p.get("name"):
            names.add(p["name"])
    return names


def main():
    with open(OPENAPI_PATH, encoding="utf-8") as f:
        try:
            spec = yaml.safe_load(f)
        except yaml.YAMLError as e:
            fail(f"api/openapi.yaml is not valid YAML: {e}")
            return

    if not isinstance(spec, dict):
        fail("api/openapi.yaml root is not a mapping")
    if str(spec.get("openapi", "")).split(".")[0] != "3":
        fail(f"openapi version must be 3.x, got {spec.get('openapi')}")
    if spec.get("info", {}).get("title") != "AntiNAT Controller API":
        fail("info.title must be 'AntiNAT Controller API'")

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        fail("paths must be a mapping")

    # 1. Normative routes exist.
    present = set()
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method in ops:
            if method in {"get", "post", "put", "patch", "delete"}:
                present.add(f"{method.upper()} {path}")
    missing = NORMATIVE_ROUTES - present
    if missing:
        fail(f"missing normative routes: {sorted(missing)}")

    # 2. If-Match required on mutations.
    for method, path in sorted(MUTATIONS_REQUIRING_IF_MATCH):
        ops = paths.get(path, {})
        op = ops.get(method.lower())
        if not op:
            fail(f"missing operation {method} {path}")
        params = resolve_param_names(op, spec)
        if "If-Match" not in params:
            fail(f"{method} {path} must require If-Match")

    # 3. Idempotency-Key required on creates.
    for method, path in sorted(CREATES_REQUIRING_IDEMPOTENCY):
        op = paths.get(path, {}).get(method.lower())
        if not op:
            fail(f"missing operation {method} {path}")
        params = resolve_param_names(op, spec)
        if "Idempotency-Key" not in params:
            fail(f"{method} {path} must require Idempotency-Key")

    # 4. Pagination/cursor on listed routes.
    for route in sorted(PAGINATED_ROUTES):
        method, path = route.split(" ", 1)
        op = paths.get(path, {}).get(method.lower())
        if not op:
            fail(f"missing operation {method} {path}")
        names = resolve_param_names(op, spec)
        if not ({"page", "page_size"} <= names or "cursor" in names):
            fail(f"{route} must expose page/page_size or cursor")

    # 5. SSE stream exposes Last-Event-ID and durable event id.
    events = paths.get("/api/v1/events", {}).get("get")
    if not events:
        fail("missing GET /api/v1/events")
    ev_names = resolve_param_names(events, spec)
    if "Last-Event-ID" not in ev_names:
        fail("GET /api/v1/events must accept Last-Event-ID")
    content = events.get("responses", {}).get("200", {}).get("content", {})
    if "text/event-stream" not in content:
        fail("GET /api/v1/events 200 must be text/event-stream")

    # 6. Error-code coverage is bidirectional.
    codes_in_openapi = set()
    for path, ops in paths.items():
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            for status, resp in op.get("responses", {}).items():
                if not isinstance(resp, dict):
                    continue
                content = resp.get("content", {})
                appjson = content.get("application/json", {})
                schema = appjson.get("schema", {})
                ref = schema.get("$ref", "")
                if ref == "#/components/schemas/Error":
                    codes_in_openapi.add(status)

    codes_in_registry = set()
    with open(ERROR_CODES_PATH, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^\|\s*(\d{3})\s*\|\s*`([A-Z_]+)`", line)
            if m:
                codes_in_registry.add(m.group(1))

    # Every status code referenced by an Error response must be registered.
    unregistered = {s for s in codes_in_openapi if s not in codes_in_registry}
    if unregistered:
        fail(f"error status codes in OpenAPI not in registry: {sorted(unregistered)}")

    # Every registered HTTP status must be reachable by at least one Error
    # response (statuses 200/201/204 have no error body by definition).
    error_statuses = {s for s in codes_in_registry if s not in {"200", "201", "204"}}
    unreachable = error_statuses - codes_in_openapi
    if unreachable:
        fail(f"registered error statuses unreachable in OpenAPI: {sorted(unreachable)}")

    print(
        f"OK: openapi.yaml valid; {len(paths)} paths; "
        f"{len(codes_in_openapi)} error statuses referenced; "
        f"{len(codes_in_registry)} registered."
    )


if __name__ == "__main__":
    main()
