#!/usr/bin/env python3
"""Compare JSON Schema and canonical Go evidence validation verdicts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators


def is_number(checker: Any, instance: Any) -> bool:
    return isinstance(instance, (Decimal, float, int)) and not isinstance(instance, bool)


def is_integer(checker: Any, instance: Any) -> bool:
    if isinstance(instance, bool):
        return False
    if isinstance(instance, int):
        return True
    return isinstance(instance, Decimal) and instance.is_finite() and instance == instance.to_integral_value()


parity_type_checker = Draft202012Validator.TYPE_CHECKER.redefine_many(
    {"number": is_number, "integer": is_integer}
)
# Decimal keeps JSON numbers exact, so the schema side does not turn large
# integral exponents into infinity before applying Draft 2020-12 integer rules.
ParityValidator = validators.extend(
    Draft202012Validator, type_checker=parity_type_checker
)


class DuplicateMemberError(ValueError):
    pass


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMemberError(key)
        result[key] = value
    return result


format_checker = FormatChecker()


@format_checker.checks("date-time", raises=ValueError)
def valid_rfc3339_datetime(instance: Any) -> bool:
    if not isinstance(instance, str):
        return True
    normalized = list(instance)
    if len(normalized) <= 10:
        raise ValueError("date-time is too short")
    normalized[10] = "T"
    if normalized[-1] in ("z", "Z"):
        normalized[-1] = "Z"
    value = "".join(normalized)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    datetime.fromisoformat(value)
    return True


def schema_verdict(validator: Draft202012Validator, raw: bytes) -> tuple[bool, str]:
    try:
        instance = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_members,
            parse_float=Decimal,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMemberError) as exc:
        return False, f"JSON parse: {exc}"

    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        return False, "; ".join(error.message for error in errors)

    if isinstance(instance, dict):
        started = instance.get("started_at")
        finished = instance.get("finished_at")
        if isinstance(started, str) and isinstance(finished, str):
            # Draft 2020-12 has no portable cross-property comparison keyword;
            # retain the canonical timestamp-order invariant in this sidecar.
            def parse_timestamp(value: str) -> datetime:
                normalized = list(value)
                normalized[10] = "T"
                if normalized[-1] in ("z", "Z"):
                    normalized[-1] = "Z"
                return datetime.fromisoformat("".join(normalized).replace("Z", "+00:00"))

            if parse_timestamp(finished) < parse_timestamp(started):
                return False, "finished_at must not be earlier than started_at"
    return True, ""


def go_verdict(root: Path, fixture: Path) -> tuple[bool, str]:
    completed = subprocess.run(
        [
            os.environ.get("GO", "go"),
            "run",
            "./scripts/verify-evidence.go",
            str(fixture.relative_to(root)),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip().replace("\n", " ")
    return completed.returncode == 0, output


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    schema_path = root / "test" / "evidence" / "schema.json"
    cases_path = root / "test" / "evidence" / "parity" / "cases.json"

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cases = json.loads(cases_path.read_text(encoding="utf-8"))["cases"]
        validator = ParityValidator(schema, format_checker=format_checker)
        validator.check_schema(schema)
    except (OSError, KeyError, json.JSONDecodeError, ValidationError) as exc:
        print(f"parity setup failed: {exc}", file=sys.stderr)
        return 2

    mismatches = 0
    for case in cases:
        fixture = (cases_path.parent / case["path"]).resolve()
        raw = fixture.read_bytes()
        schema_valid, schema_detail = schema_verdict(validator, raw)
        go_valid, go_detail = go_verdict(root, fixture)
        expected = case["valid"]
        status = "PASS" if schema_valid == go_valid == expected else "FAIL"
        if status == "FAIL":
            mismatches += 1
        print(
            f"{status} {case['name']}: expected={expected} "
            f"schema={schema_valid} go={go_valid}"
        )
        if status == "FAIL":
            if schema_detail:
                print(f"  schema: {schema_detail}")
            if go_detail:
                print(f"  go: {go_detail}")

    if mismatches:
        print(f"{mismatches} parity mismatch(es)", file=sys.stderr)
        return 1
    print(f"parity passed: {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
