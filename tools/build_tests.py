"""Turn each test case into a self-checking KQL query you can paste into Azure Data Explorer.

For every tests/cases/<name>.yaml this writes tests/kql/<name>.kql, which:
  1. builds the sample logs inline with `datatable` (timestamps are offsets from now(),
     so the tests never go stale),
  2. runs the rule's query text exactly as written in the rule file, and
  3. returns one row: Test, Result (PASS/FAIL), Rows, Expected.

It also writes tests/kql/ALL_TESTS.kql: every test as its own function (so their sample
tables don't collide), unioned into one query that returns one PASS/FAIL row per test.

Usage:
    python tools/build_tests.py           # write the .kql files
    python tools/build_tests.py --check   # fail if the committed .kql files are out of date (CI)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schemas import SCHEMAS  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CASES = REPO / "tests" / "cases"
OUT = REPO / "tests" / "kql"
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def seconds(value: str) -> int:
    m = _DURATION.match(str(value).strip())
    if not m:
        raise ValueError(f"Bad duration {value!r}; use forms like 30s, 15m, 2h, 14d")
    return int(m.group(1)) * _UNIT[m.group(2)]


def kql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def kql_value(value, kind: str) -> str:
    if kind == "dynamic":
        return "dynamic(null)" if value is None else f"dynamic({json.dumps(value)})"
    if kind == "string":
        return kql_string("" if value is None else str(value))
    if kind in ("int", "long"):
        return f"{kind}(null)" if value is None else str(int(value))
    if kind == "bool":
        return "bool(null)" if value is None else str(bool(value)).lower()
    raise ValueError(f"Unsupported column type in test data: {kind}")


def substitute(value, i: int):
    """Replace '{i}' with the copy number in strings, including inside nested lists and maps."""
    if isinstance(value, str):
        return value.replace("{i}", str(i))
    if isinstance(value, list):
        return [substitute(v, i) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, i) for k, v in value.items()}
    return value


def expand_rows(rows: list[dict]) -> list[dict]:
    """Apply _repeat (n copies, '{i}' in strings replaced by 1..n) and _step (each copy later by step)."""
    out = []
    for row in rows:
        repeat = int(row.get("_repeat", 1))
        step = seconds(row["_step"]) if "_step" in row else 0
        base = seconds(row["ago"])
        for i in range(1, repeat + 1):
            new = {}
            for key, value in row.items():
                if key in ("_repeat", "_step", "ago"):
                    continue
                new[key] = substitute(value, i) if repeat > 1 else value
            new["_ago_seconds"] = max(base - (i - 1) * step, 0)
            out.append(new)
    return out


def datatable(table: str, rows: list[dict]) -> str:
    schema = SCHEMAS[table]
    columns = [c for c in schema if c != "TimeGenerated"]
    for row in rows:
        unknown = set(row) - set(columns) - {"_ago_seconds"}
        if unknown:
            raise ValueError(f"{table}: unknown column(s) {sorted(unknown)}; add them to tools/schemas.py")
    header = ", ".join(["AgoSeconds:long"] + [f"{c}:{schema[c]}" for c in columns])
    lines = []
    for row in rows:
        values = [str(row["_ago_seconds"])] + [kql_value(row.get(c), schema[c]) for c in columns]
        lines.append("    " + ", ".join(values) + ",")
    body = "\n".join(lines).rstrip(",")
    return (
        f"let {table} = datatable({header}) [\n{body}\n]\n"
        f"| extend TimeGenerated = now() - AgoSeconds * 1s\n"
        f"| project-away AgoSeconds;"
    )


def condition(spec: dict) -> str:
    parts = []
    for col, value in spec.items():
        if isinstance(value, bool):
            parts.append(f"tobool({col}) == {str(value).lower()}")
        elif isinstance(value, int):
            parts.append(f"tolong({col}) == {value}")
        else:
            parts.append(f"tostring({col}) == {kql_string(str(value))}")
    return " and ".join(parts)


def build(case_path: Path) -> str:
    case = yaml.safe_load(case_path.read_text(encoding="utf-8"))
    rule = yaml.safe_load((REPO / case["rule"]).read_text(encoding="utf-8"))
    name = case_path.stem
    expect = case["expect"]

    tables = [datatable(t, expand_rows(rows)) for t, rows in case["data"].items()]
    query = rule["query"].strip()
    if re.search(r"\n\s*\n", query):
        raise ValueError(f"{case['rule']}: the query has a blank line, which splits it into two queries in the web UI")

    counters, checks = ["Rows = count()"], [f"Rows == {int(expect['rows'])}"]
    for n, spec in enumerate(expect.get("include", []), 1):
        counters.append(f"Include{n} = countif({condition(spec)})")
        checks.append(f"Include{n} >= 1")
    for n, spec in enumerate(expect.get("exclude", []), 1):
        counters.append(f"Exclude{n} = countif({condition(spec)})")
        checks.append(f"Exclude{n} == 0")
    expected = f"{expect['rows']} row(s); {len(expect.get('include', []))} must appear; {len(expect.get('exclude', []))} must not"

    header = [
        f"// Test: {name}",
        f"// Rule: {rule['name']} ({case['rule']})",
        f"// {case['description'].strip()}",
        "// Generated by tools/build_tests.py from tests/cases/" + case_path.name + ". Do not edit by hand.",
    ]
    body = [
        *tables,
        "let RuleResults = () {",
        query,
        "};",
        "RuleResults()",
        "| summarize " + ", ".join(counters),
        f"| extend Test = {kql_string(name)}, Expected = {kql_string(expected)}",
        f"| extend Result = iff({' and '.join(checks)}, \"PASS\", \"FAIL\")",
        "| project Test, Result, Rows, Expected",
    ]
    return header, body


def standalone(header: list[str], body: list[str]) -> str:
    return "\n".join(header + body) + "\n"


def as_function(name: str, header: list[str], body: list[str]) -> tuple[str, str]:
    """Wrap one test in a function so its sample tables don't collide with other tests'."""
    fn = "Test_" + re.sub(r"\W", "_", name)
    return fn, "\n".join(header + [f"let {fn} = () {{"] + body + ["};"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Exit 1 if generated files are out of date")
    args = parser.parse_args()

    built = {p.stem: build(p) for p in sorted(CASES.glob("*.yaml"))}
    outputs = {f"{name}.kql": standalone(h, b) for name, (h, b) in built.items()}
    functions = [as_function(name, h, b) for name, (h, b) in built.items()]
    outputs["ALL_TESTS.kql"] = "\n".join(
        ["// All tests in one query: paste into Azure Data Explorer and run. One PASS/FAIL row per test.",
         "// Generated by tools/build_tests.py. Do not edit by hand."]
        + [text for _, text in functions]
        + ["union " + ", ".join(f"{fn}()" for fn, _ in functions), "| order by Test asc"]
    ) + "\n"

    if args.check:
        stale = [n for n, text in outputs.items() if not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != text]
        if stale:
            print("Out of date (run python tools/build_tests.py):", ", ".join(stale))
            sys.exit(1)
        print(f"{len(outputs) - 1} generated tests are up to date")
        return

    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"Wrote {len(outputs) - 1} tests and ALL_TESTS.kql to {OUT.relative_to(REPO)}/")


if __name__ == "__main__":
    main()
