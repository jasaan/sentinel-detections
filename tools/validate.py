"""Static checks for every detection and hunting query. Runs in CI on every push.

Checks: required fields, unique GUIDs and names, severity and tactic values Sentinel
accepts, MITRE ATT&CK technique ID format, that every table a query uses is declared in
requiredDataConnectors and known to tools/schemas.py, that each description has its
Tuning/Triage (rules) or How to hunt (hunts) guidance, that every rule has a test case,
and that the generated tests, deployment templates and README catalog are up to date.
"""

from __future__ import annotations

import re
import subprocess
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schemas import SCHEMAS  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

DETECTION_FIELDS = ["id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
                    "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
                    "query", "entityMappings", "version", "kind"]
HUNTING_FIELDS = ["id", "name", "description", "requiredDataConnectors", "tactics", "relevantTechniques", "query"]
SEVERITIES = {"Informational", "Low", "Medium", "High"}
TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
           "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
           "Collection", "Exfiltration", "CommandAndControl", "Impact"}
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
DURATION = re.compile(r"^\d+[mhd]$")


def tables_used(query: str) -> set[str]:
    return {t for t in SCHEMAS if re.search(rf"\b{t}\b", query)}


def check_file(path: Path, kind: str, seen_ids: set[str], seen_names: set[str]) -> list[str]:
    errors = []
    rel = path.relative_to(REPO)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as err:
        return [f"{rel}: invalid YAML: {err}"]

    for field in DETECTION_FIELDS if kind == "detection" else HUNTING_FIELDS:
        if field not in doc:
            errors.append(f"{rel}: missing field '{field}'")
    if errors:
        return errors

    try:
        rid = str(uuid.UUID(str(doc["id"])))
    except ValueError:
        errors.append(f"{rel}: id is not a GUID")
        rid = str(doc["id"])
    if rid in seen_ids:
        errors.append(f"{rel}: duplicate id {rid}")
    seen_ids.add(rid)

    if kind == "detection":
        if doc["severity"] not in SEVERITIES:
            errors.append(f"{rel}: severity must be one of {sorted(SEVERITIES)}")
        for field in ("queryFrequency", "queryPeriod"):
            if not DURATION.match(str(doc[field])):
                errors.append(f"{rel}: {field} must look like 15m, 1h or 14d")
        if doc["kind"] != "Scheduled":
            errors.append(f"{rel}: kind must be Scheduled")
        if not doc["entityMappings"]:
            errors.append(f"{rel}: add at least one entity mapping")

    for tactic in doc["tactics"]:
        if tactic not in TACTICS:
            errors.append(f"{rel}: unknown tactic '{tactic}'")
    for tech in doc["relevantTechniques"]:
        if not TECHNIQUE.match(str(tech)):
            errors.append(f"{rel}: technique '{tech}' is not a valid ATT&CK ID (T1234 or T1234.001)")

    declared = {dt for c in doc["requiredDataConnectors"] for dt in c.get("dataTypes", [])}
    used = tables_used(doc["query"])
    if not used:
        errors.append(f"{rel}: query uses no table known to tools/schemas.py")
    for table in used - declared:
        errors.append(f"{rel}: query uses {table} but requiredDataConnectors doesn't declare it")
    if re.search(r"\n\s*\n", doc["query"].strip()):
        errors.append(f"{rel}: query contains a blank line")

    required_sections = ("Tuning:", "Triage:") if kind == "detection" else ("How to hunt:",)
    for section in required_sections:
        if section not in doc["description"]:
            errors.append(f"{rel}: description needs a '{section}' paragraph")
    if doc["name"] in seen_names:
        errors.append(f"{rel}: duplicate name '{doc['name']}'")
    seen_names.add(doc["name"])

    case = REPO / "tests" / "cases" / f"{path.stem}.yaml"
    if not case.exists():
        errors.append(f"{rel}: no test case at {case.relative_to(REPO)}")
    return errors


def main() -> None:
    errors: list[str] = []
    seen: set[str] = set()
    names: set[str] = set()
    files = [(p, "detection") for p in sorted((REPO / "detections").glob("*.yaml"))]
    files += [(p, "hunting") for p in sorted((REPO / "hunting").glob("*.yaml"))]
    for path, kind in files:
        errors += check_file(path, kind, seen, names)

    summaries = []
    for script in ("build_tests.py", "build_deploy.py", "build_docs.py"):
        run = subprocess.run([sys.executable, str(REPO / "tools" / script), "--check"], capture_output=True, text=True)
        if run.returncode != 0:
            errors.append((run.stdout + run.stderr).strip())
        else:
            summaries.append(run.stdout.strip())

    if errors:
        print("\n".join(f"FAIL  {e}" for e in errors))
        sys.exit(1)
    print(f"OK: {len(files)} queries validated; " + "; ".join(summaries))


if __name__ == "__main__":
    main()
