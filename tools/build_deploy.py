"""Build ARM templates that deploy every rule and hunting query to a Sentinel workspace.

Writes:
  deploy/analytics-rules.json   all detections as Scheduled analytics rules (disabled by default)
  deploy/hunting-queries.json   all hunting queries as saved searches in the "Hunting Queries" category

Rules deploy disabled unless you set enableRules=true, so you can tune thresholds and
allow-lists before anything alerts.

Usage:
    python tools/build_deploy.py           # write the templates
    python tools/build_deploy.py --check   # fail if the committed templates are out of date (CI)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "deploy"
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
TRIGGER = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}


def iso_duration(value: str) -> str:
    m = re.fullmatch(r"(\d+)([mhd])", str(value))
    if not m:
        raise ValueError(f"Bad duration {value!r}")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def load(folder: str) -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((REPO / folder).glob("*.yaml"))]


def alert_rule(rule: dict) -> dict:
    techniques = sorted({t.split(".")[0] for t in rule["relevantTechniques"]})
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2022-11-01",
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '{rule['id']}')]",
        "kind": "Scheduled",
        "properties": {
            "displayName": rule["name"],
            "description": rule["description"].strip(),
            "severity": rule["severity"],
            "enabled": "[parameters('enableRules')]",
            "query": rule["query"].strip(),
            "queryFrequency": iso_duration(rule["queryFrequency"]),
            "queryPeriod": iso_duration(rule["queryPeriod"]),
            "triggerOperator": TRIGGER[rule["triggerOperator"]],
            "triggerThreshold": int(rule["triggerThreshold"]),
            "suppressionEnabled": False,
            "suppressionDuration": "PT1H",
            "tactics": rule["tactics"],
            "techniques": techniques,
            "entityMappings": rule["entityMappings"],
            "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": False,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "AllEntities",
                },
            },
        },
    }


def saved_search(hunt: dict) -> dict:
    return {
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": "2020-08-01",
        "name": f"[concat(parameters('workspace'), '/', '{hunt['id']}')]",
        "properties": {
            "category": "Hunting Queries",
            "displayName": hunt["name"],
            "query": hunt["query"].strip(),
            "version": 2,
            "tags": [
                {"name": "description", "value": hunt["description"].strip()},
                {"name": "tactics", "value": ",".join(hunt["tactics"])},
                {"name": "techniques", "value": ",".join(hunt["relevantTechniques"])},
            ],
        },
    }


def template(resources: list[dict], extra_params: dict) -> dict:
    params = {
        "workspace": {
            "type": "string",
            "metadata": {"description": "Name of the Log Analytics workspace that has Microsoft Sentinel enabled."},
        },
        **extra_params,
    }
    return {"$schema": SCHEMA, "contentVersion": "1.0.0.0", "parameters": params, "resources": resources}


def build() -> dict[str, str]:
    rules = template(
        [alert_rule(r) for r in load("detections")],
        {
            "enableRules": {
                "type": "bool",
                "defaultValue": False,
                "metadata": {"description": "Deploy rules enabled. Leave false to tune thresholds and allow-lists first."},
            }
        },
    )
    hunts = template([saved_search(h) for h in load("hunting")], {})
    return {
        "analytics-rules.json": json.dumps(rules, indent=2, ensure_ascii=False) + "\n",
        "hunting-queries.json": json.dumps(hunts, indent=2, ensure_ascii=False) + "\n",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Exit 1 if the committed templates are out of date")
    args = parser.parse_args()
    outputs = build()
    if args.check:
        stale = [n for n, text in outputs.items() if not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != text]
        if stale:
            print("Out of date (run python tools/build_deploy.py):", ", ".join(stale))
            sys.exit(1)
        print("deployment templates are up to date")
        return
    OUT.mkdir(exist_ok=True)
    for name, text in outputs.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"Wrote {', '.join(outputs)} to deploy/")


if __name__ == "__main__":
    main()
