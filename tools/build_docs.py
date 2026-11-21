"""Generate the rule catalog in README.md and the MITRE ATT&CK Navigator coverage layer.

The README section between <!-- catalog:start --> and <!-- catalog:end --> is rebuilt from
the rule files, so the tables can't drift from what's in the repo. The layer file can be
opened in https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload).

Usage:
    python tools/build_docs.py           # rewrite the catalog and coverage/attack-layer.json
    python tools/build_docs.py --check   # fail if either is out of date (CI)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
LAYER = REPO / "coverage" / "attack-layer.json"
START, END = "<!-- catalog:start -->", "<!-- catalog:end -->"

# A rule's area is decided by the first table in its requiredDataConnectors.
AREAS = [
    ("Entra ID", ["SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs", "AuditLogs",
                  "MicrosoftGraphActivityLogs"]),
    ("Exchange, SharePoint and email", ["OfficeActivity", "EmailEvents", "EmailAttachmentInfo", "UrlClickEvents"]),
    ("Azure", ["AzureActivity", "AzureDiagnostics"]),
    ("AWS", ["AWSCloudTrail"]),
    ("Endpoint (Defender for Endpoint)", ["DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents",
                                          "DeviceNetworkEvents", "DeviceLogonEvents"]),
    ("Active Directory", ["SecurityEvent"]),
]
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
TACTIC_LABEL = {"InitialAccess": "Initial Access", "PrivilegeEscalation": "Privilege Escalation",
                "DefenseEvasion": "Defense Evasion", "CredentialAccess": "Credential Access",
                "LateralMovement": "Lateral Movement", "CommandAndControl": "Command and Control",
                "ResourceDevelopment": "Resource Development"}


def load(folder: str) -> list[tuple[str, dict]]:
    return [(f"{folder}/{p.name}", yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted((REPO / folder).glob("*.yaml"))]


def tables(doc: dict) -> list[str]:
    return [dt for c in doc["requiredDataConnectors"] for dt in c.get("dataTypes", [])]


def area(doc: dict) -> str:
    first = tables(doc)[0]
    return next((name for name, area_tables in AREAS if first in area_tables), "Other")


def technique_links(ids: list[str]) -> str:
    return ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in ids)


def catalog(detections, hunts) -> str:
    lines = [START, ""]
    tactic_count = len({t for _, d in detections + hunts for t in d["tactics"]})
    technique_count = len({t for _, d in detections + hunts for t in d["relevantTechniques"]})
    lines.append(f"**{len(detections)} detection rules and {len(hunts)} hunting queries**, covering {technique_count} ATT&CK "
                 f"techniques across {tactic_count} tactics. The [coverage layer](coverage/attack-layer.json) opens in the "
                 "[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).")
    lines.append("")
    lines.append("### Detection rules")
    lines.append("")
    by_area = defaultdict(list)
    for path, d in detections:
        by_area[area(d)].append((path, d))
    for name, _ in AREAS + [("Other", [])]:
        if name not in by_area:
            continue
        rows = sorted(by_area[name], key=lambda x: (SEVERITY_ORDER[x[1]["severity"]], x[1]["name"]))
        lines += [f"#### {name} ({len(rows)})", "", "| Rule | Severity | ATT&CK | Data |", "|---|---|---|---|"]
        for path, d in rows:
            lines.append(f"| [{d['name']}]({path}) | {d['severity']} | {technique_links(d['relevantTechniques'])} | {', '.join(tables(d))} |")
        lines.append("")
    lines += ["### Hunting queries", "",
              "Hunts are for questions an analyst asks on purpose, where the results need judgment rather than an automatic "
              "alert. Each one has a short \"how to hunt\" guide in its description.", "",
              "| Hunt | ATT&CK | Data |", "|---|---|---|"]
    for path, d in sorted(hunts, key=lambda x: x[1]["name"]):
        lines.append(f"| [{d['name']}]({path}) | {technique_links(d['relevantTechniques'])} | {', '.join(tables(d))} |")
    lines += ["", END]
    return "\n".join(lines)


def layer(detections, hunts) -> str:
    entries = defaultdict(list)
    for _, d in detections:
        for t in d["relevantTechniques"]:
            entries[t].append(f"Rule: {d['name']}")
    for _, d in hunts:
        for t in d["relevantTechniques"]:
            entries[t].append(f"Hunt: {d['name']}")
    techniques = [
        {"techniqueID": t, "score": len(names), "comment": "; ".join(sorted(names)), "enabled": True}
        for t, names in sorted(entries.items())
    ]
    doc = {
        "name": "sentinel-detections coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by the detection rules and hunting queries in github.com/jasaan/sentinel-detections. "
                       "Score = number of rules and hunts that map to the technique.",
        "techniques": techniques,
        "gradient": {"colors": ["#d0e6ff", "#1f6feb"], "minValue": 1, "maxValue": max([e["score"] for e in techniques] + [1])},
        "showTacticRowBackground": True,
        "selectSubtechniquesWithParent": False,
    }
    return json.dumps(doc, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    detections, hunts = load("detections"), load("hunting")

    readme = README.read_text(encoding="utf-8")
    if START not in readme or END not in readme:
        sys.exit(f"README.md needs {START} and {END} markers")
    new_readme = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _: catalog(detections, hunts), readme, flags=re.S)
    new_layer = layer(detections, hunts)

    if args.check:
        stale = []
        if new_readme != readme:
            stale.append("README.md catalog")
        if not LAYER.exists() or LAYER.read_text(encoding="utf-8") != new_layer:
            stale.append(str(LAYER.relative_to(REPO)))
        if stale:
            print("Out of date (run python tools/build_docs.py):", ", ".join(stale))
            sys.exit(1)
        print("README catalog and coverage layer are up to date")
        return
    README.write_text(new_readme, encoding="utf-8")
    LAYER.parent.mkdir(exist_ok=True)
    LAYER.write_text(new_layer, encoding="utf-8")
    print(f"Updated README.md catalog ({len(detections)} rules, {len(hunts)} hunts) and {LAYER.relative_to(REPO)}")


if __name__ == "__main__":
    main()
