"""Connect to an Azure Data Explorer (Kusto) cluster for running the tests.

The cluster URI comes from the KUSTO_CLUSTER environment variable or from
~/.config/sentinel-detections/config.json ({"cluster": "...", "database": "..."}),
so it never lives in the repo. Sign-in uses the device-code flow once; the token is
cached in the OS keychain (via MSAL), so later runs don't prompt.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from azure.identity import AuthenticationRecord, DeviceCodeCredential, TokenCachePersistenceOptions
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder

CONFIG_DIR = Path.home() / ".config" / "sentinel-detections"
CONFIG_FILE = CONFIG_DIR / "config.json"
RECORD_FILE = CONFIG_DIR / "auth-record.json"
# Public client app used by Microsoft's Kusto tools; unlike the Azure CLI app it accepts
# personal Microsoft accounts, which is what the free Azure Data Explorer cluster uses.
KUSTO_CLIENT_ID = "db662dc1-0cfe-4e1c-a843-19a68e65be58"


def load_config() -> tuple[str, str, str]:
    cfg = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    cluster = os.environ.get("KUSTO_CLUSTER") or cfg.get("cluster")
    database = os.environ.get("KUSTO_DATABASE") or cfg.get("database", "detections")
    tenant = os.environ.get("KUSTO_TENANT") or cfg.get("tenant", "common")
    if not cluster:
        raise SystemExit(
            "No cluster configured. Set KUSTO_CLUSTER, or create "
            f"{CONFIG_FILE} with {{\"cluster\": \"https://<name>.<region>.kusto.windows.net\"}}"
        )
    return cluster.rstrip("/"), database, tenant


def _credential(cluster: str, tenant: str) -> DeviceCodeCredential:
    cache = TokenCachePersistenceOptions(name="sentinel-detections")
    record = AuthenticationRecord.deserialize(RECORD_FILE.read_text()) if RECORD_FILE.exists() else None
    cred = DeviceCodeCredential(
        client_id=KUSTO_CLIENT_ID, tenant_id=tenant,
        cache_persistence_options=cache, authentication_record=record,
    )
    if record is None:
        record = cred.authenticate(scopes=[f"{cluster}/.default"])  # prints a code to enter in the browser
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        RECORD_FILE.write_text(record.serialize())  # account metadata only, no tokens
    return cred


def connect() -> tuple[KustoClient, str]:
    cluster, database, tenant = load_config()
    kcsb = KustoConnectionStringBuilder.with_azure_token_credential(cluster, _credential(cluster, tenant))
    return KustoClient(kcsb), database


def run(client: KustoClient, database: str, query: str) -> list[dict]:
    response = client.execute(database, query)
    table = response.primary_results[0]
    columns = [c.column_name for c in table.columns]
    return [dict(zip(columns, row)) for row in table]


if __name__ == "__main__":
    client, db = connect()
    print(run(client, db, "print Connected = true, Now = now()"))
