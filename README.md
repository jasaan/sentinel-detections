# sentinel-detections

**Microsoft Sentinel detection rules and threat-hunting queries for Entra ID, Microsoft 365, Azure and Defender for Endpoint, mapped to MITRE ATT&CK, with sample logs and tests that prove each rule fires on the attack and stays quiet on the look-alikes.**

> All users, domains, IPs and events in the sample data are fictional (contoso.com and documentation IP ranges).

## Why this exists

Detection rules are code, and most of them ship untested. A rule that never fires is invisible; a rule that fires on everything gets disabled. Each rule here comes with a test case: realistic sample events that should trigger it, plus near misses that shouldn't (an internal forward instead of an external one, a PIM activation instead of a direct role assignment, listing shadow copies instead of deleting them). The tests run against Microsoft's own Kusto engine, using the exact query text from the rule file.

The rules focus on what I've seen matter in Microsoft-centric companies: identity takeover, business email compromise, privileged-access abuse, consent phishing, data theft and ransomware's last steps.

## Detection rules

| Rule | Severity | ATT&CK | Tactics | Data |
|---|---|---|---|---|
| [Break-glass account sign-in attempt](detections/breakglass-signin.yaml) | High | T1078.004 | Initial Access, Privilege Escalation | SigninLogs |
| [Conditional Access policy deleted or disabled](detections/conditional-access-policy-disabled.yaml) | High | T1556.009 | Defense Evasion | AuditLogs |
| [Consent granted to an app with high-risk permissions](detections/oauth-high-risk-consent.yaml) | High | T1528 | Credential Access, Persistence | AuditLogs |
| [Inbox rule forwards mail to an external address](detections/inbox-rule-external-forward.yaml) | High | T1114.003 | Collection, Exfiltration | OfficeActivity |
| [New MFA method followed by sign-in from a new country](detections/mfa-method-added-new-country.yaml) | High | T1098.005, T1078.004 | Persistence, Initial Access | AuditLogs, SigninLogs |
| [Privileged Entra role assigned outside PIM](detections/global-admin-outside-pim.yaml) | High | T1098.003 | Persistence, Privilege Escalation | AuditLogs |
| [Shadow copy or backup catalog deletion](detections/shadow-copy-deletion.yaml) | High | T1490 | Impact | DeviceProcessEvents |
| [Mass file download from SharePoint or OneDrive](detections/mass-file-download.yaml) | Medium | T1530 | Collection, Exfiltration | OfficeActivity |
| [Mass secret retrieval from Azure Key Vault](detections/keyvault-mass-secret-read.yaml) | Medium | T1555.006 | Credential Access | AzureDiagnostics |
| [Password spray against Entra ID from a single IP](detections/entra-password-spray.yaml) | Medium | T1110.003 | Credential Access | SigninLogs |

## Hunting queries

Hunts are for questions an analyst asks on purpose, where the results need judgment rather than an automatic alert. Each one includes a short "how to hunt" guide in its description.

| Hunt | ATT&CK | Data |
|---|---|---|
| [MFA fatigue (repeated push denials)](hunting/hunt-mfa-fatigue.yaml) | T1621 | SigninLogs |
| [Dormant account signs in again](hunting/hunt-dormant-account-reactivated.yaml) | T1078.004 | SigninLogs |
| [New credentials added to an app or service principal](hunting/hunt-service-principal-new-credential.yaml) | T1098.001 | AuditLogs |
| [Apps granted access to mailboxes](hunting/hunt-oauth-mail-permissions.yaml) | T1528, T1114.002 | AuditLogs |
| [Successful sign-ins with rarely seen user agents](hunting/hunt-rare-user-agent.yaml) | T1078.004 | SigninLogs |

## How the tests work

```
tests/cases/<rule>.yaml  ──►  tools/build_tests.py  ──►  tests/kql/<rule>.kql      (one self-checking query per rule)
  sample events that              datatable() of the          tests/kql/ALL_TESTS.kql  (all tests, one query)
  should and shouldn't fire       sample logs + the rule's
  + expected results              exact query + PASS/FAIL
```

- **Test cases** (`tests/cases/`) list sample events for each table the rule reads, with timestamps written as offsets ("10m ago", "45d ago") so the tests never go stale, and the expected results: how many rows, which must appear, which must not.
- **The generator** (`tools/build_tests.py`) builds each test as a KQL query: the sample events as inline `datatable`s named exactly like the Sentinel tables, then the rule's query text unchanged, then a check that returns `PASS` or `FAIL`. Nothing is uploaded or stored anywhere.
- **Running them:** paste `tests/kql/ALL_TESTS.kql` into [Azure Data Explorer](https://dataexplorer.azure.com) (a [free cluster](https://dataexplorer.azure.com/freecluster) works) and run it. You get one PASS/FAIL row per test.
- **Automated checks** (`tools/validate.py`, run by GitHub Actions on every push): required fields, unique GUIDs, valid severities and tactics, ATT&CK ID format, every table a query reads is declared in its data connectors, every rule has a test, and the generated tests match the rules.

### Results

All **15 of 15** tests (10 detections, 5 hunts) pass in Azure Data Explorer, run on 2026-11-20.

## Deploying to Sentinel

The YAML follows the field layout used by Microsoft's [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository (`id`, `severity`, `queryFrequency`, `queryPeriod`, `tactics`, `relevantTechniques`, `entityMappings`, …).

1. In Sentinel, go to **Analytics → Create → Scheduled query rule**.
2. Paste the `query`, and set frequency, lookback, threshold, tactics and entity mappings from the YAML.
3. Do the tuning step in each rule's description first: your domains, break-glass accounts, thresholds and allow-lists.

For hunting queries, use **Hunting → New query**. To manage rules as code at scale, these files can be converted to ARM templates and deployed with Sentinel Repositories or a CI pipeline.

## Design choices

- **Every rule has negative tests.** Near misses catch the over-broad version of a rule, which is the version that gets switched off in production.
- **Tested text is deployed text.** The tests run the query exactly as it appears in the rule file; there's no separate "test version".
- **Tuning is part of the rule.** Each description says what to change for your environment and what normal volume looks like.
- **Alerts vs hunts.** Signals that need human judgment (legitimate credential rotations, travelers, rare-but-fine user agents) are hunts, not alerts, to protect analysts' attention.

## Limitations

- Sample data covers the columns each rule uses, not every column of each table.
- Thresholds are starting points; tune them on your own baseline before enabling alerts.
- `tools/kusto.py` (optional, to run tests from a script) uses device-code sign-in. Personal Microsoft accounts were rejected in my testing, so the published results come from running `ALL_TESTS.kql` in the Data Explorer web UI. It is expected to work with a work or school (Entra ID) account, but that path is untested.
- The MFA-fatigue hunt groups denials into clock-hour buckets; a burst that straddles an hour boundary can be split. Its test packs the burst into 30 seconds, so a split is very unlikely.

## License

MIT
