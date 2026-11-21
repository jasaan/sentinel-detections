# sentinel-detections

**Microsoft Sentinel detection rules and threat-hunting queries for Entra ID, Microsoft 365, Azure, AWS, Defender for Endpoint and Active Directory, mapped to MITRE ATT&CK. Every rule ships with sample logs and a test that proves it fires on the attack and stays quiet on the look-alikes. Deployable in one click.**

> All users, domains, IPs and events in the sample data are fictional (contoso.com, documentation IP ranges, made-up account IDs).

## Why this exists

Detection rules are code, and most of them ship untested. A rule that never fires is invisible; a rule that fires on everything gets disabled. Each rule here comes with a test case: realistic sample events that should trigger it, plus near misses that shouldn't (an internal forward instead of an external one, a PIM activation instead of a direct role assignment, Office saving `.tmp` files as `.docx` instead of ransomware renaming them). The tests run on Microsoft's own Kusto engine against the exact query text in the rule file.

The rules follow how real intrusions in Microsoft-centric and hybrid companies unfold, drawing on Microsoft Threat Intelligence, CISA advisories, The DFIR Report and MITRE ATT&CK:

- **Identity takeover:** AiTM session theft, device code phishing, password spray (single-IP and distributed), help-desk social engineering, legacy auth, risky sign-ins
- **Tenant persistence:** federation backdoors, cross-tenant trust, privileged app permissions, app owners, named locations, the Entra Connect sync account
- **Business email compromise:** inbox rules that hide or forward mail, mailbox forwarding, transport rules, mailbox permissions, audit tampering, phishing clicks
- **Cloud control plane:** Azure RBAC escalation, elevate-access, Run Command, logging and backup destruction; AWS root use, CloudTrail/GuardDuty tampering, IAM escalation, public S3, snapshot sharing
- **Endpoint and AD:** credential dumping (LSASS, SAM, NTDS, DCSync, Kerberoasting), Defender tampering, LOLBins, web shells, Impacket, RMM tools, rclone exfiltration, ransomware encryption

Each rule's description says what it catches, which threat actors have used the technique, how to tune it, and what to do when it fires.

## Deploy

[![Deploy analytics rules to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjasaan%2Fsentinel-detections%2Fmain%2Fdeploy%2Fanalytics-rules.json) **Analytics rules** ([template](deploy/analytics-rules.json))

[![Deploy hunting queries to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjasaan%2Fsentinel-detections%2Fmain%2Fdeploy%2Fhunting-queries.json) **Hunting queries** ([template](deploy/hunting-queries.json))

Pick the resource group and enter the name of your Sentinel workspace. **Rules deploy disabled** (`enableRules = false`) so you can do the tuning step in each description first: your domains, break-glass accounts, approved tools, thresholds. Turn them on one by one in **Analytics**, or redeploy with `enableRules = true`.

From the command line:

```bash
az deployment group create -g <resource-group> \
  --template-file deploy/analytics-rules.json --parameters workspace=<workspace-name>
```

Rules only work on tables you collect. What each area needs:

| Area | Data connector | Tables |
|---|---|---|
| Entra ID | Microsoft Entra ID (diagnostic settings) | SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs, MicrosoftGraphActivityLogs |
| Microsoft 365 | Microsoft 365 (formerly Office 365) | OfficeActivity |
| Email | Microsoft Defender XDR (Defender for Office 365 P2) | EmailEvents, EmailAttachmentInfo, UrlClickEvents |
| Azure | Azure Activity, Azure Key Vault diagnostics | AzureActivity, AzureDiagnostics |
| AWS | Amazon Web Services (CloudTrail via S3) | AWSCloudTrail |
| Endpoint | Microsoft Defender XDR (Defender for Endpoint) | DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceLogonEvents |
| Active Directory | Windows Security Events via AMA (domain controllers) | SecurityEvent |

## Catalog

<!-- catalog:start -->

**79 detection rules and 16 hunting queries**, covering 84 ATT&CK techniques across 12 tactics. The [coverage layer](coverage/attack-layer.json) opens in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

### Detection rules

#### Entra ID (24)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [Admin reset of password or MFA followed by sign-in from a new IP](detections/helpdesk-reset-then-new-ip-signin.yaml) | High | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1098.005](https://attack.mitre.org/techniques/T1098/005/), [T1656](https://attack.mitre.org/techniques/T1656/) | AuditLogs, SigninLogs |
| [Application granted a high-privilege Microsoft Graph application permission](detections/app-granted-privileged-graph-role.yaml) | High | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | AuditLogs |
| [Break-glass account sign-in attempt](detections/breakglass-signin.yaml) | High | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | SigninLogs |
| [Conditional Access policy deleted or disabled](detections/conditional-access-policy-disabled.yaml) | High | [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | AuditLogs |
| [Consent granted to an app with high-risk permissions](detections/oauth-high-risk-consent.yaml) | High | [T1528](https://attack.mitre.org/techniques/T1528/) | AuditLogs |
| [Domain federation settings changed in Entra ID](detections/federation-domain-change.yaml) | High | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | AuditLogs |
| [Entra Connect sync account used outside directory sync](detections/entra-connect-sync-account-misuse.yaml) | High | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | SigninLogs, AADNonInteractiveUserSignInLogs |
| [Global Administrator elevated access to all Azure subscriptions](detections/azure-elevate-access.yaml) | High | [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | AuditLogs |
| [High-risk sign-in succeeded with a password only](detections/risky-signin-single-factor.yaml) | High | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | SigninLogs |
| [New MFA method followed by sign-in from a new country](detections/mfa-method-added-new-country.yaml) | High | [T1098.005](https://attack.mitre.org/techniques/T1098/005/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | AuditLogs, SigninLogs |
| [Privileged Entra role assigned outside PIM](detections/global-admin-outside-pim.yaml) | High | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | AuditLogs |
| [Repeated failed passwords then a successful sign-in from the same IP](detections/brute-force-then-success.yaml) | High | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | SigninLogs |
| [Same sign-in session used from two countries (possible AiTM token theft)](detections/aitm-session-token-replay.yaml) | High | [T1539](https://attack.mitre.org/techniques/T1539/), [T1550.004](https://attack.mitre.org/techniques/T1550/004/), [T1557](https://attack.mitre.org/techniques/T1557/) | SigninLogs, AADNonInteractiveUserSignInLogs |
| [Broad directory enumeration through Microsoft Graph](detections/graph-directory-enumeration.yaml) | Medium | [T1087.004](https://attack.mitre.org/techniques/T1087/004/), [T1069.003](https://attack.mitre.org/techniques/T1069/003/), [T1526](https://attack.mitre.org/techniques/T1526/) | MicrosoftGraphActivityLogs |
| [Conditional Access named location added, changed or deleted](detections/named-location-change.yaml) | Medium | [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | AuditLogs |
| [Cross-tenant access or sync settings changed](detections/cross-tenant-access-change.yaml) | Medium | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | AuditLogs |
| [Device code sign-in by a user who doesn't normally use it](detections/device-code-auth-first-use.yaml) | Medium | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1528](https://attack.mitre.org/techniques/T1528/) | SigninLogs |
| [Distributed password spray from many unfamiliar IPs](detections/distributed-password-spray.yaml) | Medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | SigninLogs |
| [Mass deletion of users, groups or apps in Entra ID](detections/mass-entra-object-deletion.yaml) | Medium | [T1531](https://attack.mitre.org/techniques/T1531/) | AuditLogs |
| [New owner added to an application or service principal](detections/app-owner-added.yaml) | Medium | [T1098](https://attack.mitre.org/techniques/T1098/) | AuditLogs |
| [Password spray against Entra ID from a single IP](detections/entra-password-spray.yaml) | Medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | SigninLogs |
| [Per-user MFA disabled for an account](detections/per-user-mfa-disabled.yaml) | Medium | [T1556.006](https://attack.mitre.org/techniques/T1556/006/) | AuditLogs |
| [Service principal signs in from a new country](detections/service-principal-signin-new-country.yaml) | Medium | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | AADServicePrincipalSignInLogs |
| [Successful sign-in over legacy authentication](detections/legacy-auth-success.yaml) | Medium | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | SigninLogs |

#### Exchange, SharePoint and email (12)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [Exchange transport rule copies, redirects or deletes mail](detections/transport-rule-redirects-mail.yaml) | High | [T1114.003](https://attack.mitre.org/techniques/T1114/003/), [T1564.008](https://attack.mitre.org/techniques/T1564/008/) | OfficeActivity |
| [Inbox rule forwards mail to an external address](detections/inbox-rule-external-forward.yaml) | High | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | OfficeActivity |
| [Inbox rule hides mail about payments or security](detections/inbox-rule-hides-mail.yaml) | High | [T1564.008](https://attack.mitre.org/techniques/T1564/008/), [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | OfficeActivity |
| [Mailbox-level forwarding set to an external address](detections/mailbox-forwarding-external.yaml) | High | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | OfficeActivity |
| [Microsoft 365 audit logging turned off or bypassed](detections/m365-audit-logging-disabled.yaml) | High | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | OfficeActivity |
| [User clicked a link in a delivered phishing email](detections/phish-delivered-and-clicked.yaml) | High | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | EmailEvents, UrlClickEvents |
| [Account suddenly emails far more recipients than usual](detections/outbound-mail-burst.yaml) | Medium | [T1534](https://attack.mitre.org/techniques/T1534/), [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | EmailEvents |
| [Burst of anonymous "anyone with the link" sharing links](detections/anonymous-link-burst.yaml) | Medium | [T1567](https://attack.mitre.org/techniques/T1567/), [T1213.002](https://attack.mitre.org/techniques/T1213/002/) | OfficeActivity |
| [Compliance search exported or used to purge mail](detections/ediscovery-export-or-purge.yaml) | Medium | [T1114.002](https://attack.mitre.org/techniques/T1114/002/), [T1070.008](https://attack.mitre.org/techniques/T1070/008/) | OfficeActivity |
| [Email with a high-risk attachment type delivered to the inbox](detections/risky-attachment-delivered.yaml) | Medium | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | EmailAttachmentInfo, EmailEvents |
| [Full Access or Send As granted on a mailbox](detections/mailbox-permission-granted.yaml) | Medium | [T1098.002](https://attack.mitre.org/techniques/T1098/002/), [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | OfficeActivity |
| [Mass file download from SharePoint or OneDrive](detections/mass-file-download.yaml) | Medium | [T1530](https://attack.mitre.org/techniques/T1530/) | OfficeActivity |

#### Azure (7)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [Azure backup protection removed or backup vault deleted](detections/azure-backup-destruction.yaml) | High | [T1490](https://attack.mitre.org/techniques/T1490/) | AzureActivity |
| [Azure diagnostic settings, Log Analytics workspace or Sentinel rules deleted](detections/azure-logging-tampering.yaml) | High | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | AzureActivity |
| [Owner or User Access Administrator assigned in Azure RBAC](detections/azure-privileged-role-assignment.yaml) | High | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | AzureActivity |
| [Mass deletion of Azure resources by one caller](detections/azure-mass-resource-deletion.yaml) | Medium | [T1485](https://attack.mitre.org/techniques/T1485/) | AzureActivity |
| [Mass secret retrieval from Azure Key Vault](detections/keyvault-mass-secret-read.yaml) | Medium | [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | AzureDiagnostics |
| [Network security group rule opens RDP, SSH or WinRM to the internet](detections/nsg-management-port-open-to-internet.yaml) | Medium | [T1562.007](https://attack.mitre.org/techniques/T1562/007/), [T1133](https://attack.mitre.org/techniques/T1133/) | AzureActivity |
| [VM Run Command used by an account that hasn't used it before](detections/azure-vm-run-command.yaml) | Medium | [T1651](https://attack.mitre.org/techniques/T1651/) | AzureActivity |

#### AWS (11)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [AWS CloudTrail, GuardDuty, Config or flow logs disabled](detections/aws-logging-or-guardduty-disabled.yaml) | High | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | AWSCloudTrail |
| [AWS administrator-level policy attached or written](detections/aws-admin-policy-granted.yaml) | High | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | AWSCloudTrail |
| [AWS root user activity](detections/aws-root-account-used.yaml) | High | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | AWSCloudTrail |
| [EBS, AMI or RDS snapshot shared with another account or made public](detections/aws-snapshot-shared-externally.yaml) | High | [T1537](https://attack.mitre.org/techniques/T1537/) | AWSCloudTrail |
| [S3 bucket made public or its public access block removed](detections/aws-s3-bucket-made-public.yaml) | High | [T1530](https://attack.mitre.org/techniques/T1530/), [T1537](https://attack.mitre.org/techniques/T1537/) | AWSCloudTrail |
| [AWS KMS key disabled or scheduled for deletion](detections/aws-kms-key-disabled-or-deleted.yaml) | Medium | [T1485](https://attack.mitre.org/techniques/T1485/), [T1486](https://attack.mitre.org/techniques/T1486/) | AWSCloudTrail |
| [AWS access key created for a different IAM user](detections/aws-access-key-created-for-other-user.yaml) | Medium | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | AWSCloudTrail |
| [AWS console sign-in by an IAM user without MFA](detections/aws-console-login-without-mfa.yaml) | Medium | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | AWSCloudTrail |
| [Burst of AccessDenied errors across many AWS APIs from one identity](detections/aws-access-denied-recon-burst.yaml) | Medium | [T1580](https://attack.mitre.org/techniques/T1580/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/), [T1069.003](https://attack.mitre.org/techniques/T1069/003/) | AWSCloudTrail |
| [Many AWS secrets retrieved by one identity](detections/aws-secrets-mass-retrieval.yaml) | Medium | [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | AWSCloudTrail |
| [New IAM user created and given credentials in the same session](detections/aws-iam-user-created-with-credentials.yaml) | Medium | [T1136.003](https://attack.mitre.org/techniques/T1136/003/), [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | AWSCloudTrail |

#### Endpoint (Defender for Endpoint) (22)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [Active Directory database (NTDS.dit) extraction](detections/ntds-dit-extraction.yaml) | High | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | DeviceProcessEvents |
| [Cloud sync tool used to copy data out (rclone, MEGA, restic)](detections/data-exfiltration-tool.yaml) | High | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | DeviceProcessEvents |
| [Impacket-style remote execution (wmiexec, smbexec, DCOM)](detections/impacket-remote-execution.yaml) | High | [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1021.003](https://attack.mitre.org/techniques/T1021/003/), [T1047](https://attack.mitre.org/techniques/T1047/) | DeviceProcessEvents |
| [LSASS memory dump by command line](detections/lsass-memory-dump.yaml) | High | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | DeviceProcessEvents |
| [Mass file renaming to a new extension (possible ransomware encryption)](detections/ransomware-mass-file-rename.yaml) | High | [T1486](https://attack.mitre.org/techniques/T1486/) | DeviceFileEvents |
| [Microsoft Defender protections disabled or excluded from the command line](detections/defender-tampering.yaml) | High | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | DeviceProcessEvents |
| [Office application launches a shell, script host or LOLBin](detections/office-app-spawns-script-host.yaml) | High | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | DeviceProcessEvents |
| [Reverse shell command line on Linux](detections/linux-reverse-shell.yaml) | High | [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | DeviceProcessEvents |
| [SAM, SECURITY or SYSTEM registry hive saved to disk](detections/registry-hive-credential-export.yaml) | High | [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.004](https://attack.mitre.org/techniques/T1003/004/) | DeviceProcessEvents |
| [Shadow copy or backup catalog deletion](detections/shadow-copy-deletion.yaml) | High | [T1490](https://attack.mitre.org/techniques/T1490/) | DeviceProcessEvents |
| [Web server process starts a shell or reconnaissance command (possible web shell)](detections/web-server-spawns-shell.yaml) | High | [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1190](https://attack.mitre.org/techniques/T1190/) | DeviceProcessEvents |
| [Windows event log or audit policy cleared](detections/event-log-cleared.yaml) | High | [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | DeviceProcessEvents, SecurityEvent |
| [AMSI bypass strings in a command line](detections/amsi-bypass-attempt.yaml) | Medium | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | DeviceProcessEvents |
| [Active Directory reconnaissance (AdFind, SharpHound or several discovery commands)](detections/ad-reconnaissance-tools.yaml) | Medium | [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1482](https://attack.mitre.org/techniques/T1482/) | DeviceProcessEvents |
| [Brute force against a device from a public IP (RDP, SMB or SSH)](detections/internet-logon-brute-force.yaml) | Medium | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1133](https://attack.mitre.org/techniques/T1133/) | DeviceLogonEvents |
| [Cryptocurrency miner started](detections/cryptominer-execution.yaml) | Medium | [T1496](https://attack.mitre.org/techniques/T1496/) | DeviceProcessEvents |
| [File downloaded with a built-in Windows tool](detections/lolbin-file-download.yaml) | Medium | [T1105](https://attack.mitre.org/techniques/T1105/), [T1218](https://attack.mitre.org/techniques/T1218/) | DeviceProcessEvents |
| [PowerShell run with a long encoded command](detections/encoded-powershell.yaml) | Medium | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | DeviceProcessEvents |
| [Remote access (RMM) tool runs on a device for the first time](detections/rmm-tool-first-seen.yaml) | Medium | [T1219](https://attack.mitre.org/techniques/T1219/) | DeviceProcessEvents |
| [Run key or Winlogon value points to a script host or user-writable folder](detections/run-key-persistence.yaml) | Medium | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | DeviceRegistryEvents |
| [Scheduled task created that runs a script host, LOLBin or file from a user-writable folder](detections/suspicious-scheduled-task.yaml) | Medium | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | DeviceProcessEvents |
| [Service created that runs a shell, script or binary from a user-writable folder](detections/suspicious-service-created.yaml) | Medium | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | DeviceProcessEvents |

#### Active Directory (3)

| Rule | Severity | ATT&CK | Data |
|---|---|---|---|
| [Directory replication requested by an account that isn't a domain controller (DCSync)](detections/dcsync-replication-by-non-dc.yaml) | High | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | SecurityEvent |
| [Kerberoasting (many RC4 service tickets requested by one account)](detections/kerberoasting.yaml) | High | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | SecurityEvent |
| [Member added to a privileged Active Directory group](detections/privileged-ad-group-member-added.yaml) | High | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | SecurityEvent |

### Hunting queries

Hunts are for questions an analyst asks on purpose, where the results need judgment rather than an automatic alert. Each one has a short "how to hunt" guide in its description.

| Hunt | ATT&CK | Data |
|---|---|---|
| [AWS IAM user's access key used from a new IP](hunting/hunt-aws-access-key-new-ip.yaml) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | AWSCloudTrail |
| [AWS resources created in a region the account doesn't normally use](hunting/hunt-aws-activity-in-new-region.yaml) | [T1496](https://attack.mitre.org/techniques/T1496/), [T1535](https://attack.mitre.org/techniques/T1535/) | AWSCloudTrail |
| [Apps granted access to mailboxes](hunting/hunt-oauth-mail-permissions.yaml) | [T1528](https://attack.mitre.org/techniques/T1528/), [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | AuditLogs |
| [Blocked by Conditional Access, then signed in elsewhere with a password only](hunting/hunt-ca-block-then-single-factor-success.yaml) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | SigninLogs |
| [Bulk download from a SharePoint site the user hasn't used before](hunting/hunt-sharepoint-bulk-download-new-site.yaml) | [T1213.002](https://attack.mitre.org/techniques/T1213/002/), [T1530](https://attack.mitre.org/techniques/T1530/) | OfficeActivity |
| [Dormant account signs in again](hunting/hunt-dormant-account-reactivated.yaml) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | SigninLogs |
| [First use of Azure or Graph command-line tools by a user](hunting/hunt-first-time-admin-tooling.yaml) | [T1059.009](https://attack.mitre.org/techniques/T1059/009/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | SigninLogs |
| [Large numbers of mail items deleted from a mailbox](hunting/hunt-mass-mailbox-deletion.yaml) | [T1070.008](https://attack.mitre.org/techniques/T1070/008/), [T1485](https://attack.mitre.org/techniques/T1485/) | OfficeActivity |
| [MFA fatigue (repeated push denials)](hunting/hunt-mfa-fatigue.yaml) | [T1621](https://attack.mitre.org/techniques/T1621/) | SigninLogs |
| [New credentials added to an app or service principal](hunting/hunt-service-principal-new-credential.yaml) | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | AuditLogs |
| [One account logging on to many devices over the network](hunting/hunt-logon-fan-out.yaml) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | DeviceLogonEvents |
| [Rare executables run from user-writable folders](hunting/hunt-rare-binary-user-writable-path.yaml) | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | DeviceProcessEvents |
| [Regular-interval connections to a public IP (C2 beaconing)](hunting/hunt-network-beaconing.yaml) | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573](https://attack.mitre.org/techniques/T1573/) | DeviceNetworkEvents |
| [Storage account keys listed by a new caller](hunting/hunt-storage-account-key-listing.yaml) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | AzureActivity |
| [Successful sign-ins with rarely seen user agents](hunting/hunt-rare-user-agent.yaml) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | SigninLogs |
| [Users clicked links in mail from a sender domain never seen before](hunting/hunt-clicked-link-new-sender-domain.yaml) | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | EmailEvents, UrlClickEvents |

<!-- catalog:end -->

## How the tests work

```
tests/cases/<rule>.yaml  ──►  tools/build_tests.py  ──►  tests/kql/<rule>.kql      (one self-checking query per rule)
  sample events that              datatable() of the          tests/kql/ALL_TESTS.kql  (all tests, one query)
  should and shouldn't fire       sample logs + the rule's
  + expected results              exact query + PASS/FAIL
```

- **Test cases** (`tests/cases/`) list sample events for each table the rule reads, with timestamps written as offsets ("10m ago", "45d ago") so the tests never go stale, and the expected results: how many rows, which must appear, which must not. `_repeat` and `_step` generate bursts (a spray against 20 users, 150 renamed files).
- **The generator** (`tools/build_tests.py`) builds each test as a KQL query: the sample events as inline `datatable`s named exactly like the Sentinel tables, then the rule's query text unchanged, then a check that returns `PASS` or `FAIL`. Nothing is uploaded or stored anywhere.
- **Running them:** paste `tests/kql/ALL_TESTS.kql` into [Azure Data Explorer](https://dataexplorer.azure.com) (a [free cluster](https://dataexplorer.azure.com/freecluster) works) and run it. You get one PASS/FAIL row per test.
- **Automated checks** (`tools/validate.py`, run by GitHub Actions on every push): required fields, unique GUIDs and names, valid severities and tactics, ATT&CK ID format, every table a query reads is declared in its data connectors, every rule has tuning and triage guidance and a test, and the generated tests, ARM templates and this README's catalog all match the rule files.

### Results

All **95 of 95** tests (79 detections, 16 hunts) pass in Azure Data Explorer, run on 2026-11-21.

## Repository layout

| Path | What's there |
|---|---|
| `detections/` | Scheduled analytics rules (Azure-Sentinel YAML format) |
| `hunting/` | Hunting queries with a "how to hunt" guide in each |
| `tests/cases/`, `tests/kql/` | Sample-data test cases and the generated KQL tests |
| `deploy/` | ARM templates generated from the YAML (`tools/build_deploy.py`) |
| `coverage/attack-layer.json` | ATT&CK Navigator layer generated from the YAML (`tools/build_docs.py`) |
| `tools/` | Test generator, template and docs generators, validator, table schemas |

To add a rule: write `detections/<name>.yaml` and `tests/cases/<name>.yaml`, run `python tools/build_tests.py`, `python tools/build_deploy.py` and `python tools/build_docs.py`, paste `tests/kql/<name>.kql` into Data Explorer, and run `python tools/validate.py`.

## Design choices

- **Every rule has negative tests.** Near misses catch the over-broad version of a rule, which is the version that gets switched off in production.
- **Tested text is deployed text.** The tests and the ARM templates both take the query exactly as it appears in the rule file; there's no separate "test version".
- **Tuning and triage are part of the rule.** Each description says what to change for your environment and what to do in the first ten minutes after it fires.
- **Baselines over static lists where it matters.** "First time this user did X in 14 days" rules (device code, Run Command, RMM tools, service principal countries) adapt to each environment instead of needing a hand-built allow-list.
- **Alerts vs hunts.** Signals that need human judgment (beaconing, rare binaries, first use of admin tooling, new sender domains) are hunts, not alerts, to protect analysts' attention.
- **Deploy disabled.** A rule that alerts before it's tuned trains people to ignore it.

## Limitations

- The tests prove each query's logic against sample events shaped like the real tables. Sample data covers the columns each rule uses, not every column, and operation names and field formats come from Microsoft and AWS documentation and my own experience; a few (notably some Entra audit operation names and AzureActivity request bodies) vary between tenants and API versions. Check a rule against a week of your own data before enabling it.
- Thresholds are starting points; tune them on your own baseline.
- The ARM templates are generated and structurally validated but haven't yet been deployed to a live Sentinel workspace from this repo.
- `tools/kusto.py` (optional, to run tests from a script) uses device-code sign-in. Personal Microsoft accounts were rejected in my testing, so the published results come from running `ALL_TESTS.kql` in the Data Explorer web UI.
- The MFA-fatigue hunt groups denials into clock-hour buckets; a burst that straddles an hour boundary can be split.

## License

MIT
