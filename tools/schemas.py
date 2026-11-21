"""Column subsets of the Microsoft Sentinel tables the rules use.

Names and types match the Log Analytics tables, so a query that runs against
test data built from these schemas runs unchanged in Sentinel. Only the columns
the rules and hunting queries touch are listed.
"""

SCHEMAS: dict[str, dict[str, str]] = {
    "SigninLogs": {
        "TimeGenerated": "datetime",
        "UserPrincipalName": "string",
        "UserId": "string",
        "IPAddress": "string",
        "Location": "string",
        "ResultType": "string",
        "ResultDescription": "string",
        "AppDisplayName": "string",
        "UserAgent": "string",
        "ConditionalAccessStatus": "string",
        "AuthenticationRequirement": "string",
    },
    "AuditLogs": {
        "TimeGenerated": "datetime",
        "OperationName": "string",
        "Category": "string",
        "Result": "string",
        "InitiatedBy": "dynamic",
        "TargetResources": "dynamic",
        "AdditionalDetails": "dynamic",
    },
    "OfficeActivity": {
        "TimeGenerated": "datetime",
        "Operation": "string",
        "UserId": "string",
        "ClientIP": "string",
        "OfficeWorkload": "string",
        "Parameters": "string",
        "SourceFileName": "string",
        "Site_Url": "string",
        "ResultStatus": "string",
    },
    "AzureDiagnostics": {
        "TimeGenerated": "datetime",
        "ResourceProvider": "string",
        "Category": "string",
        "OperationName": "string",
        "Resource": "string",
        "ResultSignature": "string",
        "CallerIPAddress": "string",
        "identity_claim_upn_s": "string",
        "identity_claim_appid_g": "string",
        "id_s": "string",
    },
    "DeviceProcessEvents": {
        "TimeGenerated": "datetime",
        "DeviceName": "string",
        "AccountName": "string",
        "FileName": "string",
        "ProcessCommandLine": "string",
        "InitiatingProcessFileName": "string",
        "InitiatingProcessCommandLine": "string",
    },
}
