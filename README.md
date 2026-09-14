# sentinel-home-lab
Microsoft Sentinel home lab: SIEM deployment, Windows log ingestion, and KQL-based threat detection




# Microsoft Sentinel Home Lab

I built this lab to get hands-on experience with a real SIEM outside of guided training platforms. The goal was simple: deploy Sentinel in Azure, connect a Windows machine, generate a real security event, and detect it with a KQL query.

## What I Used

| Component | What It Was |
|-----------|-------------|
| Cloud | Microsoft Azure (Azure for Students) |
| SIEM | Microsoft Sentinel |
| Workspace | Akib-sentinel-Logs |
| Log Source | Windows VM (Sentinel-Win-VM) |
| Agent | Azure Monitor Agent (AMA) |
| Rule | DCR-Windows-Security-Events |

## How I Set It Up

1. Created a Log Analytics workspace in Azure
2. Turned on Microsoft Sentinel for that workspace
3. Spun up a Windows VM as my test endpoint
4. Installed the Azure Monitor Agent and created a Data Collection Rule to pull Windows Security Events
5. Deliberately failed a login five times to generate Event ID 4625
6. Wrote a KQL query to find those failed logins in Sentinel

The fifth step was the one that made it feel real. Seeing my own failed login attempts show up in a SIEM dashboard is different from reading about it in a course.

## The Query

```kusto

SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, EventID
| order by TimeGenerated desc



## Detection Rule

After verifying the log pipeline, I built a custom analytics rule in Sentinel:

- **Rule name:** Brute Force - Multiple Failed Logins
- **Logic:** Fires when 5 or more Event ID 4625 events occur on the same computer within 5 minutes
- **Schedule:** Runs every 5 minutes, looking back at the last 5 minutes
- **MITRE ATT&CK:** T1110 (Brute Force) under Credential Access
- **Severity:** Medium
- **Response:** Automatically creates an incident for investigation

The KQL query behind the rule:

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Computer, Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
