# Microsoft Sentinel Home Lab

I built this lab to get hands-on experience with a real SIEM outside of guided training platforms. The repo covers two things: connecting a Windows endpoint to Sentinel, and building a detection rule on top of it.

---

## Project 1: Log Ingestion & First Query

### What I Used

| Component | What It Was |
|-----------|-------------|
| Cloud | Microsoft Azure (Azure for Students) |
| SIEM | Microsoft Sentinel |
| Workspace | Akib-sentinel-Logs |
| Log Source | Windows VM (Sentinel-Win-VM) |
| Agent | Azure Monitor Agent (AMA) |
| Rule | DCR-Windows-Security-Events |

### How I Set It Up

1. Created a Log Analytics workspace in Azure
2. Turned on Microsoft Sentinel for that workspace
3. Spun up a Windows VM as my test endpoint
4. Installed the Azure Monitor Agent and created a Data Collection Rule to pull Windows Security Events
5. Deliberately failed a login five times to generate Event ID 4625
6. Wrote a KQL query to find those failed logins in Sentinel

The fifth step was the one that made it feel real. Seeing my own failed login attempts show up in a SIEM dashboard is different from reading about it in a course.

### What the Results Looked Like

![Sentinel 4625 Query Results](screenshots/sentinel-4625-query-results.png)

### What I Learned

- **Patience with ingestion.** After creating the Data Collection Rule, nothing showed up for several minutes. I thought I'd done something wrong. Turns out log ingestion just takes time.
- **The agent has to be there.** No Azure Monitor Agent, no logs. Simple as that.
- **Event ID 4625 is not just one thing.** It captures failed logons from interactive logins, network logins, and service accounts. Context matters when triaging.
- **KQL is actually enjoyable.** Once I got the syntax, filtering and projecting fields felt natural.

---

## Project 2: Brute Force Detection Rule

### What I Built

- **Rule name:** Brute Force - Multiple Failed Logins
- **Logic:** Fires when 5 or more Event ID 4625 events occur on the same computer within 5 minutes
- **Schedule:** Runs every 5 minutes, looking back at the last 5 minutes
- **MITRE ATT&CK:** T1110 (Brute Force) under Credential Access
- **Severity:** Medium
- **Response:** Automatically creates an incident for investigation

### The Detection Query

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Computer, Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
