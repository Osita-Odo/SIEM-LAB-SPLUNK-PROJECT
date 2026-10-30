# Microsoft Sentinel SOC Lab on Microsoft Azure

A cloud-native SIEM lab built on Microsoft Sentinel. Windows logs from an Active Directory domain are collected with the Azure Monitor Agent, six detections are written in Kusto Query Language (KQL) and mapped to MITRE ATT&CK, and simulated attacks are confirmed as incidents in the Microsoft Defender portal.

This is the Sentinel half of the [SIEM labs](../README.md). It detects the same attacks as the [Splunk SIEM lab](../splunk/README.md), so the two can be compared side by side, and it uses the domain from the [Azure Active Directory Lab](https://github.com/Osita-Odo/azure-active-directory-lab) as its log source.

> **Status: in progress.** Phases 1 to 4 are complete: all six detections are proven by real incidents. In Phase 5, a High incident has been investigated, decoded from the evidence and closed; the rules were then tuned from what the investigation showed (user, payload and service details extracted, entities mapped, alert grouping on), re-tested, and a SOC overview workbook was built. An automated response playbook comes next.

## Objective

Rebuild a working detection pipeline in a cloud-native SIEM: connect Windows endpoints, write detections as scheduled analytics rules, simulate realistic attacks against the domain, and prove each attack raises an incident with the right entities attached.

## Architecture

```mermaid
flowchart LR
    subgraph BE["Azure: Belgium Central"]
        DC["Domain Controller<br/>VM-AD<br/>Azure Monitor Agent + Sysmon"]
        CL["Client workstation<br/>CLIENT01<br/>Azure Monitor Agent + Sysmon"]
    end
    subgraph DE["Azure: Germany West Central"]
        DCR1["dcr-security-events<br/>Security log (Common)"]
        DCR2["dcr-system-sysmon<br/>System 7045, Sysmon 1"]
        LAW["Log Analytics workspace<br/>law-soc-lab-de<br/>SecurityEvent / Event"]
        SEN["Microsoft Sentinel<br/>6 KQL analytics rules"]
    end
    DEF["Microsoft Defender portal<br/>Incidents"]

    DC --> DCR1
    CL --> DCR1
    DC --> DCR2
    CL --> DCR2
    DCR1 --> LAW
    DCR2 --> LAW
    LAW --> SEN
    SEN --> DEF
```

The Azure Monitor Agent on each endpoint follows two data collection rules. One sends Windows Security events to the `SecurityEvent` table; the other sends only System event 7045 and Sysmon event 1 to the `Event` table. Sentinel runs the analytics rules over the workspace and raises incidents in the Defender portal.

### Environment

| Component | Detail |
|---|---|
| SIEM | Microsoft Sentinel, managed through the Microsoft Defender portal |
| Workspace | `law-soc-lab-de`, Germany West Central |
| Licensing | Sentinel free trial: 10 GB/day free for Sentinel and Log Analytics |
| Log sources | Domain controller VM-AD and client CLIENT01 (Belgium Central) |
| Agent | Azure Monitor Agent (AMA) |
| Endpoint telemetry | Sysmon64 (SwiftOnSecurity configuration) |
| Data collection | [`dcr-security-events`](config/dcr-security-events.txt) and [`dcr-system-sysmon`](config/dcr-system-sysmon-xpath.txt) |

> The student email address, university tenant name, subscription and correlation IDs, and the test account password have been redacted from the screenshots. The lab accounts on `ad.terracyb.com` are fictional.

## Detections and MITRE ATT&CK mapping

| Detection | Windows event | MITRE technique | Severity | Status | Query |
|---|---|---|---|---|---|
| Brute-force sign-ins | 4625 | T1110 Brute Force | Medium | Incident raised | [01](detections/01-brute-force-4625.kql) |
| Account lockout | 4740 | T1110 Brute Force | Medium | Incident raised | [02](detections/02-account-lockout-4740.kql) |
| Privileged group change | 4728 / 4732 / 4756 | T1098 Account Manipulation | High | Incident raised | [03](detections/03-privileged-group-change-4728-4732-4756.kql) |
| New account created | 4720 | T1136 Create Account | Medium | Incident raised | [04](detections/04-new-account-4720.kql) |
| Encoded PowerShell | Sysmon 1 | T1059.001 PowerShell | High | Incident raised | [05](detections/05-encoded-powershell-sysmon1.kql) |
| Service installation | 7045 | T1543.003 Windows Service | Medium | Incident raised | [06](detections/06-service-install-7045.kql) |

## How it was built

### Phase 1: Workspace and Sentinel

A Log Analytics workspace was created and Sentinel added to it. The first attempt in Belgium Central, beside the VMs, failed because Sentinel is not offered there (Challenge 1), so the workspace was rebuilt in Germany West Central. Sentinel started on a 31-day free trial, and retention was left at the free default.

![Sentinel enabled with the free trial](images/02-sentinel-free-trial.png)

### Phase 2: Connect the endpoints

The **Windows Security Events** solution was installed from the Content hub and its **Windows Security Events via AMA** connector used to create `dcr-security-events`. The **Common** event set covers every Security event this lab detects without the cost of "All Security Events".

![Common event set selected](images/03-collect-common.png)

The first check returned no data. The Azure Monitor Agent had never been installed (Challenge 3), and was installed from the rule's data-flow status page. Both endpoints then passed the checks and Security events arrived.

![Both endpoints passing the data-flow checks](images/05-passed-initial-checks.png)

```kql
SecurityEvent
| summarize Count = count(), LastSeen = max(TimeGenerated) by Computer
```

![Security events from both endpoints](images/06-security-events-flowing.png)

A second rule, `dcr-system-sysmon`, collects only the two extra events the remaining detections need, using XPath filters on the **Windows Event Logs** data source:

```
System!*[System[(EventID=7045)]]
Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1)]]
```

![The two XPath filters](images/07-xpath-filters.png)

This rule collected nothing for a long time. The cause turned out to be invisible leading spaces in the saved Sysmon filter (Challenge 4). After the fix, System and Sysmon events arrive from both endpoints.

![System events from both endpoints](images/09-system-events-both.png)

![Sysmon event 1 from both endpoints](images/16-sysmon-flowing.png)

### Phase 3: Analytics rules

Sentinel analytics are now managed in the Microsoft Defender portal (Challenge 2). Each detection is a **scheduled query rule** with a MITRE mapping, a KQL query, entity mapping (Account, Host, IP), a schedule and an alert threshold of "greater than 0".

![Mapping the brute-force rule to T1110](images/10-mitre-mapping.png)

![Entity mapping](images/11-entity-mapping.png)

![All six rules active](images/12-six-rules.png)

### Phase 4: Simulate attacks and verify incidents

A fresh test account was created on the domain controller, added to Domain Admins, and then brute-forced from the client:

```powershell
# On VM-AD (as administrator)
New-ADUser -Name "svc_sentinel" -SamAccountName "svc_sentinel" -AccountPassword (ConvertTo-SecureString "<14+ character password>" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_sentinel"

# On CLIENT01
1..8 | ForEach-Object { net use \\VM-AD\IPC$ /user:AD\svc_sentinel "WrongPass$_" 2>$null }
```

![Attack commands on the domain controller](images/13-attack-dc.png)

![The attack events in SecurityEvent](images/14-attack-events.png)

All four Security-event rules raised incidents, with the host and account entities attached:

![Incidents in the Defender portal](images/15-incidents.png)

| Rule | Result | Entities captured |
|---|---|---|
| New account created (4720) | Incident | VM-AD, AD\svc_sentinel |
| Privileged group change | Incident (High) | VM-AD, AD\osita as the actor |
| Account lockout (4740) | Incident | VM-AD and CLIENT01, svc_sentinel |
| Brute-force sign-ins (4625) | Incident, after tuning (Challenge 5) | CLIENT01, svc_sentinel |

Once Sysmon collection was fixed (Challenge 4), the last two attacks were run on VM-AD. Both are harmless: the first only prints text, and the service is created but never started.

```powershell
$c = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "sentinel test"'))
powershell -NoProfile -EncodedCommand $c
sc.exe create TestSvc binPath= "cmd.exe /c echo test"
```

![Service installation and encoded PowerShell events](images/17-final-attack-events.png)

All six rules raised incidents:

![All six detections raised incidents](images/18-all-six-incidents.png)

| Rule | Result | Entities captured |
|---|---|---|
| New account created (4720) | Incident | VM-AD, AD\svc_sentinel |
| Privileged group change | Incident (High) | VM-AD, AD\osita as the actor |
| Account lockout (4740) | Incident | VM-AD and CLIENT01, svc_sentinel |
| Brute-force sign-ins (4625) | Incident, after tuning (Challenge 5) | CLIENT01, svc_sentinel |
| Encoded PowerShell (Sysmon 1) | Incident (High) | VM-AD only at first; host and user mapped after tuning (Challenge 9) |
| Service installation (7045) | Incident | None at first; host mapped after tuning (Challenge 9) |

The first four attacks produced nine incidents; the duplicates and their fix are covered in Challenge 6.

**Clean-up.** The live test changes were then reversed. The incidents and logs remain as evidence.

```powershell
sc.exe delete TestSvc
Remove-ADGroupMember -Identity "Domain Admins" -Members "svc_sentinel" -Confirm:$false
Disable-ADAccount -Identity "svc_sentinel"
```

### Phase 5: Investigate, tune and monitor (in progress)

#### 5.1 Investigate and close an incident

Raising an incident is only half of the SOC job. The Encoded PowerShell incident was worked the way an analyst would: scope it, establish what ran from the evidence, judge it, document the reasoning, close it.

1. **Scope.** One alert, one device (VM-AD), first and last activity at the same second: a single, isolated execution with no related alerts.
2. **Gap noted.** No user entity, because the rule maps only the host (Challenge 9).
3. **Evidence.** The alert does not show the command line, so it was taken from the Sysmon event, with KQL extracting the encoded payload into its own column:

```kql
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational" and EventID == 1
| where RenderedDescription has "EncodedCommand"
| extend Encoded = extract(@"-EncodedCommand\s+(\S+)", 1, RenderedDescription)
| project TimeGenerated, Computer, Encoded, RenderedDescription
```

4. **Decode.** PowerShell encodes commands as UTF-16, so the payload was decoded as Unicode:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHMAZQBuAHQAaQBuAGUAbAAgAHQAZQBzAHQAIgA="))
# Output: Write-Output "sentinel test"
```

5. **Judge and close.** Benign, authorised testing. Assigned, resolved and classified as *Informational, expected activity - Security testing*, with the reasoning recorded on the incident.

![Incident 11 scoped to a single execution on one device](images/19-incident-overview.png)

![Payload extracted from the Sysmon event](images/20-payload-extracted.png)

![Payload decoded](images/21-payload-decoded.png)

![Incident resolved with classification and analyst note](images/22-incident-resolved.png)

![Incident 11 closed as Benign Positive; the graph shows only the device](images/23-incident-11-closed.png)

#### 5.2 Tune the rules from what the investigation showed

The investigation exposed two weaknesses an analyst would raise with the detection team: incident 11 named the device but not the user, and the Service installation incidents named nothing (Challenge 9). Earlier attacks had also opened several incidents for the same activity (Challenge 6). Both were fixed in the rules:

- **Encoded PowerShell:** the query now extracts the user and the encoded payload from the Sysmon event, so the payload is on the alert without a separate search. Host is mapped by `FullName` (the `Computer` column holds the fully qualified name) and a new Account entity uses `AccountName` and `AccountDomain` ([query](detections/05-encoded-powershell-sysmon1.kql)).
- **Service installation:** the query now extracts the service name, file and account, and the host is mapped ([query](detections/06-service-install-7045.kql)).
- **All six rules:** alert grouping enabled, alerts within 5 hours grouped into one incident when all entities match.

The `where` lines are unchanged, so both rules fire on exactly the same events as before.

```kql
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational" and EventID == 1
| where RenderedDescription has "EncodedCommand"
| extend User = extract(@"User: (\S+)", 1, RenderedDescription)
| extend AccountDomain = tostring(split(User, "\\")[0]),
         AccountName   = tostring(split(User, "\\")[1])
| extend EncodedPayload = extract(@"-EncodedCommand\s+(\S+)", 1, RenderedDescription)
| project TimeGenerated, Computer, User, AccountName, AccountDomain, EncodedPayload
```

![Service installation rule with the new query and Host mapping](images/24-service-rule-tuned.png)

![Encoded PowerShell rule with Host and Account entities](images/25-powershell-rule-entities.png)

#### 5.3 Re-test

The encoded command was run twice on VM-AD to test the new entities and alert grouping together, and a second test service was created:

```powershell
$cmd = 'Write-Output "sentinel entity test"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
powershell.exe -EncodedCommand $enc    # about a minute later
sc.exe create TestSvc2 binPath= "C:\Windows\System32\cmd.exe /c echo test" start= demand
```

The updated rules raised **incident 14** (Encoded PowerShell, High) and **incident 15** (Service installation, Medium). Two runs produced one new incident instead of two, which shows alert grouping working. `TestSvc2` was then deleted; the incidents and logs remain as evidence.

![The encoded command run twice on VM-AD](images/26-retest-encoded-powershell.png)

![Cases after the re-test: one new incident for two runs](images/27-cases-after-retest.png)

#### 5.4 SOC Lab Overview workbook

A workbook gives the analyst the state of the environment at a glance, as the Splunk dashboard did in the other lab. It has four panels, all on the last seven days ([queries](workbook/soc-lab-overview-queries.kql)):

| Panel | Visualisation | Shows |
|---|---|---|
| Incidents by Severity | Pie chart | 15 incidents: 9 Medium, 6 High |
| Alerts by Detection Rule | Bar chart | 31 alerts; Account lockout the noisiest (9), because every brute-force test locked the account |
| Top 10 Accounts with Failed Sign-ins | Bar chart | Accounts failing to sign in |
| Open Incidents | Grid | Incidents not yet closed, newest first |

Sentinel writes a new `SecurityIncident` row every time an incident changes, so the incident panels use `arg_max(TimeGenerated, *) by IncidentNumber` to keep only the latest version of each incident. Without it, incidents would be counted several times and closed ones would still appear as open.

![Workbook: incidents by severity](images/28-workbook-severity.png)

![Workbook: alerts by detection rule](images/29-workbook-alerts-by-rule.png)

![Workbook: failed sign-ins and open incidents](images/30-workbook-open-incidents.png)

**Open finding.** The failed sign-ins panel showed five failures for a Microsoft account (`MicrosoftAccount\<name>`, redacted) that is not part of the lab domain. It may be the Remote Desktop client offering the analyst laptop's Windows sign-in before the lab credentials are typed, or sign-in attempts from the internet. The source IP decides which, and is the first triage step in the next session:

```kql
SecurityEvent
| where EventID == 4625 and TargetAccount has "<account name>"
| project TimeGenerated, Computer, TargetAccount, LogonType, IpAddress, WorkstationName, Status, SubStatus
| order by TimeGenerated desc
```

## Next steps

1. Open incidents 14 and 15 and confirm the user and host entities and the alert count.
2. Triage the failed sign-ins from the unrecognised Microsoft account.
3. Close the remaining test incidents with a classification.
4. Create a SOAR playbook (Logic App) that notifies the analyst when a High-severity incident is created.

## Repository contents

```
sentinel/
├── README.md
├── detections/   # KQL analytics rule queries, one per technique
├── workbook/     # KQL queries for the SOC Lab Overview workbook panels
├── config/       # Data collection rule settings and XPath filters
└── images/       # Redacted screenshots used in this README
```

## Challenges and resolutions

### Challenge 1: Sentinel not available in Belgium Central

**What happened.** The first workspace, in Belgium Central, was listed but could not be selected when adding Sentinel, with a banner saying Sentinel runs only in specific regions.

**Cause.** Belgium Central is one of Azure's newest regions and Sentinel is not yet offered there. The student tenant also blocks non-EU regions, so the replacement had to be in the EU.

**Steps to resolve.**
1. Created a new workspace, `law-soc-lab-de`, in Germany West Central (supported, EU, data stays in Germany).
2. Used a different name so Azure would not recover the soft-deleted Belgium workspace instead.
3. Added Sentinel to the new workspace, which was selectable immediately.
4. Deleted the empty Belgium workspace.

**Outcome.** Resolved. The VMs stayed in Belgium Central; the agent sends logs across regions at negligible cost.

![Belgium workspace not selectable](images/01-region-not-supported.png)

### Challenge 2: Sentinel pages moved to the Defender portal

**What happened.** Opening Analytics in the Azure portal showed "This page has been moved to the Defender portal".

**Cause.** New Sentinel workspaces are onboarded to the unified Microsoft Defender portal automatically.

**Steps to resolve.** Followed the link and built all rules in Defender (Analytics, Create, Scheduled query rule); incidents are reviewed there too. Logs, connectors and data collection rules remain in the Azure portal.

**Outcome.** Resolved.

### Challenge 3: No Security events, because the agent was never installed

**What happened.** The ingestion query returned no results for 24 hours despite the data collection rule being created successfully.

**Cause.** The rule deploys the agent when it is associated with a VM, but the VMs were deallocated straight after the rule was created. The deployment never ran, and a stopped VM does not retry it.

**Steps to resolve.**
1. Switched the Logs editor to KQL mode and widened the time range to rule out a query mistake.
2. Checked VM-AD's extensions: `AzureMonitorWindowsAgent` was missing.
3. Checked the VM Guest Agent was "Ready", ruling out a broken guest agent.
4. Looked in the extensions gallery: only third-party agents appeared, and these were deliberately not installed, because the Azure Monitor Agent is deployed through data collection rules.
5. Opened the rule's Resources page: both VMs showed "Needs attention".
6. The data-flow detail stated "Azure Monitor Agent is not installed on this virtual machine", with an **Install agent** action, used on each VM.
7. Both VMs passed the checks and events arrived within minutes.

**Outcome.** Resolved. Lesson: keep VMs running after creating a data collection rule until its resources show "Passed initial checks".

![Root cause shown in the data-flow detail](images/04-agent-not-installed.png)

### Challenge 4: Event table empty, caused by leading spaces in the Sysmon filter

**What happened.** `dcr-system-sysmon` delivered nothing to the `Event` table for hours, although every setting looked correct in the portal.

**Steps to diagnose and resolve.** Each link in the chain was tested in turn:
1. Listed every table receiving data (`union * | summarize count() by Type`): only SecurityEvent, Heartbeat and Usage.
2. Rule association: both VMs "Passed initial checks".
3. Sysmon64 running on VM-AD and logging event 1 every few seconds.
4. Data source: both XPath filters present; destination set to the workspace.
5. Rule JSON view: `dataFlows` sends `Microsoft-Event` to the workspace; provisioning Succeeded.
6. Agent's local copy of the rule on VM-AD: both filters present, stream `GENERIC_EVENT_BLOB` (the agent's internal name for the Event table).
7. Workspace error log (`_LogOperation`): no ingestion errors.
8. Agent restart: `Restart-Service` failed because on Windows the agent runs as extension-managed processes, not a service; both VMs were restarted from the portal instead, with no change.
9. Added a broad test filter (`System!*`) and saved: System events started arriving, proving the pipeline worked.
10. Filtered for Sysmon: zero rows while System events flowed, so the fault was specific to the Sysmon filter.
11. Re-read the agent's local configuration and found the cause: the Sysmon filter was saved as `"   Microsoft-Windows-Sysmon/Operational..."`, with three leading spaces, most likely from pasting. The agent looked for a log by that exact name, found none, and collected nothing. The portal trims leading spaces in its display, so the filter looked correct there.
12. Deleted the Sysmon entry and the test filter, cleared the input box, typed the filter by hand, and saved.
13. Confirmed on VM-AD that the agent downloaded the new configuration (fresh timestamp) and the filter now has no leading spaces.
14. Within minutes, Sysmon event 1 arrived in the `Event` table from both endpoints.

**Root cause.** Leading whitespace in a pasted XPath filter. It passed portal validation and was invisible in the portal view.

**Outcome.** Resolved. Lesson: type XPath filters by hand, and when a data collection rule looks right but collects nothing, read the agent's local copy of the rule rather than trusting the portal view.

![Agent configuration before and after the fix](images/08-agent-config-fix.png)

### Challenge 5: Brute-force rule did not fire

**What happened.** The brute-force attack produced only four 4625 events (three on CLIENT01, one on VM-AD) and no incident.

**Cause.** The lockout policy from the AD lab locked the account after about three failures, so the attack never reached the original threshold of more than five: the preventive control stopped the attack before the detective control saw enough attempts. The original query also grouped by account, source and computer, splitting the failures across two machines.

**Steps to resolve.**
1. Compared the event counts with the rule threshold and the lockout policy.
2. Rewrote the query to count failures per account across all machines and fire at three, matching the lockout threshold ([query](detections/01-brute-force-4625.kql)). Column names were kept so the entity mapping still worked.
3. Re-ran the brute-force loop.

**Outcome.** Resolved; the brute-force incident was raised. Lesson: tune detection thresholds to the preventive controls in place.

### Challenge 6: Duplicate incidents

**What happened.** Four attacks produced nine incidents, for example three for the same new account.

**Cause.** Each rule looks back further than it runs (every 10 minutes over the last 30, for example), so consecutive runs matched the same event and each opened a new incident. In a real SOC this is alert fatigue.

**Steps to resolve.**
1. On each of the six rules: Edit, Incident settings, Alert grouping enabled, alerts within 5 hours grouped into one incident when all entities match, Review + create, Save.
2. Checked each rule's *Last modified* date on the Analytics page to confirm the change had saved.
3. Re-tested by running the same encoded PowerShell command twice.

**Outcome.** Resolved. Two runs produced one new incident (14) instead of two. Lesson: set alert grouping when a rule is created, not after the incident queue fills up.

### Challenge 7: `Unlock-ADAccount` not recognised

**What happened.** Unlocking the test account before repeating the brute-force test returned "not recognized as the name of a cmdlet".

**Cause.** It was run on CLIENT01; the Active Directory PowerShell module is only on the domain controller.

**Steps to resolve.** Confirmed that failed attempts against the locked account still log 4625 (with a locked-out status), which is all the rule needs, so no unlock was required. AD commands run on VM-AD; the `net use` attack runs on CLIENT01.

**Outcome.** Resolved without further action.

### Challenge 8: Typo in a rule name

**What happened.** The privileged group change rule was saved as "rivileged group change", which would appear on every incident.

**Steps to resolve.** Analytics, the rule, Edit, General, corrected the name, Save.

**Outcome.** Resolved; the name was later capitalised to "Privileged group change". Incidents raised before the fix keep the old name, because an incident keeps the name it was created with.

### Challenge 9: Incomplete entity mapping on two rules

**What happened.** The Service installation incident showed no impacted assets at all, and the Encoded PowerShell incident showed a device but no user, so neither said who was involved.

**Cause.** Entities only appear on an incident if the rule maps them. The service installation rule had no mapping, and the encoded PowerShell rule mapped only the host, because its query does not extract the user from the Sysmon event text.

**Steps to resolve.**
1. Compared impacted assets across incidents: every other rule shows a host and an account.
2. Service installation: rewrote the query to extract the service name, file and account, and mapped Host with identifier `FullName` to `Computer` (FullName rather than HostName, because `Computer` holds the fully qualified name).
3. Encoded PowerShell: rewrote the query to extract the user (split into `AccountName` and `AccountDomain`) and the encoded payload, changed the Host identifier to `FullName`, and added an Account entity.
4. Re-ran both attacks; the updated rules raised incidents 14 and 15.

**Outcome.** Fixes applied and re-tested. Confirming the entities on the incident pages of 14 and 15 is the first step of the next session. Lesson: test that every rule returns the entities an analyst needs, not just that it fires.

### Challenge 10: Decoding the payload failed twice

**What happened.** The first decode returned "The input is not a valid Base-64 string", and the next attempt nearly failed the same way.

**Cause.** The first attempt still contained the placeholder text instead of the payload. The second copied value had lost its final `=`. Base64 is written in blocks of four characters with `=` as padding; the copied string was 75 characters long, so it was invalid without it.

**Steps to resolve.**
1. Took the value from the log rather than retyping it.
2. Added a KQL `extract()` so the payload sits in its own column, which is easier to copy accurately than a long event description.
3. Checked the length (75 is not a multiple of four), recopied the full value including the `=`, and decoded it.

**Outcome.** Resolved. Lesson: take evidence directly from the source, and know enough about the encoding to spot a truncated value.

### Challenge 11: Portal labels changed again during the build

**What happened.** Instructions did not match the screen: incidents were now listed under **Cases** (with a Case ID beside the Incident ID), and the workbook editor had no *Add query* option.

**Cause.** Microsoft is still reorganising the unified Defender portal (see Challenge 2). Incidents are now managed as cases, and *Add query* was renamed *Add data source + visualization*.

**Steps to resolve.** Matched each new label to the documented function, and confirmed the function was unchanged by checking the panel settings (data source, workspace, time range, visualisation, query).

**Outcome.** Resolved. Lesson: in cloud consoles, follow the function rather than the exact label, and record the label in use on the date of the build.

## Skills demonstrated

- Deploying Microsoft Sentinel on a Log Analytics workspace and working within regional and tenant constraints
- Collecting Windows Security, System and Sysmon logs with the Azure Monitor Agent and data collection rules, including XPath filtering for cost control
- Writing KQL analytics rules mapped to MITRE ATT&CK, with entity mapping and scheduling
- Simulating attacks against an Active Directory domain and verifying incidents in the Defender portal
- Systematic troubleshooting of an ingestion pipeline from the portal down to the agent's local configuration
- Detection tuning: aligning thresholds with lockout policy and diagnosing duplicate incidents
- Incident triage: scoping an incident, extracting and decoding an obfuscated PowerShell payload from the evidence, and closing it with a documented classification
- Improving detections from investigation findings: extracting context into the alert, mapping host and account entities, and grouping alerts to reduce duplicate incidents
- Building a Sentinel workbook for an at-a-glance SOC view, and spotting an unexpected account from it
