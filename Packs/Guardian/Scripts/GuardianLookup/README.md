Operator-owned automation that runs one optional lookup of a triage playbook without ever stopping the playbook. The six
typed triage sub-playbooks (`GuardianTriagePhishing`, `IdentityThreat`, `EndpointThreat`, `NetworkThreat`, `DataExposure`,
`Vulnerability`) run every reputation, endpoint, CVE and user lookup through it. The model never calls it: it is on the
denylist and not on the allowlist.

## Why it exists
---

A playbook task that runs a generic command (`ip`, `domain`, `url`, `file`, `endpoint`, `cve`) that no enabled integration
implements stops the whole playbook ("Couldnt find any modules to run for command ... - stopping playbook"), even with
*continue on error*. A task marked *skip if unavailable* is marked "will not be executed", and so is every task after it,
the investigation session included. Both ended in an investigation that never ran, with no error. A script that calls
`demisto.executeCommand` gets error entries back instead, so a missing integration or a missing content script becomes a
line in a note.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |
| Cortex XSOAR Version | 6.10.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| command | Required. One of `ip`, `domain`, `url`, `file`, `endpoint`, `cve`, `GetUserData`, `GetEndpointData`. Anything else is refused with a note and nothing is run. |
| ip | The IP address (`ip`, and `endpoint` by address). |
| domain | The domain (`domain`). |
| url | The URL (`url`). |
| file | The file hash (`file`). |
| hostname | The host name (`endpoint`). |
| cve_id | The CVE id (`cve`). |
| user_name | The user name (`GetUserData`). |
| endpoint_hostname | The host name (`GetEndpointData`). |

Only the arguments of the chosen command are read; empty ones are dropped, and when none is left nothing is run.

## What it does
---

1. Calls `demisto.executeCommand(command, args)`. A generic command runs on every enabled integration that implements it,
   as `|||` does.
2. Records the error entries (including "no modules" and "unsupported") and never raises them; an exception from the call
   itself is recorded too.
3. Re-emits the successful entries' context, merged, in one entry: `IP`, `Domain`, `URL`, `File`, `Endpoint`, `CVE`,
   `DBotScore`, `UserData`, `EndpointData`. These are the paths the playbooks' "Add enrichment to the evidence packet" task
   (`GuardianIncidentEvidence mode=append`) reads, so nothing there changes.
4. Writes `Guardian.Lookup.<command>` and a one-line note.

It is read-only. It does not change the incident.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.Lookup.<command>.ok | True when at least one entry came back that is not an error. | Boolean |
| Guardian.Lookup.<command>.error | The error entries' text (secrets masked), or why nothing was run. | String |
| Guardian.Lookup.<command>.seconds | How long the lookup took. | Number |
| IP, Domain, URL, File, Endpoint, CVE, DBotScore, UserData, EndpointData | The context of the successful entries, as the command returned it. | Unknown |

## Timeout
---

The automation keeps the default script timeout (`timeout: '0'`, as every Guardian automation does). A reputation lookup
that takes minutes on a slow integration needs that integration's own timeout and, if your server limits script run time,
a longer script timeout in the automation's settings.

## Command Example
```!GuardianLookup command=ip ip=203.0.113.50```
