Throwaway liveness-check automation used to prove the Guardian content delivery pipeline
(author -> validate -> upload -> server-side run) end-to-end before building the real
Guardian automations. It takes no arguments and always returns `pong`.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |
| Cortex XSOAR Version | 6.10.0 |

## Inputs
---
There are no inputs for this script.

## Outputs
---
| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.Ping | Static "pong" payload confirming the script executed on the server. | String |

## Command Example
```!GuardianPing```

## Human Readable Output
```
pong
```
