# ATT&CK Coverage — What This Pack Sees, and What It Doesn't

This is the honest part of the repo. Anyone can write detection rules;
documenting the gaps is what makes them trustworthy.

## Techniques covered

| Technique | Tactic | Rule | Data source required | Confidence |
|---|---|---|---|---|
| T1078 — Valid Accounts | Initial Access | `impossible_travel_workspace_login` | Google Workspace login events with geo-IP enrichment | Medium — depends on geo-IP DB accuracy and VPN noise |
| T1110.003 — Password Spraying | Credential Access | `password_spray` | Google Workspace login failure events | High |
| T1550 / T1528 — OAuth Token Abuse | Persistence | `new_oauth_app_authorized` | Google Workspace token/authorize events | High, but requires a maintained allowlist to avoid noise |
| T1114.003 — Email Forwarding Rule | Collection | `mail_forwarding_rule_created` | Google Workspace Gmail settings events | High |
| T1098 — Account Manipulation | Persistence, Privilege Escalation | `super_admin_role_granted` | Google Workspace admin audit log | High |
| T1059.001 — PowerShell | Execution | `suspicious_encoded_powershell` | Windows process creation (Sysmon Event ID 1 or endpoint EDR telemetry) | Medium — attackers can obfuscate beyond these patterns |
| T1562.001 — Disable or Modify Tools | Defense Evasion | `edr_agent_tampering` | Windows process creation with EDR service/process names | High for this specific EDR; needs updating if EDR vendor changes |

## Known blind spots (as of this version)

- **No coverage for lateral movement (TA0008)** — nothing here detects SMB/RDP/WinRM abuse between endpoints. Requires network flow logs or endpoint EDR network telemetry not yet onboarded.
- **No coverage for data exfiltration volume/timing anomalies (TA0010)** — would require DLP tooling or egress traffic baselining, which this environment does not currently have.
- **No macOS or Linux endpoint coverage** — all endpoint rules assume Windows/Sysmon-style telemetry. If any macOS/Linux endpoints exist in scope, this pack does not cover them.
- **PowerShell rule is signature-based, not behavioral** — a sufficiently obfuscated or non-PowerShell-based execution chain (e.g., living-off-the-land binaries other than powershell.exe) will not trigger it.
- **OAuth allowlist requires manual maintenance** — a new legitimate SaaS tool will generate a false positive until added to `filter_known_good`; this is an intentional trade-off (fail toward visibility, not silence).
- **Impossible-travel rule needs an enrichment step outside Sigma's native rule language** — see `runbooks/impossible_travel.md`. Sigma's condition syntax alone cannot express geo-velocity across two events.

## MITRE ATT&CK Navigator layer

See `coverage/attack-navigator-layer.json` — importable directly at
https://mitre-attack.github.io/attack-navigator/ to visualize coverage
as a heatmap.
