# Sigma Detection Pack — Small Healthcare Org Reference Environment

A detection-as-code repository: portable Sigma rules, tested in CI,
mapped to MITRE ATT&CK, with an honest coverage matrix and a runbook
per rule.

## Why this exists

Most SIEM detection content lives as untested, unversioned rules
buried in a vendor console. This repo treats detections the way you'd
treat application code: version-controlled, peer-reviewed via PR,
tested against synthetic telemetry in CI before anything ships, and
documented well enough that someone other than the author can operate
it during an incident at 2 AM.

The rules are modeled on a **generic reference environment** — a
small, multi-site healthcare organization using Google Workspace as
its identity provider and Windows endpoints with an EDR agent. No real
organization's data, hostnames, IPs, or logs are used anywhere in this
repo; all fixtures are synthetic.

## What's here

```
rules/
  identity/     — Google Workspace identity & access detections
  endpoint/      — Windows endpoint detections
tests/
  fixtures/      — synthetic true-positive / false-positive log samples
  test_rules.py  — CI-run unit tests per rule
coverage/
  coverage.md                  — what this pack sees, and what it doesn't
  attack-navigator-layer.json  — importable ATT&CK Navigator heatmap
runbooks/        — one per rule: what it means, how to triage, what to do
.github/workflows/ci.yml — validates, converts, and tests every rule on every PR
```

## The seven rules

| Rule | ATT&CK | Severity |
|---|---|---|
| Impossible travel login | T1078 | High |
| Password spray | T1110.003 | High |
| New OAuth app authorized | T1550 / T1528 | Medium |
| Mail forwarding rule created | T1114.003 | High |
| Super-admin role granted | T1098 | Critical |
| Suspicious encoded PowerShell | T1059.001 | High |
| EDR agent tampering | T1562.001 | Critical |

These seven were chosen deliberately over a longer list: each is a
well-understood, high-value technique in a Workspace + Windows
environment, and each ships with a working test and a runbook. A
shorter list of rules that are actually tested and documented is more
useful — and more honest — than a long list that isn't.

## Security decisions & trade-offs

- **Detection-as-code over console-only rules.** Every change to a
  detection goes through a pull request, is validated for syntax, is
  converted to a target backend as a sanity check, and is tested
  against both a true-positive and false-positive fixture before merge.
- **Correlation logic is documented, not hidden.** The impossible-travel
  rule cannot be expressed as a single-event Sigma match. Rather than
  force it into the rule file dishonestly, the `.yml` documents the
  intent and required fields, and `runbooks/impossible_travel.md`
  documents the actual enrichment logic that implements it.
- **Bias toward visibility over silence.** Several rules (OAuth
  authorization, mail forwarding) are tuned to over-alert relative to
  under-alert, because the cost of missing a real persistence event is
  higher than the cost of a human spending two minutes closing a false
  positive.
- **The test harness is intentionally lightweight**, not a full Sigma
  condition parser (see the docstring in `tests/test_rules.py`). It
  catches obvious regressions cheaply in CI. It does not replace
  end-to-end validation against real telemetry — see below.

## Validating against real telemetry (Atomic Red Team)

CI testing here proves the *rule logic* is internally consistent. It
does not prove the rule fires against real SIEM telemetry end-to-end.
For that, each rule should be validated by:

1. Running the corresponding **Atomic Red Team** test for the mapped
   ATT&CK technique against a lab endpoint.
2. Confirming the raw event lands in the SIEM.
3. Confirming the converted Sigma rule (via `sigma convert`) actually
   fires an alert on that event.

This two-step validation (CI unit test + Atomic Red Team live fire) is
the standard this repo aims for as it grows.

## Known limitations

See `coverage/coverage.md` for the full, honest list — no lateral
movement coverage, no macOS/Linux endpoint coverage, and the
PowerShell rule is signature-based rather than behavioral. Documenting
gaps openly is part of the point of this repo.

## Roadmap

- Add lateral movement detections (SMB/RDP/WinRM abuse) once network
  flow telemetry is onboarded.
- Add a second backend conversion target in CI (Splunk) to demonstrate
  cross-platform portability.
- Wire Atomic Red Team execution into a scheduled CI job against a
  disposable lab environment.

## Running the tests locally

```
pip install pyyaml pytest
python3 -m pytest tests/ -v
```
