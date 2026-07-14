"""
Detection unit tests.

WHAT THIS DOES
---------------
For each rule with field-matchable logic (i.e., not requiring cross-event
correlation), this harness loads the rule's `detection` block and a
paired fixture file containing a `true_positive` event (must fire) and a
`false_positive` event (must NOT fire), then evaluates the rule's simple
selection logic against both.

WHAT THIS DOES NOT DO (be honest about this in interviews)
-----------------------------------------------------------
This is a lightweight, hand-rolled evaluator for `contains` / `equals` /
`re` field matches — it is NOT a full Sigma condition parser. For
production-grade correctness, rules should be converted and tested with
the real pySigma backend (`sigma convert` + `sigma-cli`) against the
target SIEM query language, and validated end-to-end with real telemetry
(see Atomic Red Team validation in the README). This harness exists to
catch obvious regressions in CI cheaply and quickly, not to replace that
end-to-end validation.

The `impossible_travel_workspace_login` rule is intentionally excluded
here: it is a correlation/enrichment rule (geo-velocity across two
events), not a single-event field match, and is validated instead via
the enrichment script described in runbooks/impossible_travel.md.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Maps rule filename (without extension) -> fixture filename (without extension)
# Excludes impossible_travel_workspace_login (correlation rule, see docstring).
RULE_FIXTURE_PAIRS = [
    ("identity/password_spray", "password_spray"),
    ("identity/new_oauth_app_authorized", "new_oauth_app_authorized"),
    ("identity/mail_forwarding_rule_created", "mail_forwarding_rule_created"),
    ("identity/super_admin_role_granted", "super_admin_role_granted"),
    ("endpoint/suspicious_encoded_powershell", "suspicious_encoded_powershell"),
    ("endpoint/edr_agent_tampering", "edr_agent_tampering"),
]


def load_rule(rule_relpath: str) -> dict:
    with open(RULES_DIR / f"{rule_relpath}.yml") as f:
        return yaml.safe_load(f)


def load_fixture(fixture_name: str) -> dict:
    with open(FIXTURES_DIR / f"{fixture_name}.json") as f:
        return json.load(f)


def _match_field(event: dict, field_expr: str, expected) -> bool:
    """Evaluate a single Sigma field expression (e.g. 'CommandLine|contains') against an event."""
    if "|" in field_expr:
        field, modifier = field_expr.split("|", 1)
    else:
        field, modifier = field_expr, "equals"

    value = event.get(field)
    if value is None:
        return False

    if modifier == "contains":
        candidates = expected if isinstance(expected, list) else [expected]
        return any(str(c).lower() in str(value).lower() for c in candidates)
    if modifier == "contains|all":
        candidates = expected if isinstance(expected, list) else [expected]
        return all(str(c).lower() in str(value).lower() for c in candidates)
    if modifier == "endswith":
        candidates = expected if isinstance(expected, list) else [expected]
        return any(str(value).lower().endswith(str(c).lower()) for c in candidates)
    if modifier == "re":
        return re.search(expected, str(value), re.IGNORECASE) is not None
    # plain equals
    candidates = expected if isinstance(expected, list) else [expected]
    return str(value) in [str(c) for c in candidates]


def _eval_selection(event: dict, selection: dict) -> bool:
    return all(_match_field(event, field, expected) for field, expected in selection.items())


def _eval_condition(event: dict, detection: dict) -> bool:
    """
    Very small condition evaluator: supports 'selection', 'selection and not X',
    'A or B' across named selection blocks. Sufficient for the rules in this
    repo; not a general Sigma condition parser.
    """
    condition = detection["condition"]
    selections = {k: v for k, v in detection.items() if k != "condition"}

    # Special-case password spray: its condition uses a count() aggregate,
    # which this per-event evaluator can't compute. Handled separately below.
    if "count(" in condition:
        return None  # signal: needs aggregate handling

    if " and not " in condition:
        left, right = condition.split(" and not ")
        return _eval_selection(event, selections[left.strip()]) and not _eval_selection(
            event, selections[right.strip()]
        )
    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(_eval_selection(event, selections[p]) for p in parts)

    return _eval_selection(event, selections[condition.strip()])


@pytest.mark.parametrize("rule_path,fixture_name", RULE_FIXTURE_PAIRS)
def test_rule_fires_on_true_positive_and_not_on_false_positive(rule_path, fixture_name):
    rule = load_rule(rule_path)
    fixture = load_fixture(fixture_name)
    detection = rule["detection"]

    # Password spray is a threshold/count rule over a timeframe — verified
    # structurally here (enough events, all same source.ip, all login_failure)
    # rather than replaying the full aggregate logic, which belongs in the
    # SIEM's own query engine, not this unit test.
    if rule_path.endswith("password_spray"):
        tp_events = fixture["true_positive"]
        distinct_targets = {e["target.email"] for e in tp_events}
        same_ip = {e["source.ip"] for e in tp_events}
        assert len(distinct_targets) > 10, "true_positive fixture must exceed the >10 distinct-account threshold"
        assert len(same_ip) == 1, "true_positive fixture must originate from a single source IP"

        fp_events = fixture["false_positive"]
        fp_targets = {e["target.email"] for e in fp_events if e.get("event.name") == "login_failure"}
        assert len(fp_targets) < 10, "false_positive fixture must stay under the alert threshold"
        return

    tp_event = fixture["true_positive"][0]
    fp_event = fixture["false_positive"][0]

    tp_result = _eval_condition(tp_event, detection)
    fp_result = _eval_condition(fp_event, detection)

    assert tp_result is True, f"{rule_path}: rule did NOT fire on its true-positive fixture"
    assert fp_result is False, f"{rule_path}: rule incorrectly fired on its false-positive fixture"


def test_all_rules_have_required_fields():
    """Every rule file must have the fields the coverage matrix and CI depend on."""
    required = {"title", "id", "status", "description", "tags", "logsource", "detection", "falsepositives", "level"}
    for rule_relpath, _ in RULE_FIXTURE_PAIRS + [("identity/impossible_travel_workspace_login", None)]:
        rule = load_rule(rule_relpath)
        missing = required - rule.keys()
        assert not missing, f"{rule_relpath} is missing required fields: {missing}"
