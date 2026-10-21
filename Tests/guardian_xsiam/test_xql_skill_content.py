"""Content checks for the `cortex_xql` skill: the text the model reads before it writes its own XQL.

The skill must agree with the data it summarises (the templates List), name only datasets and fields that are known to
exist on the Cortex platform, carry the rules that keep a query cheap and exact, and name nobody. The dataset and field
sets below are hard-coded on purpose: a new name is added here only after it was seen in the templates List, an existing
skill or a read-only schema survey of a real tenant, so a typo or a guess in the skill fails the test.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "Packs" / "GuardianXSIAM"
LISTS = PACK / "Lists"
FORBIDDEN_FILE = ROOT / "scripts" / "release_forbidden.local.txt"

#: Datasets whose fields are verified. The skill's examples may use only these.
VERIFIED_FIELDS = {
    "cloud_audit_logs": {
        "_time", "cloud_provider", "service_type", "event_type", "log_name", "project", "region", "identity_name",
        "identity_uuid", "identity_type", "identity_sub_type", "identity_invoked_by_name", "identity_invoked_by_type",
        "operation_name", "operation_status", "referenced_resource", "referenced_resource_name", "resource_type", "resource_sub_type",
        "state_changing_event", "caller_ip", "caller_ip_geolocation", "caller_ip_asn_org", "user_agent",
    },
    "ciem_permissions_with_last_access": {
        "source_cloud_resource_name", "source_cloud_resource_type", "action_name", "action_access_level",
        "action_access_isadministrative", "dest_cloud_resource_name", "dest_cloud_service_name",
        "grantedby_cloud_policy_name", "is_last_access_supported", "last_access_time",
    },
    # the data source health preset (`preset = metrics_view`); `last_seen` is epoch milliseconds
    "metrics_view": {
        "total_event_count", "total_event_rate", "total_size_bytes", "last_seen", "data_freshness_max_delay",
        "data_freshness_median", "_vendor", "_product", "_collector_type", "_collector_name", "_reporting_device_ip",
        "_final_reporting_device_ip", "_broker_device_name", "_broker_device_ip", "_time",
    },
}
#: The `dataset` shown for a template that works on whichever dataset the caller names (its `dataset` parameter).
PARAMETRIC_DATASET = "{dataset}"
#: Fields the skill says to keep out of `fields` because they are very long: named, but not for use in a query.
NAMED_BUT_AVOIDED = {"raw_log", "operation_name_orig", "backtrace_identities"}
#: Datasets the skill may name as existing without verified fields.
NAMED_UNVERIFIED_DATASETS = {"xdr_data", "endpoints", "auth_logs", "login_logs", "saas_audit_logs", "alerts"}


def _wrapper(name):
    return json.loads((LISTS / "list-{}.json".format(name)).read_text())


def _skill():
    return _wrapper("guardian_skill_cortex_xql")["data"]


def _templates():
    return json.loads(_wrapper("guardian_xql_templates")["data"])["templates"]


def _index():
    return {e["name"]: e for e in json.loads(_wrapper("guardian_skills_index")["data"])}


def _examples():
    """The raw XQL queries in the skill's fenced blocks, one per block."""
    return [block.strip() for block in re.findall(r"```\n(.*?)```", _skill(), flags=re.S)]


def _frontmatter(body):
    match = re.match(r"---\n(.*?)\n---\n", body, flags=re.S)
    assert match, "the skill has no frontmatter"
    fields = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(": ")
        fields[key] = value
    return fields


# --- the List and the index -----------------------------------------------------------------------------------------

def test_the_skill_list_parses_and_has_the_wrapper_of_the_other_skills():
    wrapper = _wrapper("guardian_skill_cortex_xql")
    other = _wrapper("guardian_skill_cortex_triage")
    assert set(wrapper) == set(other)
    assert wrapper["id"] == wrapper["name"] == "guardian_skill_cortex_xql"
    assert wrapper["type"] == "markdown" and wrapper["version"] == -1 and isinstance(wrapper["data"], str)


def test_the_skill_is_indexed_enabled_and_its_frontmatter_matches_the_index_entry():
    entry = _index()["cortex_xql"]
    assert entry["enabled"] is True and entry["category"] == "foundation"
    front = _frontmatter(_skill())
    assert front["name"] == "cortex_xql"
    description = front["description"]
    assert description.startswith("'") and description.endswith("'")
    assert description[1:-1].replace("''", "'") == entry["description"]
    assert entry["description"].startswith("LOAD BEFORE WRITING A RAW XQL QUERY")


def test_the_model_is_pointed_to_the_skill_where_it_decides_to_write_raw_xql():
    tail = _wrapper("guardian_prompt_tail")["data"]
    assert "GuardianSkillRead name=cortex_xql" in tail
    assert "your own XQL as `GuardianXQL query=" in tail.replace("\\`", "`")


# --- the templates --------------------------------------------------------------------------------------------------

def test_every_template_the_skill_names_exists_and_every_template_is_covered():
    names = {t["name"] for t in _templates()}
    skill = _skill()
    mentioned = set(re.findall(r"template=([a-z_]+)", skill)) - {"list"}
    mentioned |= set(re.findall(r"^\| `([a-z_]+)` \|", skill, flags=re.M))
    assert mentioned and mentioned <= names, sorted(mentioned - names)
    assert names <= mentioned, sorted(names - mentioned)


def test_the_template_table_agrees_with_the_templates_list():
    skill = _skill()
    for template in _templates():
        rows = [line for line in skill.splitlines() if line.startswith("| `{}` |".format(template["name"]))]
        assert len(rows) == 1, template["name"]
        cells = [c.strip() for c in rows[0].strip("|").split("|")]
        assert cells[2] == ", ".join("`{}`".format(param) for param in template["params"])
        assert cells[3] == "`{}`".format(template["dataset"])
        assert cells[4] == "{} / {}".format(template["default_hours"], template["max_hours"]), template["name"]


def test_the_identity_activity_account_query_uses_the_split_form_and_no_regex():
    """A `DOMAIN\\account` is matched on the UPN's local part. The regex form (`~=`) parsed on a real tenant but matched
    nothing, so no template may carry it."""
    raw = (LISTS / "list-guardian_xql_templates.json").read_text()
    assert "~=" not in raw
    template = next(t for t in _templates() if t["name"] == "identity_activity")
    assert "~=" not in template["account_query"] and "~=" not in template["query"]
    assert 'arrayindex(split(lowercase(identity_name), "@"), 0) = "{account}"' in template["account_query"]


def test_every_template_reads_a_verified_dataset():
    for template in _templates():
        if template["params"] == ["dataset"]:
            assert template["dataset"] == PARAMETRIC_DATASET and "{dataset}" in template["query"], template["name"]
        else:
            assert template["dataset"] in VERIFIED_FIELDS, template["name"]


def test_the_data_source_health_templates_filter_early_aggregate_on_the_server_and_say_how_to_read_last_seen():
    by_name = {t["name"]: t for t in _templates()}
    health, senders = by_name["source_ingestion_health"], by_name["reporter_sources"]
    assert health["query"].startswith("preset = metrics_view | filter ") and senders["query"].startswith("preset = metrics_view | filter ")
    assert health["params"] == ["vendor", "product"] and (health["default_hours"], health["max_hours"]) == (24, 168)
    assert senders["params"] == ["ip"] and (senders["default_hours"], senders["max_hours"]) == (24, 168)
    for template in (health, senders):
        assert " | comp " in template["query"] and "last_seen_utc" in template["description"] and "format_timestamp(" in template["query"]
        assert {"total_event_count", "last_seen", "_vendor", "_product"} <= set(re.findall(r"[A-Za-z_]+", template["query"]))
    for name, stage in (("dataset_raw_volume", "dataset = {dataset} | bin _time span = 1h | comp count() as raw_events by _time"),
                        ("datamodel_volume", "datamodel dataset = {dataset} | bin _time span = 1h | comp count() as modeled_events by _time")):
        assert by_name[name]["query"].startswith(stage) and by_name[name]["default_hours"] == 24


# --- datasets and fields --------------------------------------------------------------------------------------------

def test_every_dataset_in_the_examples_is_a_verified_one():
    examples = _examples()
    assert 2 <= len(examples) <= 4
    for query in examples:
        datasets = re.findall(r"dataset\s*=\s*(\w+)", query)
        assert len(datasets) == 1 and datasets[0] in VERIFIED_FIELDS, query


def test_every_field_the_examples_use_exists_on_their_dataset():
    for query in _examples():
        known = VERIFIED_FIELDS[re.search(r"dataset\s*=\s*(\w+)", query).group(1)]
        used = set(re.findall(r"(?:filter|and|or)\s+(\w+)\s*(?:=|!=|contains)\s", query))
        used |= set(re.findall(r"\b(?:values|count_distinct|min|max)\((\w+)\)", query))
        for group in re.findall(r"\bby\s+([\w,\s]+?)\s*\|", query):
            used |= {part.strip() for part in group.split(",")}
        assert used and used <= known, (query, sorted(used - known))


def test_every_dataset_the_skill_names_in_backticks_is_known():
    names = set(re.findall(r"`([a-z]+(?:_[a-z]+)+)`", _skill()))
    known = set(VERIFIED_FIELDS) | NAMED_UNVERIFIED_DATASETS | NAMED_BUT_AVOIDED | {t["name"] for t in _templates()}
    known |= {f for fields in VERIFIED_FIELDS.values() for f in fields}
    known |= {"last_access_time", "is_last_access_supported", "query_cost", "execution_id", "state_changing_event", "anchor_time"}
    assert not (names - known), sorted(names - known)


def test_no_example_queries_the_issues_or_cases_dataset():
    for query in _examples():
        assert not re.search(r"dataset\s*=\s*(issues|cases)\b", query)


# --- the rules the skill exists to teach ----------------------------------------------------------------------------

def test_the_skill_carries_the_value_passing_and_gotcha_rules():
    skill = _skill()
    assert 'state_changing_event = "true"' in skill and "STRING" in skill
    assert "`=` is an exact match" in skill and "`contains` is a substring match" in skill
    # one backslash in a template parameter, two inside a raw string literal
    assert "identity=CORP\\svc_backup" in skill and "ONE backslash" in skill
    assert 'identity_name = "CORP\\\\svc_backup"' in skill and "written `\\\\`" in skill


def test_the_skill_carries_the_cost_and_reading_rules():
    skill = _skill()
    for needle in ("daily limit", "shared with the customer", "Filter first", "`comp", "`fields`", "`limit` caps the output",
                   "core-get-issues", "cost nothing", "dataset = issues", "0 rows", "not proof", "does not authorise",
                   "not run again with the same filter", "GuardianXQL execution_id=", "wider window rarely helps"):
        assert needle in skill, needle


def test_the_skill_stays_short():
    assert len(_skill()) <= 8000


# --- no customer names ----------------------------------------------------------------------------------------------

def test_the_skill_the_index_and_the_tail_name_no_customer():
    if not FORBIDDEN_FILE.exists():
        pytest.skip("scripts/release_forbidden.local.txt is not present (it is kept out of git)")
    patterns = [re.compile(line.strip(), re.IGNORECASE) for line in FORBIDDEN_FILE.read_text().splitlines()
                if line.strip() and not line.startswith("#")]
    assert patterns
    for name in ("guardian_skill_cortex_xql", "guardian_skills_index", "guardian_prompt_tail"):
        text = (LISTS / "list-{}.json".format(name)).read_text() + json.dumps(_wrapper(name)["data"])
        hits = [i for i, pattern in enumerate(patterns, 1) if pattern.search(text)]
        # report the file and the pattern's position only, never the text that matched
        assert not hits, "{} matches forbidden pattern line(s) {}".format(name, hits)


def test_no_bullet_in_the_skill_is_run_into_the_line_before_it():
    """A `- ` bullet starts its own line; one glued after a sentence ("... changes. - Set the window ...") breaks the list."""
    for line in _skill().splitlines():
        assert not re.search(r"[.!?]\s+- [A-Z`]", line), line
