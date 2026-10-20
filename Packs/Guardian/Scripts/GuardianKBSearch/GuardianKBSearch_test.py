import json

import pytest

import GuardianKBSearch as gks


# --- test fixtures -----------------------------------------------------------


def _entries_for_list(lists_map, list_name):
    """Fake `getList` response for `list_name`, keyed off `lists_map`
    ({list_name: <already-JSON-encodable python value>}). Anything not
    present in `lists_map` comes back "Item not found", mirroring real
    `getList` behavior for a List that doesn't exist on the box.
    """
    if list_name in lists_map:
        payload = lists_map[list_name]
        contents = payload if isinstance(payload, str) else json.dumps(payload)
        return [{"Type": 1, "Contents": contents}]
    return [{"Type": 4, "Contents": "Item not found (8) on list [{}]".format(list_name)}]


def _install_lists(monkeypatch, lists_map):
    def fake_execute(command, args):
        assert command == "getList"
        return _entries_for_list(lists_map, args["listName"])

    monkeypatch.setattr(gks.demisto, "executeCommand", fake_execute)


def _entry(id_, technique, category, title, tags, body):
    return {"id": id_, "technique": technique, "category": category, "title": title, "tags": tags, "body": body}


# A small fixture KB modeling the real shape: 3 attack-technique guides + 2
# playbooks, one of which (pb-lateral-movement) shares T1021 with an
# attack-technique guide via its tags -- exercising the technique-filter
# tags-fallback the module docstring describes.
KB_ENTRIES = [
    _entry(
        "T1021",
        "T1021",
        "attack-technique",
        "Remote Services: RDP and SMB/Windows Admin Shares",
        ["lateral-movement", "rdp", "smb"],
        "Adversary moves laterally using RDP or SMB admin shares. Investigation steps: check "
        "event 4624 type 10 for RDP logons and correlate with the source host.",
    ),
    _entry(
        "T1003.001",
        "T1003.001",
        "attack-technique",
        "OS Credential Dumping: LSASS Memory",
        ["credential-access", "lsass", "mimikatz"],
        "Adversary dumps LSASS memory using mimikatz to extract credentials. Investigation "
        "steps: check Sysmon Event 10 for handles to lsass.exe.",
    ),
    _entry(
        "T1486",
        "T1486",
        "attack-technique",
        "Data Encrypted for Impact: Ransomware",
        ["ransomware", "impact", "encryption"],
        "Adversary encrypts files for ransom. Investigation steps: identify patient zero and "
        "check for shadow-copy deletion.",
    ),
    _entry(
        "pb-lateral-movement",
        "T1021",
        "playbook",
        "Playbook: Lateral Movement Investigation",
        ["lateral-movement", "rdp", "T1021", "T1570"],
        "When to use: anomalous remote-logon chains, PsExec/WMI/RDP. Investigation steps: "
        "identify the source host and reconstruct the rdp logon chain.",
    ),
    _entry(
        "pb-credential-access",
        "T1003.001",
        "playbook",
        "Playbook: Credential Access Investigation",
        ["credential-access", "T1003.001", "T1558"],
        "When to use: mimikatz alerts, LSASS dumping detected, DCSync attempts. Investigation "
        "steps: scope every host the harvested credential touched.",
    ),
]


def _install_kb(monkeypatch, entries=None):
    _install_lists(monkeypatch, {gks.GUARDIAN_KBSEARCH_LIST_NAME: entries if entries is not None else KB_ENTRIES})


# --- guardian_kbsearch_load_entries ------------------------------------------


def test_load_entries_parses_json_list(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch_load_entries()
    assert result["ok"] is True
    assert len(result["data"]) == 5


def test_load_entries_missing_list_is_a_real_error(monkeypatch):
    _install_lists(monkeypatch, {})
    result = gks.guardian_kbsearch_load_entries()
    assert result["ok"] is False
    assert "does not exist" in result["error"]


def test_load_entries_non_json_string_is_error(monkeypatch):
    _install_lists(monkeypatch, {gks.GUARDIAN_KBSEARCH_LIST_NAME: "not json {{{"})
    result = gks.guardian_kbsearch_load_entries()
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_load_entries_non_array_payload_is_error(monkeypatch):
    _install_lists(monkeypatch, {gks.GUARDIAN_KBSEARCH_LIST_NAME: {"not": "an array"}})
    result = gks.guardian_kbsearch_load_entries()
    assert result["ok"] is False
    assert "not a JSON array" in result["error"]


# --- guardian_kbsearch: input validation --------------------------------------


def test_search_requires_query(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query=None)
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


def test_search_rejects_blank_query(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="   ")
    assert result["ok"] is False
    assert "NEEDS_CONTEXT" in result["error"]


# --- AND-semantics ------------------------------------------------------------


def test_and_semantics_requires_every_token(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="lateral movement rdp")
    assert result["ok"] is True
    ids = {r["id"] for r in result["data"]["results"]}
    # Only the two lateral-movement/RDP entries carry ALL three tokens
    # (via their "lateral-movement"/"rdp" tags) -- the LSASS, ransomware, and
    # credential-access playbook entries carry none of them.
    assert ids == {"T1021", "pb-lateral-movement"}


def test_and_semantics_excludes_partial_matches(monkeypatch):
    _install_kb(monkeypatch)
    # "rdp" alone matches T1021/pb-lateral-movement; "mimikatz" alone matches
    # the two credential-access entries. No single entry has both "rdp" AND
    # "mimikatz" -- AND-semantics must exclude everything.
    result = gks.guardian_kbsearch(query="rdp mimikatz")
    assert result["ok"] is True
    assert result["data"]["results"] == []
    assert result["data"]["count"] == 0


def test_no_match_is_graceful_not_an_error(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="zzz_nonsense_token_zzz")
    assert result["ok"] is True
    assert result["data"]["results"] == []
    assert result["data"]["count"] == 0
    assert result["data"]["total_kb_entries"] == 5


# --- technique / tag filters ---------------------------------------------------


def test_technique_filter_narrows_via_own_field_and_tags_fallback(monkeypatch):
    _install_kb(monkeypatch)
    # "investigation" appears in every fixture entry's body -- without a
    # filter all 5 match; technique=T1021 should narrow to exactly the
    # attack-technique guide (own `technique` field) plus the playbook
    # (whose `technique` field is also T1021 here, exercising the same
    # equality path -- the tags-fallback is covered by the dedicated test
    # below with a playbook whose PROMOTED technique differs from a
    # secondary tag).
    unfiltered = gks.guardian_kbsearch(query="investigation")
    assert unfiltered["data"]["count"] == 5

    filtered = gks.guardian_kbsearch(query="investigation", technique="T1021")
    ids = {r["id"] for r in filtered["data"]["results"]}
    assert ids == {"T1021", "pb-lateral-movement"}


def test_technique_filter_matches_via_tags_fallback_not_own_field(monkeypatch):
    # A playbook whose PROMOTED `technique` is T9999 (something else) but
    # whose tags also list T1021 as a secondary technique -- the filter must
    # still surface it for technique="T1021" via the tags fallback.
    entries = [
        _entry("T1021", "T1021", "attack-technique", "Remote Services", ["rdp"], "rdp guidance body"),
        _entry(
            "pb-multi-technique",
            "T9999",
            "playbook",
            "Playbook: Multi-technique",
            ["T9999", "T1021"],
            "some playbook body",
        ),
    ]
    _install_kb(monkeypatch, entries)

    result = gks.guardian_kbsearch(query="guidance body", technique="T1021")
    # Only T1021's own body/title matches "guidance body" via AND-semantics
    # (the playbook body doesn't contain those words) -- so exercise the
    # filter helper directly instead for the tags-fallback assertion.
    assert gks.guardian_kbsearch_matches_technique(entries[1], "T1021") is True
    assert gks.guardian_kbsearch_matches_technique(entries[1], "T9999") is True
    assert gks.guardian_kbsearch_matches_technique(entries[1], "T1003.001") is False
    assert result["ok"] is True  # sanity: the call itself still succeeds


def test_technique_filter_is_case_insensitive(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="investigation", technique="t1486")
    ids = {r["id"] for r in result["data"]["results"]}
    assert ids == {"T1486"}
    assert result["data"]["technique"] == "T1486"


def test_tags_filter_narrows_or_semantics(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="investigation", tags="ransomware")
    ids = {r["id"] for r in result["data"]["results"]}
    assert ids == {"T1486"}


def test_tags_filter_json_array_string(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="investigation", tags='["ransomware", "lsass"]')
    ids = {r["id"] for r in result["data"]["results"]}
    assert ids == {"T1486", "T1003.001"}


def test_combined_query_and_technique_and_tags(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="investigation", technique="T1021", tags="rdp")
    ids = {r["id"] for r in result["data"]["results"]}
    assert ids == {"T1021", "pb-lateral-movement"}


# --- ranking by weighted match count ------------------------------------------


def test_ranking_prefers_title_tag_hits_over_body_only(monkeypatch):
    _install_kb(monkeypatch)
    # "mimikatz" is a TAG on T1003.001 (counted GUARDIAN_KBSEARCH_TAGS_REPEAT
    # times) plus one body occurrence; on pb-credential-access it is a
    # BODY-only occurrence (not a tag) -- T1003.001 must outrank it.
    result = gks.guardian_kbsearch(query="mimikatz")
    ids_in_order = [r["id"] for r in result["data"]["results"]]
    assert ids_in_order == ["T1003.001", "pb-credential-access"]
    scores = {r["id"]: r["score"] for r in result["data"]["results"]}
    assert scores["T1003.001"] > scores["pb-credential-access"]


def test_phrase_bonus_outranks_scattered_tokens(monkeypatch):
    entries = [
        _entry(
            "contiguous",
            "T0001",
            "attack-technique",
            "Contiguous phrase entry",
            [],
            "Our remote services are great for admins.",
        ),
        _entry(
            "scattered",
            "T0002",
            "attack-technique",
            "Scattered tokens entry",
            [],
            "Remote access reaches many internal services eventually.",
        ),
    ]
    _install_kb(monkeypatch, entries)

    result = gks.guardian_kbsearch(query="remote services")
    ids_in_order = [r["id"] for r in result["data"]["results"]]
    assert ids_in_order[0] == "contiguous"
    scores = {r["id"]: r["score"] for r in result["data"]["results"]}
    assert scores["contiguous"] > scores["scattered"]


def test_single_token_query_never_gets_phrase_bonus(monkeypatch):
    # Phrase bonus requires >1 token -- a one-word query has no "phrase" to
    # reward, so score should be exactly the plain weighted match count.
    entries = [_entry("solo", "T0001", "attack-technique", "Solo", [], "alpha alpha alpha")]
    _install_kb(monkeypatch, entries)
    result = gks.guardian_kbsearch(query="alpha")
    assert result["data"]["results"][0]["score"] == 3.0  # BODY_REPEAT=1 * 3 occurrences


# --- snippet trimming ----------------------------------------------------------


def test_snippet_centers_on_body_match_with_ellipses(monkeypatch):
    padding = "x" * 500
    body = "{} NEEDLE found here {}".format(padding, "y" * 500)
    entries = [_entry("t1", "T0001", "attack-technique", "Title has none of the tokens", [], body)]
    _install_kb(monkeypatch, entries)

    result = gks.guardian_kbsearch(query="needle")
    snippet = result["data"]["results"][0]["snippet"]
    assert "NEEDLE" in snippet
    assert snippet.startswith("...")
    assert snippet.endswith("...")
    assert len(snippet) < len(body)


def test_snippet_falls_back_to_leading_text_when_body_has_no_token(monkeypatch):
    body = "z" * 500  # never contains the query token at all
    entries = [_entry("t1", "T0001", "attack-technique", "keywordhit title only", [], body)]
    _install_kb(monkeypatch, entries)

    result = gks.guardian_kbsearch(query="keywordhit")
    snippet = result["data"]["results"][0]["snippet"]
    assert snippet.startswith("z" * 10)
    assert not snippet.startswith("...")
    assert snippet.endswith("...")


def test_snippet_no_truncation_marker_when_body_shorter_than_window(monkeypatch):
    entries = [_entry("t1", "T0001", "attack-technique", "Title", [], "short body with needle inside")]
    _install_kb(monkeypatch, entries)

    result = gks.guardian_kbsearch(query="needle")
    snippet = result["data"]["results"][0]["snippet"]
    assert snippet == "short body with needle inside"


# --- limit ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, gks.GUARDIAN_KBSEARCH_DEFAULT_LIMIT),
        ("", gks.GUARDIAN_KBSEARCH_DEFAULT_LIMIT),
        ("not-a-number", gks.GUARDIAN_KBSEARCH_DEFAULT_LIMIT),
        (0, 1),
        (-5, 1),
        (100, gks.GUARDIAN_KBSEARCH_MAX_LIMIT),
        ("3", 3),
    ],
)
def test_parse_limit_clamping(raw, expected):
    assert gks.guardian_kbsearch_parse_limit(raw) == expected


def test_limit_actually_caps_result_count(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="investigation", limit=2)
    assert result["data"]["count"] == 2
    assert len(result["data"]["results"]) == 2


# --- tag/technique arg parsing ------------------------------------------------


def test_parse_list_arg_comma_separated():
    assert gks.guardian_kbsearch_parse_list_arg("a, b,c") == ["a", "b", "c"]


def test_parse_list_arg_json_array_string():
    assert gks.guardian_kbsearch_parse_list_arg('["a", "b"]') == ["a", "b"]


def test_parse_list_arg_empty():
    assert gks.guardian_kbsearch_parse_list_arg(None) == []
    assert gks.guardian_kbsearch_parse_list_arg("") == []


def test_parse_list_arg_already_a_list():
    assert gks.guardian_kbsearch_parse_list_arg(["a", " b "]) == ["a", "b"]


# --- result shape: title + technique + snippet, never the whole body ---------


def test_result_never_includes_full_body(monkeypatch):
    _install_kb(monkeypatch)
    result = gks.guardian_kbsearch(query="rdp")
    for r in result["data"]["results"]:
        assert "body" not in r
        assert set(r.keys()) == {"id", "technique", "category", "title", "tags", "snippet", "score"}


# --- main() / CommandResults integration --------------------------------------


def test_main_raises_on_missing_query(monkeypatch):
    _install_kb(monkeypatch)
    monkeypatch.setattr(gks.demisto, "args", lambda: {})
    with pytest.raises(SystemExit):
        gks.main()


def test_main_reports_no_hits_gracefully(monkeypatch):
    _install_kb(monkeypatch)
    monkeypatch.setattr(gks.demisto, "args", lambda: {"query": "zzz_nonsense_zzz"})
    import CommonServerPython as csp

    csp.RESULTS.clear()
    gks.main()
    assert len(csp.RESULTS) == 1
    cr = csp.RESULTS[0]
    assert cr.outputs_prefix == "Guardian.KB"
    assert cr.outputs["count"] == 0
    assert "No KB hits" in cr.readable_output


def test_main_returns_ranked_results(monkeypatch):
    _install_kb(monkeypatch)
    monkeypatch.setattr(gks.demisto, "args", lambda: {"query": "lateral movement rdp"})
    import CommonServerPython as csp

    csp.RESULTS.clear()
    gks.main()
    cr = csp.RESULTS[0]
    assert cr.outputs["count"] == 2
    assert {r["id"] for r in cr.outputs["results"]} == {"T1021", "pb-lateral-movement"}
    assert "Remote Services" in cr.readable_output
