import json

import pytest

import GuardianCommon as gc


# --- guardian_envelope ------------------------------------------------------


def test_guardian_envelope_success_defaults():
    result = gc.guardian_envelope(True, data={"a": 1})
    assert result == {
        "ok": True,
        "data": {"a": 1},
        "error": None,
        "retryable": False,
        "is_auth_error": False,
    }


def test_guardian_envelope_failure_flags_coerced_to_bool():
    result = gc.guardian_envelope(0, error="nope", retryable=1, is_auth_error="yes")
    assert result["ok"] is False
    assert result["retryable"] is True
    assert result["is_auth_error"] is True
    assert result["error"] == "nope"


# --- guardian_execute --------------------------------------------------------


def test_guardian_execute_ok_when_no_error_entries(monkeypatch):
    entries = [{"Type": 1, "Contents": {"result": "fine"}}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {"x": 1})

    assert result["ok"] is True
    assert result["data"] == entries
    assert result["error"] is None


def test_guardian_execute_classifies_type_4_entry_as_failure(monkeypatch):
    """The core no-silent-success rule: any Type==4 (entryTypes['error'])
    entry must flip ok to False, even if other entries in the same response
    look fine."""
    entries = [
        {"Type": 1, "Contents": "some progress note"},
        {"Type": 4, "Contents": "Command failed: host unreachable"},
    ]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert "host unreachable" in result["error"]
    assert result["data"] == entries


def test_guardian_execute_classifies_auth_error(monkeypatch):
    entries = [{"Type": 4, "Contents": "Error: Unauthorized (401) - invalid api key"}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert result["is_auth_error"] is True
    assert result["retryable"] is False


def test_guardian_execute_classifies_retryable_error(monkeypatch):
    entries = [{"Type": 4, "Contents": "Error 429: Too Many Requests, rate limit exceeded"}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert result["retryable"] is True
    assert result["is_auth_error"] is False


def test_guardian_execute_auth_error_takes_precedence_over_retryable(monkeypatch):
    """guardian_envelope's contract: retryable is never True alongside
    is_auth_error. A multi-entry executeCommand response can independently
    OR in an auth-flavored entry (401) and a retryable-flavored entry (503)
    -- guardian_execute must enforce auth precedence after aggregating
    across entries, not just leave both flags True."""
    entries = [
        {"Type": 4, "Contents": "Error: Unauthorized (401) - invalid api key"},
        {"Type": 4, "Contents": "Error 503: Service Unavailable"},
    ]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert result["is_auth_error"] is True
    assert result["retryable"] is False


_EXAMPLE_FAILURE_TEXT = (
    "Example module is not enabled.\nFull error message: [/api/example/v1/thing/] failed client execute - "
    "error: request to [/api/example/v1/thing/] returned non-whitelisted status [500] body: {}"
)


def test_guardian_execute_classifies_a_lone_warning_entry_with_platform_failure_text_as_failure(monkeypatch):
    """The confirmed shape: a command reports a failed platform call through `return_warning` -- ONE Type 11
    entry, format text, the failure text as Contents."""
    entries = [{"Type": 11, "ContentsFormat": "text", "Contents": _EXAMPLE_FAILURE_TEXT}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is False
    assert "non-whitelisted status [500]" in result["error"]
    assert result["data"] == entries


def test_guardian_execute_warning_without_failure_wording_is_ok_and_passed_through(monkeypatch):
    """Some integrations warn on an empty result. A warning is not an error by Type alone."""
    entries = [{"Type": 11, "ContentsFormat": "text", "Contents": "Example: no results found for this query."}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"] == entries


@pytest.mark.parametrize("contents", [None, "", {"note": "x"}])
def test_guardian_execute_warning_with_empty_or_structured_contents_is_ok(monkeypatch, contents):
    entries = [{"Type": 11, "Contents": contents}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    assert gc.guardian_execute("example-command", {})["ok"] is True


def test_guardian_execute_warning_next_to_data_stays_ok(monkeypatch):
    entries = [
        {"Type": 11, "Contents": "Example: results were truncated to 50 rows."},
        {"Type": 1, "Contents": [{"id": 1}]},
    ]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is True
    assert result["data"] == entries


def test_guardian_execute_text_note_quoting_the_platform_failure_wording_is_not_a_failure(monkeypatch):
    """Only a warning entry (Type 11) reports a failed platform call; a Type 1 note that quotes the same words
    (a case note, a memory value, a war-room entry read back) is data."""
    entries = [{"Type": 1, "ContentsFormat": "text", "Contents": _EXAMPLE_FAILURE_TEXT}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"] == entries


def test_guardian_execute_failure_phrase_inside_a_warning_next_to_data_is_not_a_failure(monkeypatch):
    entries = [{"Type": 11, "Contents": _EXAMPLE_FAILURE_TEXT}, {"Type": 1, "Contents": [{"id": 1}]}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    assert gc.guardian_execute("example-command", {})["ok"] is True


def test_guardian_execute_several_warnings_with_the_failure_wording_and_no_data_is_a_failure(monkeypatch):
    entries = [{"Type": 11, "Contents": "Example: first notice."}, {"Type": 11, "Contents": _EXAMPLE_FAILURE_TEXT}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is False
    assert "non-whitelisted status [500]" in result["error"]


def test_guardian_execute_warning_whose_text_is_a_json_document_is_data(monkeypatch):
    document = json.dumps([{"detail": _EXAMPLE_FAILURE_TEXT}])
    entries = [{"Type": 11, "ContentsFormat": "text", "Contents": document}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    assert gc.guardian_execute("example-command", {})["ok"] is True


@pytest.mark.parametrize("command", ["getList", "getEntries", "getIncidents", "getContext", "GuardianAuditWrite", "GuardianMemory"])
def test_guardian_execute_stored_data_readers_never_read_the_failure_wording(monkeypatch, command):
    """`getList` returns a stored List as a JSON STRING; once a row quotes a failed lookup, reading it must still work.
    The internal readers are exempt even in the otherwise-confirmed failure shape (one Type 11 text entry)."""
    for entries in (
        [{"Type": 1, "ContentsFormat": "json", "Contents": json.dumps([{"detail": _EXAMPLE_FAILURE_TEXT}])}],
        [{"Type": 1, "ContentsFormat": "text", "Contents": _EXAMPLE_FAILURE_TEXT}],
        [{"Type": 11, "ContentsFormat": "text", "Contents": _EXAMPLE_FAILURE_TEXT}],
    ):
        monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args, entries=entries: entries)

        result = gc.guardian_execute(command, {"listName": "guardian_audit"})

        assert result["ok"] is True, entries
        assert result["data"] == entries


def test_guardian_execute_a_type_4_error_from_a_stored_data_reader_is_still_an_error(monkeypatch):
    entries = [{"Type": 4, "Contents": "list not found"}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    assert gc.guardian_execute("getList", {"listName": "guardian_audit"})["ok"] is False


def test_guardian_execute_failure_text_is_classified_for_retry(monkeypatch):
    entries = [{"Type": 11, "Contents": _EXAMPLE_FAILURE_TEXT + " timed out"}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is False
    assert result["retryable"] is True


def test_guardian_execute_structured_result_that_quotes_the_failure_wording_stays_ok(monkeypatch):
    """Guardian's own scripts answer with structured Contents (case notes, memory, audit rows and the evidence
    packet can quote a failed lookup verbatim). Only a STRING Contents is read for the failure wording."""
    quote = _EXAMPLE_FAILURE_TEXT
    for contents in ({"note": quote}, [{"text": quote}], {"results": [{"value": "lookup failed: " + quote}]}):
        monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args, c=contents: [{"Type": 1, "Contents": c}])
        result = gc.guardian_execute("GuardianCaseNote", {})
        assert result["ok"] is True and result["error"] is None


@pytest.mark.parametrize(
    "contents",
    [
        {"summary": "0 errors", "error": None, "rows": [{"message": "Full error message: none, all good"}]},
        [{"status": "failed", "error_count": 0}],
        "Completed with no error. 3 rows returned.",
        "The user wrote: request failed earlier, now fine",
    ],
)
def test_guardian_execute_normal_result_mentioning_error_stays_ok(monkeypatch, contents):
    """A clean result whose data merely mentions an error word must not become a failure."""
    entries = [{"Type": 1, "Contents": contents}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("example-command", {})

    assert result["ok"] is True
    assert result["error"] is None


def test_guardian_execute_never_raises_on_command_exception(monkeypatch):
    def raise_it(command, args):
        raise RuntimeError("boom")

    monkeypatch.setattr(gc.demisto, "executeCommand", raise_it)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert result["retryable"] is True
    assert "boom" in result["error"]


def test_guardian_execute_passes_using_through_as_arg(monkeypatch):
    captured = {}

    def fake_execute(command, args):
        captured["command"] = command
        captured["args"] = args
        return [{"Type": 1, "Contents": "ok"}]

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    gc.guardian_execute("ip", {"ip": "1.2.3.4"}, using="MyInstance")

    assert captured["command"] == "ip"
    assert captured["args"] == {"ip": "1.2.3.4", "using": "MyInstance"}


def test_guardian_execute_empty_entries_is_ok(monkeypatch):
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: [])

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is True
    assert result["data"] == []


def test_guardian_execute_redacts_dict_contents_sensitive_key_before_flattening(monkeypatch):
    """A failing entry's structured (dict) Contents must be redacted BEFORE
    it's flattened to the joined error string -- mirrors what the success
    path (guardian_redact on structured Contents, in GuardianToolBridge)
    already does, so a dict-shaped error payload can't leak a
    sensitive-keyed value (e.g. an upstream integration echoing back the
    api_key it rejected) into guardian_execute's own flattened `error`
    string. This is layer 1 of the two-layer error-path redaction defense
    (see guardian_scrub_secrets below for layer 2, the free-form-string
    case this structural masking cannot reach)."""
    entries = [{"Type": 4, "Contents": {"message": "unauthorized", "api_key": "sk" "-live-should-not-leak"}}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert "sk" "-live-should-not-leak" not in result["error"]
    assert "***" in result["error"]


def test_guardian_execute_dict_contents_non_sensitive_keys_pass_through(monkeypatch):
    """Confirms the redaction above is targeted, not a wholesale wipe of a
    dict-shaped error -- non-secret keys/values must still reach the
    flattened message so the error remains informative."""
    entries = [{"Type": 4, "Contents": {"message": "host unreachable", "code": 503}}]
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda command, args: entries)

    result = gc.guardian_execute("some-command", {})

    assert result["ok"] is False
    assert "host unreachable" in result["error"]
    assert "503" in result["error"]


# --- guardian_scrub_secrets ---------------------------------------------------


def test_scrub_secrets_masks_provider_key_prefix():
    scrubbed = gc.guardian_scrub_secrets("invalid api_key 'sk-SECRET123ABCDEFGHIJK'")
    assert "sk-SECRET123ABCDEFGHIJK" not in scrubbed
    assert "***" in scrubbed


def test_scrub_secrets_masks_key_value_pair():
    scrubbed = gc.guardian_scrub_secrets("auth failed: password=hunter2 rejected")
    assert "hunter2" not in scrubbed
    assert "password=***" in scrubbed


def test_scrub_secrets_masks_bearer_token():
    scrubbed = gc.guardian_scrub_secrets("Authorization: Bearer abcDEF123456789xyz")
    assert "abcDEF123456789xyz" not in scrubbed
    assert "Bearer ***" in scrubbed


def test_scrub_secrets_masks_connection_string_password_but_keeps_username():
    scrubbed = gc.guardian_scrub_secrets("connect failed: postgres://dbuser:hunter2@db.internal:5432/prod")
    assert "hunter2" not in scrubbed
    assert "dbuser" in scrubbed  # username is not itself a secret
    assert "***" in scrubbed


def test_scrub_secrets_masks_long_base64_hex_run_catchall():
    scrubbed = gc.guardian_scrub_secrets("token blob: aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl")
    assert "aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl" not in scrubbed
    assert "***" in scrubbed


def test_scrub_secrets_leaves_benign_text_unchanged():
    assert gc.guardian_scrub_secrets("host unreachable") == "host unreachable"


def test_scrub_secrets_handles_none_and_empty():
    assert gc.guardian_scrub_secrets(None) is None
    assert gc.guardian_scrub_secrets("") == ""


def test_scrub_secrets_combined_realistic_error_message():
    """The realistic multi-secret shape this helper exists for: a single
    error string with a provider-style API key, a DB connection-string
    password, and a key=value pair, all in one sentence."""
    text = (
        "401 Unauthorized: invalid api_key 'sk-SECRET123ABCDEFGHIJK'; connection string "
        "postgres://dbuser:hunter2@db.internal:5432/prod failed; password=hunter2 rejected"
    )
    scrubbed = gc.guardian_scrub_secrets(text)
    assert "sk-SECRET123ABCDEFGHIJK" not in scrubbed
    assert "hunter2" not in scrubbed
    assert "dbuser" in scrubbed
    assert "***" in scrubbed


# --- guardian_scrub_secrets(keep_identifiers=True) ----------------------------

_KEEP_IDENTIFIERS = [
    "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b",  # UUID, lowercase
    "3F2B8C1E-9A4D-4E6F-8B7A-1C2D3E4F5A6B",  # UUID, uppercase
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # sha1 (40 hex)
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # sha256 / asset id (64 hex)
    "STATUS_250_RESOLVED_FIXED",
    "log-demo-app-dev-operation-weu-01",
    "aks-userpool-12345678-vmss",
    "aks-nodepool1-12345678-vmss",
    "aks-nodepool1-12345678-vmss_0",  # a scale-set instance
    "aks-systempool-87654321-vmss",
    "rt-app-demo-qa-kubemail-weu-66",
]


@pytest.mark.parametrize("identifier", _KEEP_IDENTIFIERS)
def test_scrub_secrets_keep_identifiers_preserves_plain_identifiers(identifier):
    text = "see {} for details".format(identifier)
    assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text
    # Default behaviour is unchanged: the strict catch-all masks every one of these.
    assert gc.guardian_scrub_secrets(text) == "see *** for details"


def test_scrub_secrets_keep_identifiers_short_name_with_digit_part_unchanged():
    """A short name is below the catch-all's 20-char floor: kept in both modes, as before."""
    text = "host vm-web01-prod up"
    assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text
    assert gc.guardian_scrub_secrets(text) == text


_STILL_MASKED = [
    "sk-SECRET123ABCDEFGHIJK",
    "Bearer abcDEF123456789xyzABCDEF",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "github" "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
    "d41d8cd98f00b204e9800998ecf8427e",  # unlabelled 32 hex stays masked
    "Zx8kQ2-mP9vL_Tq3Wn7Rb4Yc6Hd1Fj0s",  # random base64url with incidental - and _
    "password=hunter2supersecretvalue",
    "a1b2-c3d4-e5f6-g7h8-i9j0",  # product-key / recovery-code shape (all parts <= 4 chars)
    "1234567890-1234567890-1234567890",  # digit-only multi-part run
    "abcdefghijklmnopqrstuvwxyz0123456789abcd",  # 40 lowercase alphanumerics that are not hex
    "da39a3ee5e6b4b0d-3255bfef95601890-afd80709",  # 40 hex split into hyphenated runs
    "Zx8kQ2mP9vL3Tq3Wn7Rb4Yc6Hd1Fj0s7",  # 33 mixed-case base64-like run
    "aks-Zx8kQ2mP9vL3-12345678-vmss",  # mixed case with digits inside a name-shaped token
    "xo" "xb-123456789012-abcdefghijklmnop",
    "sk-test0000000000000000fake",
    "gh" "p_fakefakefake1_fakefakefake2_fakefake3",
    "AK" "IA-FAKE-FAKEFAKEFAKE-1234",
    "unsaid-reload7-handsfree",  # generated passphrase with a digit
    "correct-horse7-battery9-staple",
]


@pytest.mark.parametrize("secret", _STILL_MASKED)
def test_scrub_secrets_keep_identifiers_still_masks_secrets(secret):
    scrubbed = gc.guardian_scrub_secrets("leaked: {} end".format(secret), keep_identifiers=True)
    value = secret.split("=", 1)[-1].split(" ", 1)[-1]
    assert value not in scrubbed
    assert "***" in scrubbed
    # Same outcome as the strict default for every one of these.
    assert scrubbed == gc.guardian_scrub_secrets("leaked: {} end".format(secret))


def test_scrub_secrets_keep_identifiers_masks_every_jwt_segment():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    scrubbed = gc.guardian_scrub_secrets("jwt {}.{}.{}".format(header, payload, signature), keep_identifiers=True)
    for segment in (header, payload, signature):
        assert segment not in scrubbed


def test_scrub_secrets_keep_identifiers_keeps_ids_but_masks_secret_in_same_text():
    text = "asset {} rule {} key sk-SECRET123ABCDEFGHIJK md5 d41d8cd98f00b204e9800998ecf8427e".format(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b"
    )
    scrubbed = gc.guardian_scrub_secrets(text, keep_identifiers=True)
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in scrubbed
    assert "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b" in scrubbed
    assert "sk-SECRET123ABCDEFGHIJK" not in scrubbed
    assert "d41d8cd98f00b204e9800998ecf8427e" not in scrubbed


_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_AZURE_RT_ID = "/subscriptions/{}/resourcegroups/rg-example/providers/microsoft.network/routetables/rt-example".format(
    _ZERO_GUID
)


def test_scrub_secrets_keep_identifiers_keeps_azure_resource_id_and_resource_arg():
    text = (
        "Route table {rid} was changed. Next: !GuardianXQL template=resource_change_history resource={rid}".format(
            rid=_AZURE_RT_ID
        )
    )
    assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text


def test_scrub_secrets_keep_identifiers_keeps_azure_id_with_trailing_sentence_punctuation():
    text = "changed {}.".format(_AZURE_RT_ID)
    assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text


@pytest.mark.parametrize(
    "path",
    [
        "arn:aws:ec2:us-east-1:000000000000:instance/i-0123456789abcdef0",
        "arn:aws:iam::000000000000:role/role-example",
        "arn:aws:secretsmanager:us-east-1:000000000000:secret:secret-example-AbCdEf",
        "arn:aws-us-gov:s3:::bucket-example/prefix-example/object-example.txt",
        "projects/project-example-123/zones/us-central1-a/instances/vm-example-1",
        "//compute.googleapis.com/projects/project-example-123/global/networks/net-example",
        "projects/123456789012/locations/us-central1/keyRings/ring-example",
    ],
)
def test_scrub_secrets_keep_identifiers_keeps_aws_arn_and_gcp_paths(path):
    for text in ("asset {} was changed.".format(path), "resource={} end".format(path)):
        assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text


def test_scrub_secrets_keep_identifiers_keeps_resource_id_but_masks_secret_in_same_text():
    text = "route table {} rotated, key sk-SECRET123ABCDEFGHIJK, token=hunter2supersecret, blob aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl".format(
        _AZURE_RT_ID
    )
    scrubbed = gc.guardian_scrub_secrets(text, keep_identifiers=True)
    assert _AZURE_RT_ID in scrubbed
    assert "sk-SECRET123ABCDEFGHIJK" not in scrubbed
    assert "hunter2supersecret" not in scrubbed
    assert "aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl" not in scrubbed
    assert scrubbed.count("***") == 3


def test_scrub_secrets_keep_identifiers_masks_secret_glued_after_resource_id():
    scrubbed = gc.guardian_scrub_secrets(
        "{}?sig=aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl and Bearer abcDEF123456789xyzABCDEF".format(_AZURE_RT_ID),
        keep_identifiers=True,
    )
    assert _AZURE_RT_ID in scrubbed
    assert "aGVsbG8gd29ybGQgc2VjcmV0IHZhbHVl" not in scrubbed
    assert "abcDEF123456789xyzABCDEF" not in scrubbed


_GUID0 = "00000000-0000-0000-0000-000000000000"


@pytest.mark.parametrize(
    "prefix, secret",
    [
        ("/subscriptions/" + _GUID0 + "/resourceGroups/rg-example/providers/X/y/", "sk-AbCdEf0123456789xyz"),
        ("arn:aws:s3:::bucket/", "AK" "IAIOSFODNN7EXAMPLE1234"),
        ("/subscriptions/" + _GUID0 + "/resourceGroups/rg-example/providers/Microsoft.Web/sites/app/", "wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY"),
    ],
)
def test_scrub_secrets_keep_identifiers_masks_a_secret_segment_inside_a_resource_id(prefix, secret):
    """A resource id is kept whole except for a segment that is itself a provider key or a long token."""
    for text in ("asset {}{} was changed.".format(prefix, secret), "resource={}{} end".format(prefix, secret)):
        scrubbed = gc.guardian_scrub_secrets(text, keep_identifiers=True)
        assert secret not in scrubbed
        assert prefix + "***" in scrubbed


@pytest.mark.parametrize(
    "resource_id",
    [
        "/subscriptions/" + _GUID0 + "/resourceGroups/rg-example/providers/Microsoft.Storage/storageAccounts/stexampleprod0123456",
        "/subscriptions/" + _GUID0 + "/resourceGroups/rg-example/providers/Microsoft.Compute/disks/vm-example_OsDisk_1_0123456789abcdef0123456789abcdef",
        "/subscriptions/" + _GUID0 + "/resourceGroups/RG-Example/providers/Microsoft.ContainerRegistry/registries/acrexample0123456789abcd",
        "arn:aws:ecs:us-east-1:000000000000:task/cluster-example/0123456789abcdef0123456789abcdef",
        "arn:aws:ec2:us-east-1:000000000000:instance/i-0123456789abcdef0",
    ],
)
def test_scrub_secrets_keep_identifiers_keeps_resource_names_with_digits_and_hex(resource_id):
    """Common real names -- a storage account, a managed OS disk, an ECS task id -- are single lowercase runs with digits."""
    for text in ("asset {} was changed.".format(resource_id), "resource={} end".format(resource_id)):
        assert gc.guardian_scrub_secrets(text, keep_identifiers=True) == text
        assert gc.guardian_scrub_secrets(text.lower(), keep_identifiers=True) == text.lower()


def test_scrub_secrets_keep_identifiers_keeps_guid_group_and_resource_segments_in_a_resource_id():
    rid = "/subscriptions/{}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-example-pool-01/virtualMachines/0".format(_GUID0)
    assert gc.guardian_scrub_secrets("asset " + rid + " ok", keep_identifiers=True) == "asset " + rid + " ok"


def test_scrub_secrets_resource_paths_are_still_masked_by_default():
    """keep_identifiers=False is unchanged: the strict catch-all still masks the path."""
    scrubbed = gc.guardian_scrub_secrets("changed {} ok".format(_AZURE_RT_ID))
    assert "rg-example" not in scrubbed
    assert "***" in scrubbed


def test_scrub_secrets_keep_identifiers_does_not_treat_arbitrary_slash_run_as_resource_id():
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in gc.guardian_scrub_secrets(
        "resource=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", keep_identifiers=True
    )


def test_scrub_secrets_default_call_masks_uuid_and_64_hex():
    text = "rule 3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b asset 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert gc.guardian_scrub_secrets(text) == "rule *** asset ***"


# --- guardian_project_incident ----------------------------------------------


def test_guardian_project_incident_maps_nine_fields():
    inc = {
        "id": "42",
        "name": "Phishing report",
        "type": "Phishing",
        "severity": 3,
        "status": 1,
        "owner": "analyst1",
        "created": "2026-07-01T00:00:00Z",
        "modified": "2026-07-02T00:00:00Z",
        "dueDate": "2026-07-10T00:00:00Z",
        "extra_field_not_projected": "should be dropped",
    }

    projected = gc.guardian_project_incident(inc)

    assert projected == {
        "id": "42",
        "name": "Phishing report",
        "type": "Phishing",
        "severity": 3,
        "status": 1,
        "owner": "analyst1",
        "created": "2026-07-01T00:00:00Z",
        "modified": "2026-07-02T00:00:00Z",
        "due_date": "2026-07-10T00:00:00Z",
    }
    assert "extra_field_not_projected" not in projected


def test_guardian_project_incident_normalizes_zero_value_due_date():
    inc = {"id": "1", "dueDate": "0001-01-01T00:00:00Z"}

    projected = gc.guardian_project_incident(inc)

    assert projected["due_date"] is None


def test_guardian_project_incident_handles_none():
    projected = gc.guardian_project_incident(None)
    assert projected["id"] is None
    assert projected["due_date"] is None


# --- guardian_dbot_label -----------------------------------------------------


def test_guardian_dbot_label_known_scores():
    assert gc.guardian_dbot_label(0) == "Unknown"
    assert gc.guardian_dbot_label(1) == "Good"
    assert gc.guardian_dbot_label(2) == "Suspicious"
    assert gc.guardian_dbot_label(3) == "Bad"


def test_guardian_dbot_label_unknown_or_unparseable_score():
    assert gc.guardian_dbot_label(4) == "Unknown"
    assert gc.guardian_dbot_label(-1) == "Unknown"
    assert gc.guardian_dbot_label(None) == "Unknown"
    assert gc.guardian_dbot_label("not-a-number") == "Unknown"


def test_guardian_dbot_label_accepts_numeric_string():
    assert gc.guardian_dbot_label("2") == "Suspicious"


# --- guardian_normalize_due --------------------------------------------------


def test_guardian_normalize_due_zero_value_becomes_none():
    assert gc.guardian_normalize_due("0001-01-01T00:00:00Z") is None


def test_guardian_normalize_due_passes_real_date_through():
    assert gc.guardian_normalize_due("2026-07-04T12:00:00Z") == "2026-07-04T12:00:00Z"


def test_guardian_normalize_due_passes_none_through():
    assert gc.guardian_normalize_due(None) is None


# --- guardian_normalize_techniques --------------------------------------------


def test_guardian_normalize_techniques_list_input():
    assert gc.guardian_normalize_techniques(["T1566", "T1078"]) == ["T1078", "T1566"]


def test_guardian_normalize_techniques_comma_string_input():
    assert gc.guardian_normalize_techniques("T1566, T1078") == ["T1078", "T1566"]


def test_guardian_normalize_techniques_none_returns_empty_list():
    assert gc.guardian_normalize_techniques(None) == []


def test_guardian_normalize_techniques_drops_junk():
    assert gc.guardian_normalize_techniques(["nope", "T9999999", "", "T15", None]) == []


def test_guardian_normalize_techniques_collapses_subtechnique_to_parent():
    assert gc.guardian_normalize_techniques(["T1566.001"]) == ["T1566"]


def test_guardian_normalize_techniques_sorts_and_dedupes():
    assert gc.guardian_normalize_techniques(["t1078.001", "T1078", " t1566 "]) == ["T1078", "T1566"]


# --- guardian_estimate_tokens -------------------------------------------------


def test_guardian_estimate_tokens_empty_string_bias():
    assert gc.guardian_estimate_tokens("") == 5


def test_guardian_estimate_tokens_none_treated_as_empty():
    assert gc.guardian_estimate_tokens(None) == 5


def test_guardian_estimate_tokens_scales_with_length():
    text = "a" * 400
    assert gc.guardian_estimate_tokens(text) == 400 // 4 + 5


def test_guardian_estimate_tokens_serializes_non_strings():
    estimate = gc.guardian_estimate_tokens({"tool": "ip", "args": {"ip": "1.2.3.4"}})
    assert isinstance(estimate, int)
    assert estimate > 5


# --- guardian_redact ----------------------------------------------------------


def test_guardian_redact_masks_known_secret_keys_case_insensitively():
    obj = {"Password": "hunter2", "API_KEY": "abc123", "note": "hello"}

    redacted = gc.guardian_redact(obj)

    assert redacted["Password"] == "***"
    assert redacted["API_KEY"] == "***"
    assert redacted["note"] == "hello"


def test_guardian_redact_masks_and_caps_long_value_under_secret_key_but_leaves_non_secret_full_length():
    """The 512-char cap applies ONLY to values redacted under a sensitive
    key (where it's moot -- the mask is "***", already far under the cap).
    A long value under a NON-secret key must pass through in full: capping
    it here would silently truncate legitimate tool output/evidence before
    the model ever sees it. Generic size-capping is a separate 16KB
    mechanism that lives in GuardianToolBridge, not in guardian_redact."""
    obj = {"password": "x" * 1000, "note": "y" * 1000}

    redacted = gc.guardian_redact(obj)

    assert redacted["password"] == "***"
    assert redacted["note"] == "y" * 1000
    assert len(redacted["note"]) == 1000


def test_guardian_redact_recurses_into_nested_dicts_and_lists():
    obj = {
        "top": "fine",
        "nested": {"password": "hunter2", "deeper": {"token": "abc", "ok": "value"}},
        "list_of_dicts": [{"secret": "shh"}, {"note": "y" * 600}],
    }

    redacted = gc.guardian_redact(obj)

    assert redacted["nested"]["password"] == "***"
    assert redacted["nested"]["deeper"]["token"] == "***"
    assert redacted["nested"]["deeper"]["ok"] == "value"
    assert redacted["list_of_dicts"][0]["secret"] == "***"
    assert redacted["list_of_dicts"][1]["note"] == "y" * 600  # non-secret: not capped


def test_guardian_redact_leaf_key_scope_limitation_is_known_behavior():
    """Documents a known, intentional scope limitation of the leaf-key
    design (not a bug): masking only checks a string value's OWN dict key.
    A sensitive-looking PARENT key whose value is a dict is recursed into
    rather than masked wholesale, so a nested leaf whose own key does not
    match (e.g. "value") is never masked, even though the parent key
    ("credentials") does match. See `_guardian_redact_value`'s docstring."""
    obj = {"credentials": {"value": "secret"}}

    redacted = gc.guardian_redact(obj)

    assert redacted["credentials"]["value"] == "secret"  # NOT masked -- documented limitation


def test_guardian_redact_extra_keys_param():
    obj = {"internal_codename": "project-x", "note": "keep"}

    redacted = gc.guardian_redact(obj, extra_keys=["codename"])

    assert redacted["internal_codename"] == "***"
    assert redacted["note"] == "keep"


def test_guardian_redact_leaves_non_string_scalars_untouched():
    obj = {"password": None, "count": 12345, "enabled": True}

    redacted = gc.guardian_redact(obj)

    # Non-string values are never masked (nothing to mask), even under a
    # sensitive key name, and non-string scalars pass through untouched.
    assert redacted["password"] is None
    assert redacted["count"] == 12345
    assert redacted["enabled"] is True


def test_guardian_redact_does_not_mutate_input():
    obj = {"password": "hunter2"}

    gc.guardian_redact(obj)

    assert obj["password"] == "hunter2"


def test_guardian_redact_bare_key_field_name_is_not_masked():
    """FIX A (cosmetic-fixes batch): a field literally named ``key`` (e.g.
    GuardianMemory's own memory-row lookup key) must pass through UNMASKED
    -- the bare substring "key" over-matched every such field, hiding
    legitimate, non-secret data from the model/analyst. Compound
    secret-bearing "*key" shapes (api_key, private_key, access_key, ...)
    must still mask -- see the sibling test below."""
    obj = {"key": "tech_stack:siem", "Key": "another-lookup-key", "note": "fine"}

    redacted = gc.guardian_redact(obj)

    assert redacted["key"] == "tech_stack:siem"
    assert redacted["Key"] == "another-lookup-key"
    assert redacted["note"] == "fine"


def test_guardian_redact_still_masks_compound_key_secret_shapes():
    """The bare "key" exclusion (FIX A) must not weaken masking of the real
    secret-bearing compound shapes it was meant to catch."""
    obj = {
        "api_key": "sk" "-live-abc123",
        "apikey": "sk" "-live-def456",
        "api-key": "sk" "-live-ghi789",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "access_key": "AK" "IAABCDEF",
        "secret_key": "shh-secret",
        "token": "opaque-token-value",
        "password": "hunter2",
    }

    redacted = gc.guardian_redact(obj)

    for field in obj:
        assert redacted[field] == "***", "expected {} to still be masked".format(field)


def test_guardian_redact_masks_all_compound_key_shapes_but_not_bare_key():
    """FIX A security-review regression guard: removing bare "key" must NOT
    stop masking real compound `*_key` credential fields. A plain lookup
    `key` field passes through, but every enumerated secret-bearing `*_key`
    shape (including ones NOT containing api/secret/private -- signing,
    session, ssh, master, hmac, consumer, encryption, decryption, access)
    is still masked."""
    obj = {
        "key": "abc",  # plain lookup key -- must pass through
        "access_key": "AK" "IAxxx",
        "secret_key": "shh",
        "signing_key": "sig-xxx",
        "session_key": "sess-xxx",  # covered transitively by "session"
        "ssh_key": "ssh-rsa AAAA",
        "master_key": "mk-xxx",
        "hmac_key": "hm-xxx",
        "consumer_key": "ck-xxx",
        "encryption_key": "ek-xxx",
        "decryption_key": "dk-xxx",
        "jwt_key": "jwt-xxx",  # covered transitively by "jwt"
    }

    redacted = gc.guardian_redact(obj)

    assert redacted["key"] == "abc"  # bare lookup key NOT masked
    for field in obj:
        if field == "key":
            continue
        assert redacted[field] == "***", "expected compound field {} to be masked".format(field)


# --- guardian_ctx_read / guardian_ctx_write ----------------------------------


def test_guardian_ctx_read_reads_under_guardian_namespace(monkeypatch):
    monkeypatch.setattr(gc.demisto, "context", lambda: {"Guardian": {"state": {"tick_count": 3}}})

    assert gc.guardian_ctx_read("state.tick_count") == 3


def test_guardian_ctx_read_returns_default_when_missing(monkeypatch):
    monkeypatch.setattr(gc.demisto, "context", lambda: {})

    assert gc.guardian_ctx_read("state.tick_count", default="fallback") == "fallback"


def test_guardian_ctx_write_namespaces_under_guardian(monkeypatch):
    written = {}

    def fake_set_context(path, value):
        written[path] = value
        return {"status": True}

    monkeypatch.setattr(gc.demisto, "setContext", fake_set_context)

    result = gc.guardian_ctx_write("state.tick_count", 4)

    assert written == {"Guardian.state.tick_count": 4}
    assert result == {"status": True}


# --- guardian_set_incident_fields / _guardian_rest_post (Task D1) ------------
#
# The REST full-object-merge path verified live on XSOAR 6.14.0: read the
# incident via `demisto-api-post /incidents/search`, merge into CustomFields,
# `demisto-api-post /incident` with the FULL object. These stub
# `gc.demisto.executeCommand` directly (matching this file's existing
# `guardian_execute` test style) rather than a higher-level fixture, since
# `_guardian_rest_post` is the one thing translating `uri`/`body` args into
# the `{"response": ...}`-wrapped entries these tests construct by hand.


def _rest_entry(response_body):
    """One successful `demisto-api-post`/`core-api-post` entry wrapping
    `response_body` exactly as the real integration does (verified live,
    Task D1)."""
    return [{"Type": 1, "Contents": {"response": response_body}}]


def test_guardian_set_incident_fields_reads_merges_and_posts_full_object(monkeypatch):
    posted = {}

    def fake_execute(command, args):
        assert command == "demisto-api-post"
        body = json.loads(args["body"])
        if args["uri"] == "/incidents/search":
            assert body == {"filter": {"id": ["42"]}}
            return _rest_entry(
                {"total": 1, "data": [{"id": "42", "version": 3, "CustomFields": {"existing": "x"}}]}
            )
        if args["uri"] == "/incident":
            posted.update(body)
            return _rest_entry(body)
        raise AssertionError("unexpected uri {}".format(args["uri"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 0.5, "guardiantickcount": 3})

    assert result["ok"] is True
    assert posted["id"] == "42"
    # Untouched fields survive the merge -- this is a MERGE, not a replace.
    assert posted["CustomFields"]["existing"] == "x"
    # Number fields land as real numbers, never stringified.
    assert posted["CustomFields"]["guardiancostusd"] == 0.5
    assert isinstance(posted["CustomFields"]["guardiancostusd"], float)
    assert posted["CustomFields"]["guardiantickcount"] == 3
    assert isinstance(posted["CustomFields"]["guardiantickcount"], int)
    assert not isinstance(posted["CustomFields"]["guardiantickcount"], bool)


def test_guardian_set_incident_fields_incident_not_found(monkeypatch):
    monkeypatch.setattr(
        gc.demisto, "executeCommand", lambda c, a: _rest_entry({"total": 0, "data": []})
    )

    result = gc.guardian_set_incident_fields("999999", {"guardiancostusd": 1})

    assert result["ok"] is False
    assert "not found" in result["error"]


def test_guardian_set_incident_fields_missing_incident_id_never_calls_executecommand(monkeypatch):
    calls = []
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda c, a: calls.append((c, a)))

    result = gc.guardian_set_incident_fields(None, {"guardiancostusd": 1})

    assert result["ok"] is False
    assert calls == []


def test_guardian_set_incident_fields_empty_fields_is_a_no_op_success(monkeypatch):
    calls = []
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda c, a: calls.append((c, a)))

    result = gc.guardian_set_incident_fields("42", {})

    assert result["ok"] is True
    assert calls == []


def test_guardian_set_incident_fields_falls_back_to_core_api_post_when_unregistered(monkeypatch):
    """`demisto-api-post` raising (the shape a genuinely unregistered command
    takes -- see GuardianReasoningTick's own STEP-0 "was not found in
    module" docstring finding) must fall back to `core-api-post`, not just
    give up."""

    def fake_execute(command, args):
        if command == "demisto-api-post":
            raise RuntimeError("command  was not found in module [error 'Item not found (8)']")
        assert command == "core-api-post"
        if args["uri"] == "/incidents/search":
            return _rest_entry({"total": 1, "data": [{"id": "42", "version": 1, "CustomFields": {}}]})
        return _rest_entry(json.loads(args["body"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 1.0})

    assert result["ok"] is True


def test_guardian_rest_post_falls_back_when_server_says_unsupported_command(monkeypatch):
    """On the Cortex platform the Demisto REST API integration does not exist: the server answers
    "Unsupported Command : demisto-api-post , verify you have proper integration enabled to support it".
    That must fall back to `core-api-post` like the "not found in module" wording does."""
    seen = []

    def fake_execute(command, args):
        seen.append(command)
        if command == "demisto-api-post":
            return [{"Type": 4, "Contents": "Unsupported Command : demisto-api-post , verify you have proper integration enabled to support it (23)"}]
        return _rest_entry({"ok": True})

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc._guardian_rest_post("/settings/integration/search", {"size": 1})

    assert result["ok"] is True
    assert seen == ["demisto-api-post", "core-api-post"]


def test_guardian_set_incident_fields_retries_once_on_optimistic_lock_then_succeeds(monkeypatch):
    write_attempts = {"n": 0}

    def fake_execute(command, args):
        if args["uri"] == "/incidents/search":
            version = 1 if write_attempts["n"] == 0 else 2
            return _rest_entry({"total": 1, "data": [{"id": "42", "version": version, "CustomFields": {}}]})
        if args["uri"] == "/incident":
            write_attempts["n"] += 1
            if write_attempts["n"] == 1:
                return [
                    {
                        "Type": 4,
                        "Contents": "errOptimisticLock: DB Version '2' and Insert version '1' do not match",
                    }
                ]
            return _rest_entry(json.loads(args["body"]))
        raise AssertionError("unexpected uri {}".format(args["uri"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 1.0})

    assert result["ok"] is True
    assert write_attempts["n"] == 2  # exactly one retry, not a blind retry loop


def test_guardian_set_incident_fields_gives_up_after_second_optimistic_lock(monkeypatch):
    def fake_execute(command, args):
        if args["uri"] == "/incidents/search":
            return _rest_entry({"total": 1, "data": [{"id": "42", "version": 1, "CustomFields": {}}]})
        if args["uri"] == "/incident":
            return [{"Type": 4, "Contents": "errOptimisticLock: version mismatch"}]
        raise AssertionError("unexpected uri {}".format(args["uri"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 1.0})

    assert result["ok"] is False
    assert "optimisticlock" in result["error"].lower().replace(" ", "")


def test_guardian_set_incident_fields_non_lock_write_failure_does_not_retry(monkeypatch):
    read_calls = {"n": 0}

    def fake_execute(command, args):
        if args["uri"] == "/incidents/search":
            read_calls["n"] += 1
            return _rest_entry({"total": 1, "data": [{"id": "42", "version": 1, "CustomFields": {}}]})
        if args["uri"] == "/incident":
            return [{"Type": 4, "Contents": "field not associated with this incident type"}]
        raise AssertionError("unexpected uri {}".format(args["uri"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)

    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 1.0})

    assert result["ok"] is False
    assert read_calls["n"] == 1  # no retry spent on a non-lock failure
    assert "field not associated with this incident type" in result["error"]


def test_guardian_rest_post_rejects_non_dict_response_shape(monkeypatch):
    """A bad `uri` can silently fall through to the server's HTML SPA shell
    instead of erroring (observed live, Task D1) -- Type != 4 alone is not
    proof of a usable REST response; `_guardian_rest_post` must still flag
    it as a failure."""
    monkeypatch.setattr(
        gc.demisto, "executeCommand", lambda c, a: _rest_entry("<html>not json</html>")
    )

    result = gc._guardian_rest_post("/some/uri", {"a": 1})

    assert result["ok"] is False


# --- guardian_selfcheck / main -----------------------------------------------


def test_guardian_selfcheck_passes():
    assert gc.guardian_selfcheck() is True


def test_no_script_returns_outputs_under_the_bare_guardian_context_key():
    """XSOAR APPENDS a dict returned at an existing context key, so `outputs_prefix="Guardian"` turns the whole
    Guardian context (Guardian.Loop, ...) into a list [old, new] and every later Guardian.* read fails. It happened
    in GuardianSkillRead (live, 2026-10-01). Outputs must use a nested prefix (Guardian.X) or setContext."""
    import pathlib
    import re

    offenders = []
    for path in pathlib.Path(__file__).resolve().parents[1].glob("*/*.py"):
        if path.name.endswith("_test.py"):
            continue
        if re.search(r"outputs_prefix\s*=\s*[\"']Guardian[\"']", path.read_text()):
            offenders.append(path.name)
    assert offenders == []


# --- guardian_resolve_model_params / the model profile List -----------------

_PROFILE = {
    "active": "GuardianCohere:lab",
    "profiles": {"GuardianCohere:lab": {
        "model": "command-r:35b", "instance_name": "lab", "max_input_tokens": 28102,
        "probed_at": "2026-10-01T03:00:00Z", "window": 32768, "chars_per_token": 4.1,
        "tools": True, "structured_output": True}},
    "overrides": {},
}


def test_params_fall_back_to_settings_when_there_is_no_profile():
    p = gc.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 28258}, {})
    assert (p["tier"], p["tier_source"]) == ("medium", "guardian_settings")
    assert (p["max_input_tokens"], p["max_input_tokens_source"]) == (28258, "guardian_settings")
    # 16000 is under 60% of 28258 (16954), so the medium default is kept as is
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (16000, "tier")
    assert p["profile"] is None


def test_params_defaults_when_everything_is_missing_or_malformed():
    for settings, profile in ((None, None), ("x", []), ({}, {"active": 3, "profiles": "no"})):
        p = gc.guardian_resolve_model_params(settings, profile)
        assert (p["tier"], p["tier_source"]) == (
            "small", "default (model not in the catalogue; set model_tier in guardian_settings)")
        assert (p["max_input_tokens"], p["max_input_tokens_source"]) == (None, "none")
        assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (4000, "tier")


def test_the_measured_budget_beats_guardian_settings():
    p = gc.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 28258}, _PROFILE)
    assert (p["max_input_tokens"], p["max_input_tokens_source"]) == (28102, "measured")
    assert p["profile"]["model"] == "command-r:35b" and p["profile"]["key"] == "GuardianCohere:lab"
    assert p["tier"] == "medium"  # the tier is never taken from the measurement


def test_operator_overrides_beat_the_measured_values_and_the_tier_default():
    plist = dict(_PROFILE, overrides={"max_input_tokens": 12000, "max_tool_def_tokens": 9000, "model_tier": "large"})
    p = gc.guardian_resolve_model_params({"model_tier": "small"}, plist)
    assert (p["tier"], p["tier_source"]) == ("large", "override")
    assert (p["max_input_tokens"], p["max_input_tokens_source"]) == (12000, "override")
    # an override is taken as given, even above the share of the input budget
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (9000, "override")


def test_a_bad_override_is_ignored():
    plist = dict(_PROFILE, overrides={"max_input_tokens": -5, "max_tool_def_tokens": "lots", "model_tier": "huge"})
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, plist)
    assert (p["tier"], p["max_input_tokens"], p["max_input_tokens_source"]) == ("medium", 28102, "measured")


def test_an_explicit_settings_tool_budget_is_kept_but_still_capped_by_a_small_window():
    plist = {"active": "a", "profiles": {"a": {"max_input_tokens": 6000}}}
    p = gc.guardian_resolve_model_params({"model_tier": "large", "max_tool_def_tokens": 20000}, plist)
    assert p["max_tool_def_tokens"] == 3600
    assert p["max_tool_def_tokens_source"] == "guardian_settings, capped to 60% of max_input_tokens"
    roomy = {"active": "a", "profiles": {"a": {"max_input_tokens": 100000}}}
    p = gc.guardian_resolve_model_params({"model_tier": "large", "max_tool_def_tokens": 20000}, roomy)
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (20000, "guardian_settings")


def test_a_tier_budget_is_capped_when_the_measured_window_is_small():
    plist = {"active": "a", "profiles": {"a": {"max_input_tokens": 8000}}}
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, plist)
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (4800, "tier, capped to 60% of max_input_tokens")


def test_a_tier_budget_that_fits_is_left_alone():
    p = gc.guardian_resolve_model_params({"model_tier": "small"}, _PROFILE)
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (4000, "tier")


def test_params_survive_a_json_round_trip_and_validate():
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, _PROFILE)
    assert gc.guardian_model_params_valid(json.loads(json.dumps(p)))
    assert not gc.guardian_model_params_valid(dict(p, tier="huge"))
    assert not gc.guardian_model_params_valid(dict(p, max_tool_def_tokens="4000"))
    assert not gc.guardian_model_params_valid(dict(p, max_input_tokens=0))
    assert gc.guardian_model_params_valid(dict(p, max_input_tokens=None))


def test_describe_names_every_source():
    text = "\n".join(gc.guardian_model_params_describe(gc.guardian_resolve_model_params({"model_tier": "medium"}, _PROFILE)))
    assert "Model size: medium (guardian_settings)" in text
    assert "28102 (measured)" in text and "command-r:35b" in text
    none = "\n".join(gc.guardian_model_params_describe(gc.guardian_resolve_model_params({}, {})))
    assert "no ceiling" in none and "No measured profile yet" in none


def _stub_execute(monkeypatch, result):
    monkeypatch.setattr(gc, "guardian_execute", lambda command, args: result)


def test_load_profile_missing_list_is_not_an_error(monkeypatch):
    _stub_execute(monkeypatch, gc.guardian_envelope(False, error="Item not found (8)"))
    assert gc.guardian_load_model_profile_list() == {"ok": True, "data": {}, "error": None}


def test_load_profile_other_read_error_is_reported(monkeypatch):
    _stub_execute(monkeypatch, gc.guardian_envelope(False, error="connection reset"))
    r = gc.guardian_load_model_profile_list()
    assert r["ok"] is False and r["data"] == {}


def test_load_profile_parses_json_and_rejects_bad_shapes(monkeypatch):
    _stub_execute(monkeypatch, gc.guardian_envelope(True, data=[{"Contents": json.dumps(_PROFILE)}]))
    assert gc.guardian_load_model_profile_list()["data"]["active"] == "GuardianCohere:lab"
    _stub_execute(monkeypatch, gc.guardian_envelope(True, data=[{"Contents": "{not json"}]))
    assert gc.guardian_load_model_profile_list()["ok"] is False
    _stub_execute(monkeypatch, gc.guardian_envelope(True, data=[{"Contents": "[1]"}]))
    assert gc.guardian_load_model_profile_list()["ok"] is False
    _stub_execute(monkeypatch, gc.guardian_envelope(True, data=[{"Contents": None}]))
    assert gc.guardian_load_model_profile_list()["data"] == {}


def test_for_run_uses_the_snapshot_only_when_asked_and_valid(monkeypatch):
    snap = gc.guardian_resolve_model_params({"model_tier": "medium"}, _PROFILE)
    monkeypatch.setattr(gc, "guardian_ctx_read", lambda key, default=None: snap)
    _stub_execute(monkeypatch, gc.guardian_envelope(True, data=[{"Contents": "{}"}]))
    assert gc.guardian_model_params_for_run({"model_tier": "small"}, use_snapshot=True) == (snap, "snapshot")
    params, note = gc.guardian_model_params_for_run({"model_tier": "small"}, use_snapshot=False)
    assert params["tier"] == "small" and note == "resolved"
    monkeypatch.setattr(gc, "guardian_ctx_read", lambda key, default=None: {"tier": "huge"})
    params, note = gc.guardian_model_params_for_run({"model_tier": "small"}, use_snapshot=True)
    assert params["tier"] == "small" and note == "resolved"


def test_for_run_falls_back_to_settings_when_the_list_is_unreadable(monkeypatch):
    _stub_execute(monkeypatch, gc.guardian_envelope(False, error="boom"))
    params, note = gc.guardian_model_params_for_run({"model_tier": "medium", "max_input_tokens": 9000})
    assert params["max_input_tokens"] == 9000 and "unreadable" in note


def test_tool_calls_per_turn_defaults_to_one_for_small_and_medium_models_only():
    for tier in ("small", "medium"):
        p = gc.guardian_resolve_model_params({"model_tier": tier}, _PROFILE)
        assert (p["max_tool_calls_per_turn"], p["max_tool_calls_per_turn_source"]) == (1, "tier")
    p = gc.guardian_resolve_model_params({"model_tier": "large"}, _PROFILE)
    assert (p["max_tool_calls_per_turn"], p["max_tool_calls_per_turn_source"]) == (0, "none")


def test_tool_calls_per_turn_override_beats_guardian_settings():
    plist = dict(_PROFILE, overrides={"max_tool_calls_per_turn": 1})
    p = gc.guardian_resolve_model_params({"model_tier": "medium", "max_tool_calls_per_turn": 3}, plist)
    assert (p["max_tool_calls_per_turn"], p["max_tool_calls_per_turn_source"]) == (1, "override")
    p = gc.guardian_resolve_model_params({"model_tier": "medium", "max_tool_calls_per_turn": 3}, _PROFILE)
    assert (p["max_tool_calls_per_turn"], p["max_tool_calls_per_turn_source"]) == (3, "guardian_settings")


def test_a_bad_tool_calls_per_turn_is_ignored():
    for bad in (-1, 0, "two", True, None):
        p = gc.guardian_resolve_model_params({"model_tier": "large"}, dict(_PROFILE, overrides={"max_tool_calls_per_turn": bad}))
        assert p["max_tool_calls_per_turn"] == 0


# --- HTML helpers for the layout display scripts ---------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)> \"quoted\" 'single' & more"


def test_html_escape_neutralises_script_and_img_payloads():
    out = gc.guardian_html_escape(HOSTILE)
    assert "<script" not in out and "</script" not in out and "<img" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "&lt;img src=x onerror=alert(2)&gt;" in out
    assert "&amp; more" in out and "&quot;quoted&quot;" in out and "&#x27;single&#x27;" in out


def test_html_escape_truncates_before_escaping_so_entities_are_never_cut():
    out = gc.guardian_html_escape("<<<<<<<<<<", max_len=5)
    assert out == "&lt;&lt;&lt;&lt;…"
    assert gc.guardian_html_escape("short", max_len=50) == "short"


def test_html_escape_value_kinds():
    assert gc.guardian_html_escape(None) == ""
    assert gc.guardian_html_escape(7) == "7"
    assert gc.guardian_html_escape({"a": "<b>"}) == "{&quot;a&quot;: &quot;&lt;b&gt;&quot;}"
    assert isinstance(gc.guardian_html_escape("x"), gc.GuardianHtml)


def test_html_escape_newlines_become_spaces_or_br():
    assert gc.guardian_html_escape("a\nb\r\nc") == "a b c"
    assert gc.guardian_html_escape("a\nb\r\nc\rd", keep_newlines=True) == "a<br>b<br>c<br>d"
    assert "<br>" not in gc.guardian_html_escape("<br>", keep_newlines=True).replace("&lt;br&gt;", "")


def test_trusted_markup_is_not_escaped_twice_but_plain_strings_are_never_trusted():
    trusted = gc.guardian_html_trusted("<b>ok</b>")
    assert gc.guardian_html_escape(trusted) == "<b>ok</b>"
    assert gc.guardian_html_escape("<b>ok</b>") == "&lt;b&gt;ok&lt;/b&gt;"
    # concatenating onto a GuardianHtml yields a plain str again, which a helper then escapes
    assert gc.guardian_html_escape(trusted + "<i>") == "&lt;b&gt;ok&lt;/b&gt;&lt;i&gt;"


def test_html_join_keeps_trusted_parts_and_escapes_the_rest():
    out = gc.guardian_html_join([gc.guardian_html_bold("a"), "<x>", None, 3], sep=" | ")
    assert out == "<b>a</b> | &lt;x&gt; | 3"


def test_html_badges_use_a_solid_colour_with_white_text_and_escape_their_text():
    badge = gc.guardian_html_badge(HOSTILE, "danger")
    assert "background:#c0392b" in badge and "color:#fff" in badge
    assert "<script" not in badge and "<img" not in badge
    assert "background:#667085" in gc.guardian_html_badge("x", "no-such-kind")


def test_html_status_and_tier_badges_map_to_colours():
    assert "#1f8a5b" in gc.guardian_html_status_badge("ok") and ">OK<" in gc.guardian_html_status_badge("ok")
    assert "#b36b00" in gc.guardian_html_status_badge("pending_approval")
    assert ">PENDING APPROVAL<" in gc.guardian_html_status_badge("pending_approval")  # underscores read as spaces
    assert "#b36b00" in gc.guardian_html_status_badge("awaiting_approval")
    assert "#c0392b" in gc.guardian_html_status_badge("denied")
    assert "#667085" in gc.guardian_html_status_badge("something-new")
    assert ">UNKNOWN<" in gc.guardian_html_status_badge(None)
    assert "#2f6fb5" in gc.guardian_html_tier_badge("soft")
    assert "#b36b00" in gc.guardian_html_tier_badge("destructive")
    assert "#c0392b" in gc.guardian_html_tier_badge("credential")
    assert "<script" not in gc.guardian_html_status_badge(HOSTILE)
    assert "<script" not in gc.guardian_html_tier_badge(HOSTILE)


def test_html_table_structure_alignment_padding_and_escaping():
    table = gc.guardian_html_table(
        ["Tool", HOSTILE, "N"],
        [["a", gc.guardian_html_badge("ok", "ok"), 1], [HOSTILE, "short row"]],
        aligns=["left", "center", "right"],
        nowrap_cols=(0,),
    )
    assert table.startswith("<table") and table.endswith("</table>")
    assert table.count("<tr>") == 3 and table.count("<th ") == 3
    assert table.count("<td ") == 6  # the short row is padded to the header width
    assert "text-align:right" in table and "text-align:center" in table and "white-space:nowrap" in table
    assert '<span style="display:inline-block' in table  # the trusted badge kept its markup
    assert "<script" not in table and "<img" not in table


def test_html_table_with_no_rows_is_still_valid():
    table = gc.guardian_html_table(["A", "B"], [])
    assert "<tbody></tbody>" in table


def test_html_card_empty_heading_note_text_block_header_are_all_escaped():
    parts = [
        gc.guardian_html_card(HOSTILE, HOSTILE, kind="warn"),
        gc.guardian_html_empty(HOSTILE, hint=HOSTILE),
        gc.guardian_html_heading(HOSTILE),
        gc.guardian_html_note(HOSTILE),
        gc.guardian_html_text_block(HOSTILE),
        gc.guardian_html_code(HOSTILE),
        gc.guardian_html_muted(HOSTILE),
        gc.guardian_html_bold(HOSTILE),
        gc.guardian_html_header(HOSTILE, badges=[HOSTILE, gc.guardian_html_badge("ok", "ok")], facts=[(HOSTILE, HOSTILE)]),
    ]
    page = gc.guardian_html_page(parts + [HOSTILE])
    assert "<script" not in page and "<img" not in page and "onerror=alert" not in page.replace("onerror=alert(2)&gt;", "")
    assert page.count("&lt;script&gt;") >= len(parts)
    assert "border-left:4px solid #b36b00" in gc.guardian_html_card("t", "b", kind="warn")
    assert "border-left" not in gc.guardian_html_card("t", "b")


def test_html_text_block_keeps_line_breaks_and_caps_length():
    block = gc.guardian_html_text_block("line1\nline2\n\n" + "x" * 50, max_len=20)
    assert "line1<br>line2<br><br>" in block and block.count("x") < 50 and "…" in block
    assert "monospace" in gc.guardian_html_text_block("a", mono=True)


def test_html_header_skips_empty_facts():
    header = gc.guardian_html_header("Title", facts=[("Tick", 3), ("Cost", None), ("Verdict", "")])
    assert "<b>Tick</b> 3" in header and "Cost" not in header and "Verdict" not in header
    assert "opacity" not in gc.guardian_html_header("Title")


def test_html_empty_state_without_a_hint():
    assert "<br>" not in gc.guardian_html_empty("Nothing yet")


def test_html_sections_use_no_script_style_block_or_external_resource():
    page = gc.guardian_html_page(
        [
            gc.guardian_html_header("T", badges=[gc.guardian_html_status_badge("ok")], facts=[("a", "b")]),
            gc.guardian_html_table(["h"], [["c"]]),
            gc.guardian_html_card("t", "b", kind="ok"),
            gc.guardian_html_empty("e", hint="h"),
        ]
    )
    lowered = page.lower()
    for forbidden in ("<script", "<style", "<img", "<iframe", "<link", "http://", "https://", "position:fixed", "onclick", "url("):
        assert forbidden not in lowered


def test_html_entry_is_a_note_entry_with_html_contents_and_optional_context():
    entry = gc.guardian_html_entry(gc.guardian_html_trusted("<b>x</b>"))
    assert entry == {"Type": 1, "ContentsFormat": "html", "Contents": "<b>x</b>"}
    entry = gc.guardian_html_entry("<b>x</b>", context={"A.B": {"c": 1}})
    assert entry["EntryContext"] == {"A.B": {"c": 1}}


def test_html_or_fallback_uses_the_html_entry_when_it_builds(monkeypatch):
    assert gc.guardian_html_or_fallback(lambda: "<b>x</b>", lambda: "FALLBACK")["Contents"] == "<b>x</b>"


def test_html_or_fallback_falls_back_when_the_builder_raises(monkeypatch):
    errors = []
    monkeypatch.setattr(gc.demisto, "error", errors.append)

    def boom():
        raise RuntimeError("html builder broke")

    assert gc.guardian_html_or_fallback(boom, lambda: "FALLBACK") == "FALLBACK"
    assert errors and "html builder broke" in errors[0]


def test_ts_parse_handles_z_offsets_and_long_fractions():
    assert gc.guardian_ts_parse("2026-07-04T13:10:53.786Z").isoformat() == "2026-07-04T13:10:53.786000+00:00"
    assert gc.guardian_ts_parse("2026-07-04T13:10:53.123456789+00:00").second == 53
    assert gc.guardian_ts_parse("2026-07-04T15:10:53+02:00").hour == 13
    assert gc.guardian_ts_parse("2026-07-04T13:10:53").tzinfo is not None
    for bad in (None, "", "not a date", 5):
        assert gc.guardian_ts_parse(bad) is None


def test_ts_short_and_duration_text():
    assert gc.guardian_ts_short("2026-07-04T13:10:53.786Z") == "2026-07-04 13:10:53"
    assert gc.guardian_ts_short("garbage") == "garbage"
    assert gc.guardian_ts_short(None) == ""
    assert gc.guardian_duration_text(40) == "40s"
    assert gc.guardian_duration_text(12 * 60 + 5) == "12m"
    assert gc.guardian_duration_text(3600 + 5 * 60) == "1h 05m"
    assert gc.guardian_duration_text(None) == "" and gc.guardian_duration_text(True) == ""


# --- model size follows the model: tier order, catalogue lookup ------------------------------------------------

from pathlib import Path

_PACK_LISTS = Path(__file__).resolve().parents[2] / "Lists"   # this pack's own Lists, whichever edition is under test


def _shipped_catalog():
    return json.loads(json.loads((_PACK_LISTS / "list-guardian_model_catalog.json").read_text())["data"])


def _shipped_settings():
    return json.loads(json.loads((_PACK_LISTS / "list-guardian_settings.json").read_text())["data"])


_LARGE = {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None}
_MEDIUM = {"model_id": "command-r-08-2024", "size_class": "medium", "params_b": 32}


def test_tier_order_is_pin_then_catalogue_then_settings_then_small():
    plist = {"overrides": {"model_tier": "small"}}
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, plist, _LARGE)
    assert (p["tier"], p["tier_source"], p["tier_note"]) == ("small", "override", None)
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, {}, _LARGE)
    assert (p["tier"], p["tier_source"], p["catalog_model"]) == ("large", "catalogue (gpt-5-mini)", "gpt-5-mini")
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, {}, None)
    assert (p["tier"], p["tier_source"], p["tier_note"]) == ("medium", "guardian_settings", None)
    p = gc.guardian_resolve_model_params({"model_tier": "auto"}, {}, None)
    assert (p["tier"], p["tier_source"]) == (
        "small", "default (model not in the catalogue; set model_tier in guardian_settings)")


def test_auto_missing_and_invalid_settings_tiers_all_mean_no_explicit_value():
    for settings in ({"model_tier": "auto"}, {"model_tier": "AUTO"}, {}, {"model_tier": None}, {"model_tier": "huge"},
                     {"model_tier": 3}):
        p = gc.guardian_resolve_model_params(settings, {}, _MEDIUM)
        assert (p["tier"], p["tier_source"], p["tier_note"]) == ("medium", "catalogue (command-r-08-2024)", None), settings
    assert gc.guardian_tier_name("Large ") == "large" and gc.guardian_tier_name("auto") is None


def test_an_explicit_settings_tier_the_catalogue_overrules_is_said_once():
    p = gc.guardian_resolve_model_params({"model_tier": "small"}, {}, _LARGE)
    assert p["tier"] == "large"
    assert p["tier_note"] == ("guardian_settings.model_tier (small) is not used: gpt-5-mini is a large model in the "
                              "model catalogue; to force a size use overrides.model_tier in guardian_model_profile.")
    lines = gc.guardian_model_params_describe(p)
    assert lines.count(p["tier_note"]) == 1
    # an explicit value that agrees with the catalogue is not "ignored"
    assert gc.guardian_resolve_model_params({"model_tier": "large"}, {}, _LARGE)["tier_note"] is None


def test_a_catalogued_model_without_a_size_falls_to_settings_and_says_why():
    unsized = {"model_id": "gemma-3n-e4b-it", "size_class": None, "params_b": None}
    p = gc.guardian_resolve_model_params({"model_tier": "medium"}, {}, unsized)
    assert (p["tier"], p["tier_source"]) == ("medium", "guardian_settings")
    p = gc.guardian_resolve_model_params({"model_tier": "auto"}, {}, unsized)
    assert p["tier"] == "small" and "does not give the size of gemma-3n-e4b-it" in p["tier_source"]


def test_the_size_is_looked_up_on_every_run_from_the_record_with_no_new_field():
    catalog = _shipped_catalog()
    # a gpt-5-mini documented record exactly as it was written before sizes existed
    record = {"model": "gpt-5-mini", "catalog_id": "gpt-5-mini", "source": "documented", "max_input_tokens": 173400}
    plist = {"active": "P:i", "profiles": {"P:i": record}}
    before = json.dumps(plist, sort_keys=True)
    size = gc.guardian_catalog_size_for_run(plist, None, catalog)
    assert size == {"model_id": "gpt-5-mini", "size_class": "large", "params_b": None}
    assert json.dumps(plist, sort_keys=True) == before
    p = gc.guardian_resolve_model_params({"model_tier": "auto", "max_input_tokens": 28258}, plist, size)
    assert (p["tier"], p["tier_source"], p["max_input_tokens"]) == ("large", "catalogue (gpt-5-mini)", 173400)
    # a record that names only the model the provider reported (a measured record) is found by that name
    measured = {"active": "P:i", "profiles": {"P:i": {"model": "command-r:35b", "max_input_tokens": 9000}}}
    assert gc.guardian_catalog_size_for_run(measured, None, catalog)["size_class"] == "medium"


def test_command_r_35b_resolves_to_a_medium_catalogue_entry_through_its_alias():
    catalog = _shipped_catalog()
    for name in ("command-r:35b", "ollama:command-r:35b", "COMMAND-R:35B"):
        model = gc.guardian_catalog_lookup(catalog, name)
        assert model is not None and model["id"] == "command-r-08-2024", name
        assert (model["size_class"], model["params_b"]) == ("medium", 32), name
    # no record, no search: the configured name alone is enough
    size = gc.guardian_catalog_size_for_run({}, "command-r:35b", catalog)
    assert size["size_class"] == "medium" and size["model_id"] == "command-r-08-2024"


def test_the_catalogue_is_not_read_when_the_operator_pinned_a_tier(monkeypatch):
    monkeypatch.setattr(gc, "guardian_catalog_load", lambda: (_ for _ in ()).throw(AssertionError("read the catalogue")))
    assert gc.guardian_catalog_size_for_run({"overrides": {"model_tier": "large"}}, "gpt-5-mini") is None


def test_with_no_name_anywhere_the_enabled_provider_instance_is_looked_up(monkeypatch):
    response = {"instances": [{"name": "i", "brand": "GuardianFoundry", "enabled": "true",
                               "data": [{"name": "model_choice", "value": "gpt-5-mini"}]}],
                "configurations": [{"name": "GuardianFoundry", "integrationScript": {"commands": [{"name": "guardian-llm-chat"}]}}]}
    monkeypatch.setattr(gc, "guardian_search_integrations", lambda: response)
    assert gc.guardian_catalog_size_for_run({}, None, _shipped_catalog())["size_class"] == "large"
    monkeypatch.setattr(gc, "guardian_search_integrations", lambda: None)
    assert gc.guardian_catalog_size_for_run({}, None, _shipped_catalog()) is None


def test_for_run_resolves_the_size_from_the_catalogue_and_a_failure_there_is_the_settings_fallback(monkeypatch):
    plist = {"active": "P:i", "profiles": {"P:i": {"model": "gpt-5-mini", "catalog_id": "gpt-5-mini", "max_input_tokens": 173400}}}

    def execute(command, args):
        name = args.get("listName")
        payload = {"guardian_model_profile": plist, "guardian_model_catalog": _shipped_catalog()}[name]
        return gc.guardian_envelope(True, data=[{"Contents": json.dumps(payload)}])

    monkeypatch.setattr(gc, "guardian_execute", execute)
    params, note = gc.guardian_model_params_for_run({"model_tier": "small"})
    assert (params["tier"], params["tier_source"], note) == ("large", "catalogue (gpt-5-mini)", "resolved")
    monkeypatch.setattr(gc, "guardian_catalog_load", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    params, _note = gc.guardian_model_params_for_run({"model_tier": "small"})
    assert (params["tier"], params["tier_source"]) == ("small", "guardian_settings")


def test_run_params_come_from_the_snapshot_then_the_loop_state(monkeypatch):
    snap = gc.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 9000}, {})
    loop = {"model_params": gc.guardian_resolve_model_params({"model_tier": "large", "max_input_tokens": 9000}, {})}
    store = {"ModelProfile": snap, "Loop": loop}
    monkeypatch.setattr(gc, "guardian_ctx_read", lambda key, default=None: store.get(key, default))
    assert gc.guardian_run_model_params() == (snap, "snapshot")
    store.pop("ModelProfile")
    assert gc.guardian_run_model_params() == (loop["model_params"], "run state")
    store["Loop"] = {"model_params": {"tier": "large"}}   # not well formed: no limits
    assert gc.guardian_run_model_params() == (None, None)


# --- limits that scale with the input budget -----------------------------------------------------------------


def test_limits_for_gpt_5_mini_at_its_documented_budget():
    p = gc.guardian_resolve_model_params({"model_tier": "small", "max_input_tokens": 28258}, {
        "active": "P:i", "profiles": {"P:i": {"model": "gpt-5-mini", "max_input_tokens": 173400}}}, _LARGE)
    limits = p["limits"]
    assert (p["tier"], p["max_input_tokens"]) == ("large", 173400)
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (43350, "tier (25% of the input budget)")
    assert limits["evidence_truncate_bytes"] == 138720 and limits["evidence_truncate_bytes_source"] == "20% of the input budget"
    assert limits["evidence_head_tail_bytes"] == 69296   # (138720 - 128 for the marker) // 2: head + marker + tail is the ceiling
    assert limits["incident_details_chars"] == 34680
    assert (limits["batch_cap"], limits["history_by"]) == (None, "tokens")
    assert limits["subagent_tool_message_bytes"] == 138720 and limits["compact_tool_render_chars"] == 17340
    # a provider-safety limit (OpenAI-family function descriptions may be limited to 1024 characters), not a size saving
    assert gc.GUARDIAN_TIER_PROFILES["large"]["description_max_len"] == 1024


def test_limits_for_an_unknown_model_at_the_fallback_budget():
    p = gc.guardian_resolve_model_params(_shipped_settings(), {}, None)
    limits = p["limits"]
    assert (p["tier"], p["max_input_tokens"], p["max_tool_def_tokens"]) == ("small", 28258, 4000)
    # 20% of 28258 tokens as characters is above the old 16384 floor
    assert limits["evidence_truncate_bytes"] == 22606 and limits["evidence_head_tail_bytes"] == 11239
    assert limits["incident_details_chars"] == 5651
    assert limits["batch_cap"] is None and limits["compact_tool_render_chars"] == 2825


def test_limits_for_command_r_35b_show_the_budget_source():
    plist = {"active": "P:i", "profiles": {"P:i": {"model": "command-r:35b", "max_input_tokens": 28102}}}
    catalog = _shipped_catalog()
    p = gc.guardian_resolve_model_params({"model_tier": "auto", "max_input_tokens": 28258}, plist,
                                         gc.guardian_catalog_size_for_run(plist, None, catalog))
    assert (p["tier"], p["tier_source"]) == ("medium", "catalogue (command-r-08-2024)")
    assert (p["max_input_tokens"], p["max_input_tokens_source"]) == (28102, "measured")
    assert (p["max_tool_def_tokens"], p["max_tool_def_tokens_source"]) == (16000, "tier")
    assert p["limits"]["evidence_truncate_bytes"] == 28102 * 4 * 20 // 100


def test_limits_without_a_budget_are_todays_values():
    limits = gc.guardian_derive_limits(None)
    assert (limits["evidence_truncate_bytes"], limits["evidence_head_tail_bytes"], limits["incident_details_chars"]) == (16384, 8128, 2000)
    assert (limits["batch_cap"], limits["history_by"]) == (25, "messages")
    assert (limits["subagent_tool_message_bytes"], limits["compact_tool_render_chars"]) == (8000, 2000)


def test_head_and_tail_together_reach_the_ceiling_not_half_of_it():
    for budget in (None, 28258, 173400, 1000000):
        limits = gc.guardian_derive_limits(budget)
        ceiling, head_tail = limits["evidence_truncate_bytes"], limits["evidence_head_tail_bytes"]
        assert 2 * head_tail + gc.GUARDIAN_EVIDENCE_MARKER_RESERVE_BYTES == ceiling or 2 * head_tail + 129 == ceiling
        assert ceiling - 2 * head_tail <= 129 and 2 * head_tail < ceiling
    assert gc.guardian_evidence_head_tail(138720) == 69296 and gc.guardian_evidence_head_tail(10) == 1


def test_the_per_result_ceiling_never_goes_below_the_floor():
    assert gc.guardian_derive_limits(4000)["evidence_truncate_bytes"] == 16384
    assert gc.guardian_derive_limits(4000)["incident_details_chars"] == 2000


def test_explicit_settings_values_override_the_derived_limits():
    limits = gc.guardian_derive_limits(173400, {"evidence_truncate_bytes": 50000, "evidence_head_tail_bytes": 7000, "batch_cap": 12})
    assert (limits["evidence_truncate_bytes"], limits["evidence_truncate_bytes_source"]) == (50000, "guardian_settings")
    assert (limits["evidence_head_tail_bytes"], limits["evidence_head_tail_bytes_source"]) == (7000, "guardian_settings")
    assert (limits["batch_cap"], limits["batch_cap_source"], limits["history_by"]) == (12, "guardian_settings", "messages")
    # a ceiling set without a head/tail size gets a quarter of itself
    assert gc.guardian_derive_limits(173400, {"evidence_truncate_bytes": 40000})["evidence_head_tail_bytes"] == 19936   # about half of it, less the marker
    for bad in (0, -5, "lots", True, None):
        assert gc.guardian_derive_limits(173400, {"evidence_truncate_bytes": bad})["evidence_truncate_bytes"] == 138720


def test_a_large_models_tool_budget_has_a_floor_and_stays_under_the_input_budget_share():
    big = gc.guardian_resolve_model_params({"model_tier": "large"}, {"active": "a", "profiles": {"a": {"max_input_tokens": 400000}}})
    assert big["max_tool_def_tokens"] == 100000    # 25% of 400000
    small_window = gc.guardian_resolve_model_params({"model_tier": "large", "max_input_tokens": 28258}, {})
    assert small_window["max_tool_def_tokens"] == 16954   # the 24000 floor, capped at 60% of 28258
    assert small_window["max_tool_def_tokens_source"] == "tier, capped to 60% of max_input_tokens"
    none = gc.guardian_resolve_model_params({"model_tier": "large"}, {})
    assert (none["max_tool_def_tokens"], none["max_tool_def_tokens_source"]) == (24000, "tier")
    medium = gc.guardian_resolve_model_params({"model_tier": "medium"}, {"active": "a", "profiles": {"a": {"max_input_tokens": 400000}}})
    assert medium["max_tool_def_tokens"] == 16000   # only the large tier scales


def test_a_snapshot_without_limits_is_not_valid_so_it_is_resolved_again():
    p = gc.guardian_resolve_model_params({"model_tier": "medium", "max_input_tokens": 9000}, {})
    assert gc.guardian_model_params_valid(p)
    old = {k: v for k, v in p.items() if k not in ("limits", "tier_note", "catalog_model")}
    assert not gc.guardian_model_params_valid(old)
    assert not gc.guardian_model_params_valid(dict(p, limits={"evidence_truncate_bytes": 0}))


def test_describe_lines_show_size_source_and_limits():
    p = gc.guardian_resolve_model_params({"model_tier": "small"}, {"active": "P:i", "profiles": {"P:i": {
        "model": "gpt-5-mini", "max_input_tokens": 173400}}}, _LARGE)
    text = "\n".join(gc.guardian_model_params_describe(p))
    assert "Model size: large (catalogue (gpt-5-mini))." in text
    assert "Tool list budget (max_tool_def_tokens): 43350 (tier (25% of the input budget))." in text
    assert "Tool result limit: 138,720 bytes per result (20% of the input budget)." in text
    assert "Incident details in the prompt: up to 34,680 characters (5% of the input budget)." in text
    assert "History: compacted by tokens at 173,400." in text
    summary = gc.guardian_model_params_summary(p)
    assert summary.startswith("Model profile: size large (catalogue (gpt-5-mini)); input budget 173,400;")
    assert "tool result limit 138,720 bytes" in summary and "history compacted by tokens at 173,400" in summary
    none = gc.guardian_model_params_summary(gc.guardian_resolve_model_params({}, {}))
    assert "input budget unknown" in none and "history compacted at 25 messages" in none


def test_the_shipped_settings_use_auto_and_carry_no_fixed_limits():
    settings = _shipped_settings()
    assert settings["model_tier"] == "auto"
    for key in ("evidence_truncate_bytes", "evidence_head_tail_bytes", "batch_cap", "max_tool_def_tokens"):
        assert key not in settings, key
    assert settings["max_input_tokens"] == 28258
    assert "overrides.model_tier" in settings["_comment_model_tier"] and "13B to 40B" in settings["_comment_model_tier"]


# --- the catalogue's size classes -------------------------------------------------------------------------------


def test_every_catalogue_model_follows_the_one_size_rule():
    models = _shipped_catalog()["models"]
    sizes = {"small": 0, "medium": 0, "large": 0, None: 0}
    for model in models:
        params, cls = model["params_b"], model["size_class"]
        if params is None:
            # the size is not published: a closed hosted model counts as large, an open-weight one is never guessed
            expected = "large" if not model["open_weight"] else None
        elif params < 13:
            expected = "small"                       # params_b decides whenever it is known, closed models included
        elif params <= 40:
            expected = "medium"
        else:
            expected = "large"
        assert cls == expected, (model["id"], params, cls)
        sizes[cls] += 1
    assert sum(sizes.values()) == len(models)
    spot = {m["id"]: m["size_class"] for m in models}
    assert spot["gpt-oss-120b"] == "large" and spot["Qwen3-30B-A3B-Instruct-2507"] == "medium"
    assert spot["gpt-5-mini"] == "large" and spot["llama-3.1-8b-instruct"] == "small"
    assert spot["gemma-3n-e4b-it"] is None
    assert spot["ministral-3b-2410"] == "small"      # a closed model whose size is published is classed by it


# --- the pinned head ---------------------------------------------------------------------------------------------


def test_protected_messages_are_the_incident_pin_and_the_task_but_never_a_checkpoint():
    pin = {"role": "system", "content": "YOU ARE ALREADY WORKING THIS INCIDENT -- id 7"}
    task = {"role": "user", "content": "<untrusted-case-data>x</untrusted-case-data>"}
    assert gc.guardian_is_protected_message(pin) and gc.guardian_is_protected_message(task)
    assert not gc.guardian_is_protected_message({"role": "user", "content": "YOU ARE ALREADY WORKING"})      # wrong role
    assert not gc.guardian_is_protected_message({"role": "system", "content": "CHECKPOINT", "guardian_checkpoint": True})
    assert not gc.guardian_is_protected_message({"role": "system", "content": "YOU ARE ALREADY WORKING", "guardian_checkpoint": True})
    assert not gc.guardian_is_protected_message({"role": "user", "content": None}) and not gc.guardian_is_protected_message("x")
    sysmsg = {"role": "system", "content": "s"}
    assert gc.guardian_split_protected_head([sysmsg, pin, task, {"role": "assistant", "content": "a"}])[0] == [sysmsg, pin, task]


# --- the turn limit (MAX_TICKS) follows the model's size ----------------------------------------------------------


def test_the_turn_limit_per_tier_is_25_40_60():
    assert [gc.GUARDIAN_TIER_PROFILES[t]["max_ticks"] for t in ("small", "medium", "large")] == [25, 40, 60]
    for tier, expected in (("small", 25), ("medium", 40), ("large", 60)):
        p = gc.guardian_resolve_model_params({"model_tier": tier}, {})
        assert (p["max_ticks"], p["max_ticks_source"]) == (expected, "tier")
    # a catalogued model gets its size's limit, an unknown one the small limit
    assert gc.guardian_resolve_model_params({"model_tier": "auto"}, {}, _LARGE)["max_ticks"] == 60
    assert gc.guardian_resolve_model_params({"model_tier": "auto"}, {}, _MEDIUM)["max_ticks"] == 40
    assert gc.guardian_resolve_model_params({"model_tier": "auto"}, {}, None)["max_ticks"] == 25


def test_the_turn_limit_order_is_override_then_an_explicit_setting_then_the_tier():
    plist = {"overrides": {"max_ticks": 7}}
    p = gc.guardian_resolve_model_params({"model_tier": "large", "MAX_TICKS": 12}, plist)
    assert (p["max_ticks"], p["max_ticks_source"]) == (7, "override")
    p = gc.guardian_resolve_model_params({"model_tier": "large", "MAX_TICKS": 12}, {})
    assert (p["max_ticks"], p["max_ticks_source"]) == (12, "guardian_settings")      # an explicit value still wins over the size
    p = gc.guardian_resolve_model_params({"model_tier": "large"}, {})
    assert (p["max_ticks"], p["max_ticks_source"]) == (60, "tier")
    for bad in (0, -3, "25", True, None, 2.5e-1):                                    # a bad value is ignored, the tier applies
        p = gc.guardian_resolve_model_params({"model_tier": "medium", "MAX_TICKS": bad}, {"overrides": {"max_ticks": bad}})
        assert (p["max_ticks"], p["max_ticks_source"]) == (40, "tier"), bad


def test_the_turn_limit_is_reported_and_a_snapshot_without_it_is_resolved_again():
    p = gc.guardian_resolve_model_params({"model_tier": "large", "max_input_tokens": 9000}, {})
    assert "Turn limit (MAX_TICKS): 60 (tier)." in gc.guardian_model_params_describe(p)
    assert "turn limit 60" in gc.guardian_model_params_summary(p)
    old = {k: v for k, v in p.items() if k not in ("max_ticks", "max_ticks_source")}
    assert gc.guardian_model_params_valid(p) and not gc.guardian_model_params_valid(old)


def test_the_shipped_settings_carry_no_fixed_turn_limit():
    settings = _shipped_settings()
    assert "MAX_TICKS" not in settings
    assert "25 for a small model, 40 for a medium model, 60 for a large one" in settings["_comment_MAX_TICKS"]
    assert "overrides.max_ticks" in settings["_comment_MAX_TICKS"]


# --- Ported from the Cortex platform edition: epoch timestamps and the triage block ---


@pytest.mark.parametrize("value", [1767323045678, 1767323045678.0, "1767323045678", " 1767323045678 "])
def test_ts_parse_any_reads_epoch_milliseconds_as_number_or_text(value):
    assert gc.guardian_ts_parse_any(value).isoformat() == "2026-01-02T03:04:05.678000+00:00"


@pytest.mark.parametrize("value", [1767323045, "1767323045", "1767323045.0"])
def test_ts_parse_any_reads_epoch_seconds_as_number_or_text(value):
    assert gc.guardian_ts_parse_any(value).isoformat() == "2026-01-02T03:04:05+00:00"


def test_ts_parse_any_reads_iso_text_like_ts_parse_and_returns_none_for_the_unreadable():
    assert gc.guardian_ts_parse_any("2026-01-02T05:04:05+02:00").isoformat() == "2026-01-02T03:04:05+00:00"
    for bad in (None, "", "  ", "yesterday", True, {"a": 1}, [], "1e5", 10 ** 30):
        assert gc.guardian_ts_parse_any(bad) is None

# --- triage block -----------------------------------------------------------------------------------------------

def _block(**overrides):
    block = {
        "severity": "high",
        "investigation_type": "endpoint_threat",
        "confidence": 82,
        "likely_benign": False,
        "escalate": True,
        "summary": "A production bucket allows public reads and holds customer exports.",
        "key_entities": {"identities": ["svc-deploy"], "ips": ["203.0.113.9"], "hosts": ["web-01"], "hashes": [],
                         "domains": ["update-cdn.example"], "urls": [], "emails": []},
        "next_step": "Ask the owner to close public access.",
    }
    block.update(overrides)
    return block


def _fenced(block, lang="json"):
    return "```{}\n{}\n```".format(lang, json.dumps(block))


def test_triage_default_table_has_the_six_types_and_other():
    table = gc.guardian_triage_default_table()
    names = [row["name"] for row in table["types"]]
    assert len(names) == 7 and len(set(names)) == 7 and names[-1] == "other"
    assert table["severities"] == ["low", "medium", "high", "critical"]
    assert gc.guardian_triage_type_row(table, "data_exposure")["domains"] == ["detection", "posture"]
    assert gc.guardian_triage_type_row(table, "phishing")["sub_playbook"] == "GuardianTriagePhishing"


def test_triage_valid_block_parses_to_a_normalized_dict():
    parsed = gc.guardian_triage_parse_block("Analysis first.\n" + _fenced(_block()))
    assert parsed == {
        "severity": "high", "investigation_type": "endpoint_threat", "confidence": 82, "likely_benign": False,
        "escalate": True, "summary": "A production bucket allows public reads and holds customer exports.",
        "key_entities": {"identities": ["svc-deploy"], "ips": ["203.0.113.9"], "hosts": ["web-01"], "hashes": [],
                         "domains": ["update-cdn.example"], "urls": [], "emails": []},
        "next_step": "Ask the owner to close public access.", "analysis": "", "recommendations": [], "complexity": ""}


@pytest.mark.parametrize("fence", ["json", "", "JSON"])
def test_triage_block_fence_variants_are_accepted(fence):
    assert gc.guardian_triage_parse_block(_fenced(_block(), fence))["severity"] == "high"


def test_triage_text_after_the_block_does_not_hide_it():
    assert gc.guardian_triage_parse_block(_fenced(_block()) + "\n\nHope that helps!")["investigation_type"] == "endpoint_threat"


def test_triage_the_last_block_wins_and_an_invalid_last_block_is_never_replaced_by_an_earlier_one():
    first, second = _block(severity="low"), _block(severity="critical")
    assert gc.guardian_triage_parse_block(_fenced(first) + "\nrevised:\n" + _fenced(second))["severity"] == "critical"
    bad = _block(investigation_type="made_up")
    assert gc.guardian_triage_parse_block(_fenced(first) + "\n" + _fenced(bad)) is None


def test_triage_blocks_without_investigation_type_are_skipped():
    other_json = '```json\n{"note": 1}\n```'
    assert gc.guardian_triage_parse_block(_fenced(_block()) + "\n" + other_json)["severity"] == "high"
    verdict = '```json\n{"verdict": "Benign", "confidence": 80, "summary": "x"}\n```'
    assert gc.guardian_triage_parse_block(verdict) is None


def test_triage_bare_json_answer_is_accepted():
    parsed = gc.guardian_triage_parse_block(json.dumps(_block(severity="critical")))
    assert parsed["severity"] == "critical" and parsed["investigation_type"] == "endpoint_threat"
    assert gc.guardian_triage_parse_block("\n  " + json.dumps(_block(), indent=2) + "\n\n")["severity"] == "high"  # pretty-printed


def test_triage_prose_then_bare_json_is_accepted():
    text = "I read the packet. The bucket is public {see recommendations}, so:\n\n" + json.dumps(_block(severity="medium"))
    assert gc.guardian_triage_parse_block(text)["severity"] == "medium"
    assert gc.guardian_triage_parse_block(text + "\n\nLet me know.")["severity"] == "medium"


def test_triage_two_bare_objects_use_the_last_one_with_investigation_type():
    first, second = _block(severity="low"), _block(severity="critical")
    assert gc.guardian_triage_parse_block("draft: " + json.dumps(first) + "\nfinal: " + json.dumps(second))["severity"] == "critical"
    extra = '{"note": "unrelated"}'
    assert gc.guardian_triage_parse_block(json.dumps(second) + "\n" + extra)["severity"] == "critical"
    assert gc.guardian_triage_parse_block(json.dumps(first) + "\n" + json.dumps(_block(investigation_type="made_up"))) is None  # last wins, never an earlier draft


def test_triage_fenced_block_is_still_preferred_over_bare_json():
    text = json.dumps(_block(severity="low")) + "\nfinal:\n" + _fenced(_block(severity="high"))
    assert gc.guardian_triage_parse_block(text)["severity"] == "high"


@pytest.mark.parametrize("overrides", [{"investigation_type": "made_up"}, {"severity": "urgent"}, {"confidence": None},
                                       {"summary": "short"}, {"escalate": "maybe"}])
def test_triage_bare_json_that_fails_validation_is_still_rejected(overrides):
    assert gc.guardian_triage_parse_block(json.dumps(_block(**overrides))) is None
    assert gc.guardian_triage_parse_block("Here:\n" + json.dumps(_block(**overrides))) is None


def test_triage_bare_json_missing_a_required_key_is_rejected():
    for key in ("severity", "investigation_type", "confidence", "summary"):
        block = _block()
        del block[key]
        assert gc.guardian_triage_parse_block(json.dumps(block)) is None, key
        assert gc.guardian_triage_parse_block("ok " + json.dumps(block)) is None, key


@pytest.mark.parametrize("text", ["{", "}{", "{not json at all}", '{"investigation_type": ', "{{{{{{", "[{\"a\": 1}]", '{"a": 1}',
                                  '{"investigation_type": "other"} trailing {', "x" * 5000])
def test_triage_garbage_gives_none(text):
    assert gc.guardian_triage_parse_block(text) is None


@pytest.mark.parametrize("text", [None, "", 5, "no block here", "```json\n{not json}\n```", "```json\n[1, 2]\n```", '{"investigation_type": "other"}'])
def test_triage_missing_or_malformed_blocks_give_none(text):
    assert gc.guardian_triage_parse_block(text) is None


def test_triage_enum_values_must_come_from_the_table_whole_block_rejected_otherwise():
    assert gc.guardian_triage_validate(_block(severity="urgent")) is None
    assert gc.guardian_triage_validate(_block(severity="")) is None
    assert gc.guardian_triage_validate(_block(severity=None)) is None
    assert gc.guardian_triage_validate(_block(investigation_type="identity threat")) is None
    assert gc.guardian_triage_validate(_block(investigation_type="")) is None
    assert gc.guardian_triage_validate(_block(investigation_type=["other"])) is None
    # case and surrounding spaces are forgiven, and the canonical value is returned
    parsed = gc.guardian_triage_validate(_block(severity=" HIGH ", investigation_type="Endpoint_Threat"))
    assert parsed["severity"] == "high" and parsed["investigation_type"] == "endpoint_threat"


def test_triage_other_is_always_a_valid_type_even_when_the_list_omits_it():
    table = gc.guardian_triage_normalize_table({"types": [
        {"name": "identity_threat", "description": "x", "domains": ["detection"], "sub_playbook": "P", "skill": "s"}]})
    assert gc.guardian_triage_type_row(table, "other") is not None
    assert gc.guardian_triage_validate(_block(investigation_type="other"), table)["investigation_type"] == "other"
    assert gc.guardian_triage_validate(_block(investigation_type="endpoint_threat"), table) is None


def test_triage_confidence_is_required_clamped_and_numeric():
    assert gc.guardian_triage_validate(_block(confidence=250))["confidence"] == 100
    assert gc.guardian_triage_validate(_block(confidence=-5))["confidence"] == 0
    assert gc.guardian_triage_validate(_block(confidence="73.9"))["confidence"] == 73
    for bad in (None, "high", True, [80], {"v": 1}):
        assert gc.guardian_triage_validate(_block(confidence=bad)) is None, bad
    no_confidence = _block()
    del no_confidence["confidence"]
    assert gc.guardian_triage_validate(no_confidence) is None


@pytest.mark.parametrize("bad", ["inf", "-inf", "Infinity", "-Infinity", "nan", "1e999", float("inf"), float("-inf"), float("nan"), 1e999])
def test_triage_confidence_that_has_no_integer_value_is_invalid_not_a_crash(bad):
    assert gc.guardian_triage_validate(_block(confidence=bad)) is None


def test_triage_block_with_an_infinite_confidence_in_the_conclusion_text_is_not_parsed_and_does_not_raise():
    for literal in ("Infinity", "1e999", "-Infinity", "NaN"):
        text = 'done\n```json\n{"severity": "high", "investigation_type": "endpoint_threat", "confidence": %s, "likely_benign": false, ' \
               '"escalate": true, "summary": "A production bucket allows public reads.", "key_entities": {}, "next_step": "Close it."}\n```' % literal
        assert gc.guardian_triage_parse_block(text) is None, literal


def test_triage_flags_are_booleans_default_false_and_invalid_when_present_but_not_boolean():
    parsed = gc.guardian_triage_validate(_block(likely_benign="true", escalate="FALSE"))
    assert parsed["likely_benign"] is True and parsed["escalate"] is False
    absent = _block()
    del absent["likely_benign"], absent["escalate"]
    parsed = gc.guardian_triage_validate(absent)
    assert parsed["likely_benign"] is False and parsed["escalate"] is False
    assert gc.guardian_triage_validate(_block(likely_benign="maybe")) is None
    assert gc.guardian_triage_validate(_block(escalate=1)) is None


@pytest.mark.parametrize("summary", [None, 5, "", "too short", "unknown", "n/a", "     ", "tbd.", ["a long enough list element value"]])
def test_triage_summary_must_be_substantive(summary):
    assert gc.guardian_triage_validate(_block(summary=summary)) is None


def test_triage_summary_and_next_step_are_collapsed_and_capped():
    parsed = gc.guardian_triage_validate(_block(summary="word  " * 200, next_step="step " * 200))
    assert len(parsed["summary"]) <= gc.GUARDIAN_TRIAGE_SUMMARY_MAX_CHARS and "  " not in parsed["summary"]
    assert len(parsed["next_step"]) <= gc.GUARDIAN_TRIAGE_NEXT_STEP_MAX_CHARS
    assert gc.guardian_triage_validate(_block(next_step=None))["next_step"] == ""


def test_triage_key_entities_are_cleaned_capped_and_unknown_keys_dropped():
    entities = {
        "identities": ["  alice  ", "alice", 5, None, {"a": 1}, "bob"],
        "ips": "203.0.113.9",
        "urls": ["r%d" % i for i in range(30)],
        "emails": ["x" * 600],
        "hosts": "not-a-list-but-ok",
        "hashes": 7,
        "surprise": ["dropped"],
    }
    parsed = gc.guardian_triage_validate(_block(key_entities=entities, extra_key="dropped"))
    ke = parsed["key_entities"]
    assert set(ke) == set(gc.GUARDIAN_TRIAGE_ENTITY_KEYS)
    assert ke["identities"] == ["alice", "bob"] and ke["ips"] == ["203.0.113.9"]
    assert len(ke["urls"]) == gc.GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS
    assert ke["emails"] == []  # over the cap: dropped, never cut off
    assert ke["hosts"] == ["not-a-list-but-ok"] and ke["hashes"] == []
    assert "extra_key" not in parsed
    assert gc.guardian_triage_validate(_block(key_entities="nope"))["key_entities"] == {k: [] for k in gc.GUARDIAN_TRIAGE_ENTITY_KEYS}


def _synthetic_vmss_instance_id(length_at_least=250):
    """A made-up Azure VM scale-set instance resource id (zero subscription GUID, example names) of about 260 chars."""
    rg = "rg-example-" + "x" * 50
    vmss = "vmss-example-" + "y" * 50
    rid = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/{}/providers/Microsoft.Compute/"
           "virtualMachineScaleSets/{}/virtualMachines/12").format(rg, vmss)
    assert length_at_least <= len(rid) <= 270 and len(rid) > 200
    return rid


def test_triage_a_long_resource_id_is_kept_whole_not_cut_off():
    rid = _synthetic_vmss_instance_id()
    ke = gc.guardian_triage_clean_entities({"urls": [rid]})
    assert ke["urls"] == [rid]
    assert gc.guardian_triage_validate(_block(key_entities={"urls": ["  " + rid + "  "]}))["key_entities"]["urls"] == [rid]


def test_triage_an_entity_at_the_cap_is_kept_and_one_over_is_dropped_with_the_others_staying():
    at_cap = "a" * gc.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS
    too_long = "b" * (gc.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS + 1)
    huge = "/subscriptions/" + "c" * 600
    ke = gc.guardian_triage_clean_entities({"urls": ["first", too_long, at_cap, huge, "last"]})
    assert ke["urls"] == ["first", at_cap, "last"]
    # no partial value of a dropped item survives anywhere
    assert not any(item.startswith(("b", "/subscriptions/c")) for item in ke["urls"])


def test_triage_length_is_judged_after_whitespace_is_collapsed():
    spaced = ("ab" + " \n\t  " * 2) * 55  # long raw text, short once collapsed
    assert len(spaced) > gc.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS
    collapsed = " ".join(spaced.split())
    assert len(collapsed) <= gc.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS
    assert gc.guardian_triage_clean_entities({"hosts": [spaced]})["hosts"] == [collapsed]


def test_triage_dropped_entities_do_not_use_up_the_item_limit():
    too_long = ["z" * (gc.GUARDIAN_TRIAGE_ENTITY_MAX_CHARS + 1 + i) for i in range(25)]
    good = ["res-%d" % i for i in range(gc.GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS + 5)]
    # over-long items come first and in number far above the limit; the good ones must still fill the list
    ke = gc.guardian_triage_clean_entities({"urls": too_long + good})
    assert ke["urls"] == good[:gc.GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS]
    assert gc.guardian_triage_clean_entities({"urls": too_long})["urls"] == []


def test_triage_a_partly_valid_block_is_rejected_whole():
    assert gc.guardian_triage_validate({"severity": "high", "investigation_type": "other"}) is None  # no confidence or summary
    assert gc.guardian_triage_validate("not a dict") is None


def test_triage_normalize_table_rules():
    assert gc.guardian_triage_normalize_table("not json") is None
    assert gc.guardian_triage_normalize_table({"types": []}) is None
    assert gc.guardian_triage_normalize_table({"types": [{"name": "bad name!", "domains": ["detection"]}]}) is None
    table = gc.guardian_triage_normalize_table(json.dumps({
        "severities": ["low", "urgent", "high"],
        "types": [
            {"name": "A_Type", "description": " d  e ", "domains": ["posture", "x"], "sub_playbook": " P ", "skill": {"posture": "s1", "bogus": "s2"}},
            {"name": "a_type", "domains": ["detection"]},       # repeated name: first wins
            {"name": "nodomain", "domains": ["x"]},            # no valid domain: dropped
            "junk",
        ]}))
    assert table["severities"] == ["low", "high"]
    assert [r["name"] for r in table["types"]] == ["a_type", "other"]
    first = table["types"][0]
    assert first["domains"] == ["posture"] and first["description"] == "d e" and first["sub_playbook"] == "P"
    assert first["skill"] == {"posture": "s1"}


def test_triage_load_table_reads_the_list_and_falls_back_to_the_defaults(monkeypatch):
    payload = {"types": [{"name": "alpha", "description": "d", "domains": ["detection"], "sub_playbook": "P", "skill": "s"}]}
    monkeypatch.setattr(gc.demisto, "executeCommand", lambda c, a: [{"Type": 1, "Contents": json.dumps(payload)}])
    table, source = gc.guardian_triage_load_table()
    assert source == "list" and [r["name"] for r in table["types"]] == ["alpha", "other"]

    monkeypatch.setattr(gc.demisto, "executeCommand", lambda c, a: [{"Type": 4, "Contents": "Item not found"}])
    table, source = gc.guardian_triage_load_table()
    assert source == "default" and len(table["types"]) == 7

    monkeypatch.setattr(gc.demisto, "executeCommand", lambda c, a: [{"Type": 1, "Contents": "garbage"}])
    assert gc.guardian_triage_load_table()[1] == "default"

    def boom(c, a):
        raise RuntimeError("down")
    monkeypatch.setattr(gc.demisto, "executeCommand", boom)
    assert gc.guardian_triage_load_table()[1] == "default"


# --- the optional analysis and recommendations of a triage block ---------------------------------------------------

def test_triage_block_without_analysis_or_recommendations_is_still_valid_with_empty_values():
    parsed = gc.guardian_triage_validate(_block())
    assert parsed["analysis"] == "" and parsed["recommendations"] == []


def test_triage_analysis_is_collapsed_scrubbed_and_capped():
    parsed = gc.guardian_triage_validate(_block(analysis="word  \n" * 400 + " api_key=sk-liveSecretToken1234567890"))
    assert len(parsed["analysis"]) <= gc.GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS == 800
    assert "  " not in parsed["analysis"] and "\n" not in parsed["analysis"]
    short = gc.guardian_triage_validate(_block(analysis="password=hunter2 was seen in the query string"))
    assert "hunter2" not in short["analysis"]


def test_triage_recommendations_are_a_bounded_clean_list():
    items = ["  close   public access ", "", 7, None, "x" * 500] + ["step %d" % n for n in range(10)]
    parsed = gc.guardian_triage_validate(_block(recommendations=items))
    recs = parsed["recommendations"]
    assert len(recs) == gc.GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS == 5
    assert recs[0] == "close public access" and len(recs[1]) == gc.GUARDIAN_TRIAGE_RECOMMENDATION_MAX_CHARS == 200
    assert gc.guardian_triage_validate(_block(recommendations="rotate the key"))["recommendations"] == ["rotate the key"]


@pytest.mark.parametrize("bad", [5, {"a": 1}, True, [], [[]], None])
def test_triage_malformed_analysis_or_recommendations_are_read_as_absent_and_never_reject_the_block(bad):
    parsed = gc.guardian_triage_validate(_block(analysis=bad, recommendations=bad))
    assert parsed is not None and parsed["analysis"] == "" and parsed["recommendations"] == []


# --- Guardian's section of an incident's details (same marker and helpers as the Cortex platform edition) ----------

MARK = gc.GUARDIAN_ISSUE_SECTION_MARKER


def test_issue_section_split_returns_the_original_text_exactly():
    original = "Phishing report from the mail gateway.\n\nSecond paragraph.\n"
    text = original + gc.GUARDIAN_ISSUE_SECTION_GAP + MARK + "\nTriage: high"
    assert gc.guardian_split_issue_section(text) == (original, MARK + "\nTriage: high")
    assert gc.guardian_strip_issue_section(text) == original
    assert gc.guardian_split_issue_section(MARK + "\nTriage: x") == ("", MARK + "\nTriage: x")


def test_issue_section_absent_or_not_a_line_changes_nothing():
    for text in ("", "plain text", "mentions " + MARK + " inline", "x\n" + MARK + " trailing words"):
        assert gc.guardian_split_issue_section(text) == (text, "")
        assert gc.guardian_strip_issue_section(text) == text
    assert gc.guardian_strip_issue_section(None) is None and gc.guardian_strip_issue_section(5) == 5
    assert gc.guardian_split_issue_section(None) == ("", "")


def test_issue_section_is_found_with_windows_line_endings():
    text = "original\r\n\r\n" + MARK + "\r\nTriage: x"
    assert gc.guardian_split_issue_section(text)[0] == "original"


def test_deep_strip_walks_dicts_and_lists_and_leaves_everything_else_alone():
    section = gc.GUARDIAN_ISSUE_SECTION_GAP + MARK + "\nTriage: x\nInvestigation: y"
    value = {"details": "Original." + section, "rows": [{"details": "kept" + section}, "plain", 5, None, True],
             "nested": {"a": {"b": ["deep" + section]}}, "untouched": "no marker here"}
    assert gc.guardian_strip_issue_section_deep(value) == {
        "details": "Original.", "rows": [{"details": "kept"}, "plain", 5, None, True],
        "nested": {"a": {"b": ["deep"]}}, "untouched": "no marker here"}
    assert gc.guardian_strip_issue_section_deep(value)["rows"][0] is not value["rows"][0]  # a copy, the input is not changed
    assert value["details"].endswith("Investigation: y")
    assert gc.guardian_strip_issue_section_deep(None) is None and gc.guardian_strip_issue_section_deep(7) == 7


def test_deep_strip_removes_the_section_from_json_text_with_escaped_line_breaks():
    text = json.dumps({"details": "Original." + gc.GUARDIAN_ISSUE_SECTION_GAP + MARK + "\nTriage: x \"quoted\"\nInvestigation: y", "id": "9"})
    stripped = gc.guardian_strip_issue_section_deep(text)
    assert MARK not in stripped and "Triage" not in stripped and "quoted" not in stripped
    assert json.loads(stripped) == {"details": "Original.", "id": "9"}


# --- the optional complexity of a triage block ---------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [("low", "low"), ("Medium", "medium"), (" HIGH ", "high"), ("", ""), (None, ""), (3, ""),
                                             ("extreme", ""), (["low"], ""), (True, "")])
def test_triage_complexity_is_low_medium_or_high_and_anything_else_is_absent(value, expected):
    parsed = gc.guardian_triage_validate(_block(complexity=value))
    assert parsed is not None and parsed["complexity"] == expected


def test_triage_block_without_complexity_is_valid_with_an_empty_value():
    assert gc.guardian_triage_validate(_block())["complexity"] == ""


# --- guardian_set_incident_fields: the optional `details` builder ----------------------------------------------------

def _details_world(monkeypatch, records, write_errors=()):
    """REST stubs: each read returns the next record of `records` (the last one repeats); each write fails with the next
    error of `write_errors`, then succeeds. Returns the list of posted bodies."""
    posted, reads = [], {"n": 0}
    errors = list(write_errors)

    def fake_execute(command, args):
        body = json.loads(args["body"])
        if args["uri"] == "/incidents/search":
            record = records[min(reads["n"], len(records) - 1)]
            reads["n"] += 1
            return _rest_entry({"total": 1, "data": [dict(record)]})
        if args["uri"] == "/incident":
            if errors:
                return [{"Type": 4, "Contents": errors.pop(0)}]
            posted.append(body)
            return _rest_entry(body)
        raise AssertionError("unexpected uri {}".format(args["uri"]))

    monkeypatch.setattr(gc.demisto, "executeCommand", fake_execute)
    return posted


def test_set_incident_fields_writes_details_built_from_the_record_it_read(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 3, "details": "Original text.", "CustomFields": {"a": 1}}])
    seen = []
    result = gc.guardian_set_incident_fields("42", {}, details=lambda current: seen.append(current) or current + "\n\nsection")
    assert result["ok"] is True and result["data"] == {"id": "42", "fields": {}, "details_written": True}
    assert seen == ["Original text."]
    assert len(posted) == 1 and posted[0]["details"] == "Original text.\n\nsection"
    assert posted[0]["CustomFields"] == {"a": 1} and posted[0]["version"] == 3  # nothing else changes


def test_set_incident_fields_rebuilds_details_from_the_fresh_record_after_an_optimistic_lock(monkeypatch):
    records = [{"id": "42", "version": 1, "details": "first"}, {"id": "42", "version": 2, "details": "edited meanwhile"}]
    posted = _details_world(monkeypatch, records, write_errors=["errOptimisticLock: version mismatch"])
    result = gc.guardian_set_incident_fields("42", {}, details=lambda current: current + " +section")
    assert result["ok"] is True and posted[0]["details"] == "edited meanwhile +section"  # never the stale text


def test_set_incident_fields_does_not_write_when_the_details_are_unchanged_or_the_builder_declines(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 1, "details": "same"}])
    for builder in (lambda current: current, lambda current: None):
        result = gc.guardian_set_incident_fields("42", {}, details=builder)
        assert result["ok"] is True and result["data"]["details_written"] is False
    assert posted == []


def test_set_incident_fields_never_writes_details_it_could_not_read(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 1, "CustomFields": {}}])
    result = gc.guardian_set_incident_fields("42", {}, details=lambda current: "new")
    assert result["ok"] is False and "without its details text" in result["error"] and posted == []


def test_set_incident_fields_reports_a_builder_that_raises(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 1, "details": ""}])

    def broken(current):
        raise ValueError("bad")

    result = gc.guardian_set_incident_fields("42", {}, details=broken)
    assert result["ok"] is False and "building the new details failed" in result["error"] and posted == []


def test_set_incident_fields_writes_details_and_custom_fields_in_one_post(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 1, "details": "", "CustomFields": {"keep": "x"}}])
    result = gc.guardian_set_incident_fields("42", {"guardiantickcount": 2}, details=lambda current: "section")
    assert result["ok"] is True and result["data"] == {"id": "42", "fields": {"guardiantickcount": 2}, "details_written": True}
    assert len(posted) == 1 and posted[0]["details"] == "section"
    assert posted[0]["CustomFields"] == {"keep": "x", "guardiantickcount": 2}


def test_set_incident_fields_without_details_is_unchanged(monkeypatch):
    posted = _details_world(monkeypatch, [{"id": "42", "version": 1, "details": "untouched", "CustomFields": {}}])
    result = gc.guardian_set_incident_fields("42", {"guardiancostusd": 1.0})
    assert result["data"] == {"id": "42", "fields": {"guardiancostusd": 1.0}}
    assert posted[0]["details"] == "untouched"


def test_pricing_entry_exact_then_longest_boundary_prefix():
    pricing = {"gpt-5": {"input_per_1m": 1}, "gpt-5-mini": {"input_per_1m": 2}, "command-r": {"input_per_1m": 3}, "bad": "x"}
    assert gc.guardian_pricing_entry(pricing, "gpt-5-mini") == {"input_per_1m": 2}
    assert gc.guardian_pricing_entry(pricing, "gpt-5-mini-2025-08-07") == {"input_per_1m": 2}   # the longest row wins
    assert gc.guardian_pricing_entry(pricing, "GPT-5-2025-08-07") == {"input_per_1m": 1}
    assert gc.guardian_pricing_entry(pricing, "command-r:35b") == {"input_per_1m": 3}
    assert gc.guardian_pricing_entry(pricing, "gpt-5mini") is None and gc.guardian_pricing_entry(pricing, "gpt-55") is None
    assert gc.guardian_pricing_entry(pricing, "bad-model") is None
    assert gc.guardian_pricing_entry(pricing, "") is None and gc.guardian_pricing_entry(pricing, None) is None
    assert gc.guardian_pricing_entry(None, "gpt-5") is None and gc.guardian_pricing_entry([], "gpt-5") is None
