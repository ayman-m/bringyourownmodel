# <GUARDIAN_CATALOG>
# ---------------------------------------------------------------------------
# Documented model limits: helpers over the `guardian_model_catalog` List.
#
# CANONICAL SOURCE: scripts/guardian_catalog_block.py. This block is copied verbatim, between its two
# marker lines, into GuardianModelProfileCheck, GuardianProbeModel, GuardianModelProfileUpdate and
# GuardianModelCommand in BOTH packs (scripts cannot import one another). Edit it ONLY in the canonical
# file, then run `python3 scripts/sync_catalog_block.py`; a parity test fails if any copy differs.
#
# Everything here is pure (no I/O). The lookup itself (`guardian_catalog_lookup`, `guardian_catalog_load`,
# `guardian_catalog_configured_model`, `guardian_catalog_parse`) lives in GuardianCommon, because the run
# resolves the model's size class from the catalogue in every script that reads the model numbers, not only
# in these four; this block builds on it. The List is pack-seeded data, like `guardian_pricing`: it is only
# ever read. The block uses the standard library only and carries no platform wording, so it stays identical
# in both packs.
# ---------------------------------------------------------------------------
import re

#: What a model's characters-per-token is assumed to be when it has not been measured. This is
#: deliberately conservative (lower than the 4.0 the loop's own estimator assumes): SOC content is
#: JSON-heavy and tokenises densely. The recommended budget is scaled by (chars per token / 4) so that the
#: loop's chars/4 estimate stays under the real window; at an assumed 4.0 the budget would overflow the
#: window for any tokenizer that packs below about 3.4 characters per token. A documented or confirmed
#: budget never uses a measured ratio ABOVE this value: the probe measures English prose (a gpt-5 model
#: gives about 4.6), but the loop's real content is JSON-heavy, so a prose ratio would put the real token
#: count over the documented limit.
GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN = 3.0
#: The headroom factor applied to the usable input limit (the same 0.85 the probe uses).
GUARDIAN_CATALOG_SAFETY_MARGIN = 0.85
#: The characters per token the loop's own estimator assumes (chars / 4).
GUARDIAN_CATALOG_ESTIMATOR_CHARS_PER_TOKEN = 4.0
#: A measured window at or above this share of the documented usable input limit confirms the documented
#: figure; below it the measured figure wins (the "20% rule").
GUARDIAN_CATALOG_CONFIRM_SHARE = 0.8
#: The Guardian integration (spaces, case and punctuation ignored) -> the cloud platform whose provider
#: limits row applies to it. Any other integration, including a self-hosted one, has no platform.
GUARDIAN_CATALOG_PLATFORMS = {"guardianfoundry": "azure-foundry", "guardianvertex": "vertex"}


def _guardian_catalog_positive(value):
    """``int(value)`` when it is a real positive number (not a bool), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = int(value)
    return number if number > 0 else None


def guardian_catalog_platform(integration_brand):
    """The cloud platform whose provider limits apply to a Guardian integration: GuardianFoundry ->
    ``azure-foundry``, GuardianVertex -> ``vertex``; anything else (GuardianCohere is self-hosted) -> ``None``."""
    key = re.sub(r"[^a-z0-9]", "", str(integration_brand or "").lower())
    return GUARDIAN_CATALOG_PLATFORMS.get(key)


def _guardian_catalog_provider_row(model, platform, name):
    """The provider row to apply: one whose versions include ``name``, else the first row with no versions."""
    rows = [row for row in (model.get("provider_limits") or []) if isinstance(row, dict) and row.get("provider") == platform]
    candidates = _guardian_catalog_candidates(name)
    for row in rows:
        versions = [str(v).lower() for v in (row.get("versions") or [])]
        if versions and any(candidate in versions for candidate in candidates):
            return row
    for row in rows:
        if not row.get("versions"):
            return row
    return None


def guardian_catalog_limits(model, platform, name=None):
    """The documented limits to use for ``model`` on ``platform``.

    The provider's row for that platform when there is one, else the vendor's figures. A row that
    describes a different release of the model (it lists ``versions``) applies only when ``name`` is one
    of those ids, so pass the name that was matched.

    :return: ``{"context_window", "max_input_tokens", "max_output_tokens", "basis", "managed"}``.
        ``basis`` is ``"<platform> cap"`` (for example ``"azure-foundry cap"``) or ``"vendor"``; ``managed``
        is ``True`` when a provider row matched. ``None`` when ``model`` is not a dict.
    """
    if not isinstance(model, dict):
        return None
    row = _guardian_catalog_provider_row(model, platform, name) if platform else None
    source = row if row is not None else model
    return {
        "context_window": _guardian_catalog_positive(source.get("context_window")),
        "max_input_tokens": _guardian_catalog_positive(source.get("max_input_tokens")),
        "max_output_tokens": _guardian_catalog_positive(source.get("max_output_tokens")),
        "basis": "{} cap".format(platform) if row is not None else "vendor",
        "managed": row is not None,
    }


def guardian_catalog_usable_input(limits, output_reserve):
    """The documented usable input limit, in REAL tokens, or ``None`` when no figure is known.

    ``min(max_input_tokens, context_window - output_reserve)`` when both are known; ``max_input_tokens``
    when only that is; ``context_window - output_reserve`` when only the window is.
    """
    limits = limits if isinstance(limits, dict) else {}
    window = _guardian_catalog_positive(limits.get("context_window"))
    max_input = _guardian_catalog_positive(limits.get("max_input_tokens"))
    reserve = _guardian_catalog_positive(output_reserve) or 0
    if window and max_input:
        usable = min(max_input, window - reserve)
    elif max_input:
        usable = max_input
    elif window:
        usable = window - reserve
    else:
        usable = None
    return usable if usable is not None and usable > 0 else None


def _guardian_catalog_budget_from_usable(usable, chars_per_token, safety_margin, cap):
    """``(budget, cpt_used, cpt_source, capped)`` for one DOCUMENTED usable input limit, in the loop's chars/4
    units. The ratio used is ``min(measured, assumed)``: a measured ratio only ever lowers the budget (see
    :data:`GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN`); ``cpt_source`` is ``"measured"`` only when the measured
    ratio was the lower one."""
    cpt = chars_per_token if isinstance(chars_per_token, (int, float)) and not isinstance(chars_per_token, bool) \
        and chars_per_token > 0 else None
    cpt_source = "measured" if cpt is not None and cpt < GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN else "assumed"
    if cpt is None or cpt >= GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN:
        cpt = GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN
    budget = None
    capped = False
    if usable:
        budget = int(usable * safety_margin * (cpt / GUARDIAN_CATALOG_ESTIMATOR_CHARS_PER_TOKEN))
        cap_value = _guardian_catalog_positive(cap)
        if cap_value is not None and budget > cap_value:
            budget, capped = cap_value, True
    return budget, cpt, cpt_source, capped


def guardian_catalog_documented_budget(limits, output_reserve, chars_per_token, cap=None,
                                       safety_margin=GUARDIAN_CATALOG_SAFETY_MARGIN):
    """The input budget the loop should use for a documented model, in the loop's own units.

    A profile's ``max_input_tokens`` is not a count of real tokens: the loop compares it with its own
    chars/4 estimate. So this uses the probe's formula, ``(window - output_reserve) x safety x (cpt / 4)``,
    where the usable input limit stands in for ``window - output_reserve``.

    :param limits: :func:`guardian_catalog_limits`'s result.
    :param output_reserve: Tokens kept free for the answer.
    :param chars_per_token: The measured ratio, or ``None``. The ratio used is the lower of this and the
        conservative assumed one (3.0).
    :param cap: Optional ``guardian_settings.max_input_tokens_cap`` (unset by default); limits the budget.
    :return: ``{"budget", "usable_input_tokens", "output_reserve", "chars_per_token",
        "chars_per_token_source", "safety_margin", "cap", "capped"}``; ``budget`` is ``None`` when the
        limits give no usable input figure.
    """
    usable = guardian_catalog_usable_input(limits, output_reserve)
    budget, cpt, cpt_source, capped = _guardian_catalog_budget_from_usable(usable, chars_per_token, safety_margin, cap)
    return {
        "budget": budget,
        "usable_input_tokens": usable,
        "output_reserve": _guardian_catalog_positive(output_reserve) or 0,
        "chars_per_token": round(cpt, 3),
        "chars_per_token_source": cpt_source,
        "safety_margin": safety_margin,
        "cap": _guardian_catalog_positive(cap),
        "capped": capped,
    }


def guardian_catalog_documented_trusted(catalog_entry):
    """May a model's documented window stand in for what is served? Yes for a model that needs no probe (a
    closed frontier model) and for one the provider's own cap row covers; no for a self-hosted open-weight
    model, whose served window depends on the runtime. ``catalog_entry`` is the probe's ``catalog`` dict."""
    entry = catalog_entry if isinstance(catalog_entry, dict) else {}
    return entry.get("probe") == "skip" or bool((entry.get("limits") or {}).get("managed"))


def guardian_catalog_compare(documented_input_real_tokens, probe_result, safety_margin=GUARDIAN_CATALOG_SAFETY_MARGIN,
                             cap=None, documented_trusted=True):
    """The 20% rule: weigh a probe against the documented usable input limit, like with like.

    The probe's measured window (``latency_bounded_window``, real tokens) is compared with the documented
    usable input limit (real tokens), never with a recommended budget.

    - ``confirmed``: the measured window is at least 80% of the documented limit, or the probe reached its
      ceiling. The documented-derived budget is used (with the lower of the measured and the assumed
      characters per token), but never above the probe's own recommendation when it has one: the window it
      measured may be smaller than the documented one.
    - ``measured``: the measured window is below 80% (or the search ran out of time below it). The
      probe's recommended budget is used, with an evidence line.
    - ``quota``: the probe stopped on a tokens-per-minute quota error. The window was not contradicted, so
      the documented-derived budget is used, but only when ``documented_trusted`` (the model needs no probe,
      or the provider's own cap applies). For a self-hosted model the served window is unknown: the verdict is
      then ``measured``, the budget is the probe's recommendation from the largest size that answered (``None``
      when none did), and the evidence names the quota stop.
    - No documented figure (an unknown model): the probe's recommendation, verdict ``measured``.

    :param documented_input_real_tokens: :func:`guardian_catalog_usable_input`'s result, or ``None``.
    :param documented_trusted: ``False`` for a self-hosted open-weight model (``probe`` is not ``skip`` and no
        provider cap applies): its documented window is not evidence of what is served.
    :param probe_result: The probe's calibration record (``latency_bounded_window``, ``at_ceiling``,
        ``truncated``, ``probe_ceiling_tokens``, ``quota_limited``, ``quota_at_tokens``,
        ``recommended_max_input_tokens``, ``chars_per_token``, ``chars_per_token_measured``,
        ``limit_evidence``).
    :return: ``{"verdict", "budget", "documented_input", "measured_window", "share", "gap_percent",
        "evidence", "chars_per_token", "chars_per_token_source", "capped"}``.
    """
    probe = probe_result if isinstance(probe_result, dict) else {}
    documented = _guardian_catalog_positive(documented_input_real_tokens)
    window = _guardian_catalog_positive(probe.get("latency_bounded_window"))
    measured_cpt = probe.get("chars_per_token") if probe.get("chars_per_token_measured") else None
    share = round(window / float(documented), 3) if documented and window else None
    gap_percent = int(round((1.0 - share) * 100)) if share is not None and share < 1.0 else 0
    recommended = _guardian_catalog_positive(probe.get("recommended_max_input_tokens"))

    def _documented_budget():
        return _guardian_catalog_budget_from_usable(documented, measured_cpt, safety_margin, cap)

    def _result(verdict, budget, evidence, cpt, cpt_source, capped):
        return {"verdict": verdict, "budget": budget, "documented_input": documented, "measured_window": window,
                "share": share, "gap_percent": gap_percent, "evidence": evidence,
                "chars_per_token": round(cpt, 3) if cpt else None, "chars_per_token_source": cpt_source,
                "capped": capped}

    quota_note = "quota (tokens-per-minute) reached at {} tokens; the window was not reached".format(
        probe.get("quota_at_tokens") or "an unknown number of")

    if documented is None or (probe.get("quota_limited") and not documented_trusted):
        cap_value = _guardian_catalog_positive(cap)
        budget = min(recommended, cap_value) if recommended and cap_value else recommended
        evidence = probe.get("limit_evidence")
        if probe.get("quota_limited"):
            evidence = quota_note + ("; the budget is sized from the largest size that answered ({} tokens)".format(window)
                                     if window else "")
        return _result("measured", budget, evidence, probe.get("chars_per_token"),
                       "measured" if probe.get("chars_per_token_measured") else "assumed",
                       bool(recommended and cap_value and recommended > cap_value))

    if probe.get("quota_limited"):
        budget, cpt, cpt_source, capped = _documented_budget()
        return _result("quota", budget, quota_note, cpt, cpt_source, capped)

    ceiling = _guardian_catalog_positive(probe.get("probe_ceiling_tokens"))
    reached_ceiling = bool(probe.get("at_ceiling")) and (ceiling is None or ceiling >= documented * GUARDIAN_CATALOG_CONFIRM_SHARE)
    if reached_ceiling or (window and window >= documented * GUARDIAN_CATALOG_CONFIRM_SHARE):
        budget, cpt, cpt_source, capped = _documented_budget()
        if recommended and budget is not None and recommended < budget:
            budget = recommended  # the window the probe measured can be smaller than the documented one
        if reached_ceiling:
            evidence = "the probe reached its ceiling of {} tokens without a failure".format(window or ceiling)
        else:
            evidence = "the measured window ({} tokens) is {}% of the documented usable input limit ({})".format(
                window, int(round(share * 100)), documented)
        return _result("confirmed", budget, evidence, cpt, cpt_source, capped)

    cap_value = _guardian_catalog_positive(cap)
    budget = min(recommended, cap_value) if recommended and cap_value else recommended
    if window is None:
        evidence = probe.get("limit_evidence") or "the probe could not determine a window"
    else:
        evidence = probe.get("limit_evidence") or "the largest size that was answered correctly and in time was {} tokens".format(window)
        if probe.get("truncated"):
            evidence += "; the search ran out of time, so this is a floor and the real window may be larger"
    cpt = probe.get("chars_per_token")
    return _result("measured", budget, evidence, cpt, "measured" if probe.get("chars_per_token_measured") else "assumed",
                   bool(recommended and cap_value and recommended > cap_value))


def guardian_catalog_record_source(record):
    """Where a profile record's figure comes from: ``documented``, ``confirmed``, ``measured`` or
    ``quota``. A record with no ``source`` (every record written before the catalogue existed) is measured."""
    source = record.get("source") if isinstance(record, dict) else None
    return source if source in ("documented", "confirmed", "quota") else "measured"


def guardian_catalog_source_label(record):
    """Short text for where a record's input budget comes from, for the "(source)" part of a report line."""
    source = guardian_catalog_record_source(record)
    if source == "documented":
        return "documented, catalogue {}".format(record.get("catalog_checked") or "date unknown")
    if source == "confirmed":
        return "confirmed by a probe, documented limit used"
    if source == "quota":
        return "documented, a probe hit a quota limit"
    return "measured"


def guardian_catalog_profile_line(record):
    """The report line that describes the active profile record, worded for where its figure comes from
    (the shared describe line says "Measured profile ... probed" whatever the source)."""
    source = guardian_catalog_record_source(record)
    model = record.get("model") or "unknown model"
    instance = record.get("instance_name") or "unknown instance"
    probed = record.get("probed_at") or "at an unknown time"
    documented = record.get("documented_input_tokens")
    window = record.get("window")
    if source == "documented":
        return "Documented profile: {} on {}, from the model catalogue checked {} ({}). No probe has run for it.".format(
            model, instance, record.get("catalog_checked") or "on an unknown date",
            (record.get("limits") or {}).get("basis") or "vendor")
    if source == "confirmed":
        return ("Confirmed profile: {} on {}, probed {}. The measured window ({}) is within 20% of the documented "
                "usable input limit ({}), so the documented limit is used.").format(model, instance, probed, window, documented)
    if source == "quota":
        return ("Documented profile, quota-limited probe: {} on {}, probed {}. The probe stopped on a "
                "tokens-per-minute quota ({}), so the documented window was not contradicted and the documented "
                "limit is used.").format(model, instance, probed, record.get("evidence") or "no detail")
    line = "Measured profile: {} on {}, probed {}.".format(model, instance, probed)
    if documented and isinstance(window, (int, float)) and window < documented:
        line += " The measured window ({:,}) is {}% below the documented usable input limit ({:,}){}.".format(
            int(window), int(round((1.0 - window / float(documented)) * 100)), documented,
            ": " + record["evidence"] if record.get("evidence") else "")
    return line


def guardian_catalog_apply_source(params, record):
    """A copy of the resolved model numbers whose ``max_input_tokens_source`` names where the record's
    figure really comes from. The resolver says "measured" for any profile record; that is wrong for a
    documented one. Other sources (override, settings) are left alone."""
    out = dict(params)
    if isinstance(record, dict) and out.get("max_input_tokens_source") == "measured":
        out["max_input_tokens_source"] = guardian_catalog_source_label(record)
    return out


def guardian_catalog_describe(params, record):
    """War Room lines for the resolved model numbers, worded for the active record's source.
    ``guardian_model_params_describe`` plus the two rewrites a documented figure needs."""
    lines = guardian_model_params_describe(guardian_catalog_apply_source(params, record))
    if isinstance(record, dict) and params.get("profile") and lines and lines[-1].startswith("Measured profile:"):
        lines[-1] = guardian_catalog_profile_line(record)
    return lines
# </GUARDIAN_CATALOG>
