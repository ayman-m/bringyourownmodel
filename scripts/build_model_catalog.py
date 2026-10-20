#!/usr/bin/env python3
"""Build the `guardian_model_catalog` List for both Guardian packs from the research data.

Input:  docs/reference/model-catalog/model_catalog.json (the source of truth, with notes and sources).
Output: Packs/Guardian/Lists/list-guardian_model_catalog.json and
        Packs/GuardianXSIAM/Lists/list-guardian_model_catalog.json

The output is deterministic (same input, same bytes) and safe to re-run. The list envelope (id, version,
type, fromVersion and so on) is copied from each pack's own `list-guardian_pricing.json`, because the two
packs' envelopes can differ. The List `data` is compact JSON: `{"checked": "<date>", "models": [...]}`.

Per model the List keeps: id, aliases, vendor, open_weight, context_window, max_input_tokens,
max_output_tokens, supports_tools, supports_structured_output, reasoning, status, params_b (total parameters
in billions, from the model id or card, else null), size_class (small, medium, large or null; see
size_class_for), source (the first URL only), probe ("confirm" for an open-weight model, else "skip") and provider_limits. The research notes are
dropped to keep the List small.

Each provider_limits row keeps provider, context_window, max_input_tokens and max_output_tokens. The
provider keys are normalised (aws-bedrock -> bedrock, google-vertex -> vertex; azure-foundry stays). A row
that describes a DIFFERENT release from its model entry (the research row has a `version` field) also keeps
`versions`: the exact model ids it applies to. The lookup in the pack code applies such a row only when the
name being looked up is one of those ids.

Run:  python3 scripts/build_model_catalog.py            write both Lists and print a report
      python3 scripts/build_model_catalog.py --check    exit 1 if a List on disk differs from a fresh build
"""

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESEARCH_JSON = REPO_ROOT / "docs" / "reference" / "model-catalog" / "model_catalog.json"
PACK_NAMES = ("Guardian", "GuardianXSIAM")
LIST_NAME = "guardian_model_catalog"
PRICING_LIST_FILE = "list-guardian_pricing.json"
OUTPUT_FILE = "list-guardian_model_catalog.json"
DESCRIPTION = (
    "Documented context limits for commonly used models, used to set the input budget without a probe; "
    "this file is generated, so to add or change a model edit docs/reference/model-catalog/model_catalog.json, "
    "run scripts/build_model_catalog.py and install the pack again."
)

PROVIDER_KEY_MAP = {"aws-bedrock": "bedrock", "google-vertex": "vertex", "azure-foundry": "azure-foundry"}
#: Alias prefixes that name a platform (the part before the first colon). Used only to report lookup-key
#: collisions the same way the pack code builds its index; a prefix that is not listed here (for example
#: the `command-r` in `command-r:35b`) is part of the name.
KNOWN_ALIAS_PREFIXES = ("foundry", "bedrock", "vertex", "hf", "oci", "ollama")
MODEL_FIELDS = (
    "id", "aliases", "vendor", "open_weight", "context_window", "max_input_tokens", "max_output_tokens",
    "supports_tools", "supports_structured_output", "reasoning", "status", "params_b", "size_class",
)

#: Size classes by TOTAL parameters in billions (a mixture-of-experts model counts its total, not its
#: active, parameters): below SMALL_BELOW is "small", up to MEDIUM_UP_TO inclusive is "medium", above is "large".
SIZE_SMALL_BELOW = 13
SIZE_MEDIUM_UP_TO = 40


def size_class_for(open_weight, params_b):
    """The size class of a model, by total parameters whenever they are known -- for a closed model too (a closed 3B
    model is small). Only when the size is not published does the kind of model decide: a closed hosted model is
    "large" (a frontier model with a large window and native tool use); an open-weight model with no stated size has
    no class (``None``)."""
    if isinstance(params_b, (int, float)) and not isinstance(params_b, bool) and params_b > 0:
        if params_b < SIZE_SMALL_BELOW:
            return "small"
        return "medium" if params_b <= SIZE_MEDIUM_UP_TO else "large"
    return None if open_weight else "large"


def version_ids(label):
    """The exact model ids named by a research `version` label, lower-cased.

    The label reads like ``"mistral-small-2503 (Small 3.1)"`` or
    ``"gpt-4o-2024-11-20 and gpt-4o-2024-08-06 (gpt-4o-2024-05-13 is the next row)"``: the ids are what
    comes before the first parenthesis, split on " and ".
    """
    head = str(label or "").split(" (")[0]
    ids = []
    for part in re.split(r"\s+and\s+|,\s*", head):
        part = part.strip().lower()
        if part and re.fullmatch(r"[a-z0-9][a-z0-9._:/@-]*", part) and part not in ids:
            ids.append(part)
    return ids


def build_row(row):
    out = {"provider": PROVIDER_KEY_MAP.get(row["provider"], row["provider"])}
    for key in ("context_window", "max_input_tokens", "max_output_tokens"):
        out[key] = row.get(key)
    if row.get("version"):
        out["versions"] = version_ids(row["version"])
    return out


def build_model(model):
    out = {key: model.get(key) for key in MODEL_FIELDS}
    expected = size_class_for(model.get("open_weight"), model.get("params_b"))
    if out["size_class"] != expected:
        raise SystemExit("error: {} has size_class {!r} but its open_weight/params_b give {!r}".format(
            model["id"], out["size_class"], expected))
    out["source"] = (model.get("sources") or [None])[0]
    out["probe"] = "confirm" if model.get("open_weight") else "skip"
    out["provider_limits"] = [build_row(row) for row in model.get("provider_limits") or []]
    return out


def build_catalog(research):
    return {"checked": research["checked"], "models": [build_model(m) for m in research["models"]]}


def lookup_keys(model):
    """Every lower-cased string the pack lookup can match for one catalogue model: the id, each alias as
    stored, each alias with its platform prefix removed, and the exact ids of any versioned provider row."""
    keys = [model["id"].lower()]
    for alias in model.get("aliases") or []:
        keys.append(alias.lower())
        prefix, sep, rest = alias.partition(":")
        if sep and prefix.lower() in KNOWN_ALIAS_PREFIXES and rest:
            keys.append(rest.lower())
    for row in model.get("provider_limits") or []:
        keys.extend(row.get("versions") or [])
    return keys


def find_collisions(models):
    """``{key: [model ids]}`` for every lookup key that maps to more than one model."""
    owners = {}
    for model in models:
        for key in set(lookup_keys(model)):
            owners.setdefault(key, [])
            if model["id"] not in owners[key]:
                owners[key].append(model["id"])
    return {key: ids for key, ids in owners.items() if len(ids) > 1}


def envelope_for(pack_name):
    pricing = json.loads((REPO_ROOT / "Packs" / pack_name / "Lists" / PRICING_LIST_FILE).read_text())
    envelope = {}
    for key, value in pricing.items():
        if key == "id" or key == "name":
            envelope[key] = LIST_NAME
        elif key == "description":
            envelope[key] = DESCRIPTION
        elif key == "data":
            envelope[key] = None  # filled below
        else:
            envelope[key] = value
    return envelope


def render(pack_name, catalog):
    envelope = envelope_for(pack_name)
    envelope["data"] = json.dumps(catalog, separators=(",", ":"), ensure_ascii=True)
    return json.dumps(envelope, indent=4, ensure_ascii=True) + "\n"


def main(argv):
    check = "--check" in argv
    research = json.loads(RESEARCH_JSON.read_text())
    catalog = build_catalog(research)
    models = catalog["models"]
    collisions = find_collisions(models)
    compact = json.dumps(catalog, separators=(",", ":"), ensure_ascii=True)
    print("models: {}".format(len(models)))
    print("checked: {}".format(catalog["checked"]))
    print("compact data size: {} bytes ({:.1f} KB)".format(len(compact.encode()), len(compact.encode()) / 1024.0))
    print("lookup-key collisions: {}".format(len(collisions)))
    for key, ids in sorted(collisions.items()):
        print("  COLLISION {!r}: {}".format(key, ", ".join(ids)))
    versioned = [(m["id"], r["provider"], r["versions"]) for m in models for r in m["provider_limits"] if r.get("versions")]
    print("versioned provider rows: {}".format(len(versioned)))
    for model_id, provider, versions in versioned:
        print("  {} / {}: {}".format(model_id, provider, versions))
    print("probe=confirm: {}, probe=skip: {}".format(
        sum(1 for m in models if m["probe"] == "confirm"), sum(1 for m in models if m["probe"] == "skip")))
    if collisions:
        print("error: resolve the collisions in the research data before building", file=sys.stderr)
        return 2
    differs = False
    for pack_name in PACK_NAMES:
        path = REPO_ROOT / "Packs" / pack_name / "Lists" / OUTPUT_FILE
        text = render(pack_name, catalog)
        size = len(text.encode())
        if check:
            if not path.exists() or path.read_text() != text:
                print("{}: OUT OF DATE".format(path.relative_to(REPO_ROOT)))
                differs = True
            else:
                print("{}: in sync ({} bytes)".format(path.relative_to(REPO_ROOT), size))
        else:
            path.write_text(text)
            print("wrote {} ({} bytes)".format(path.relative_to(REPO_ROOT), size))
    return 1 if differs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
