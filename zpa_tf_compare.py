#!/usr/bin/env python3
"""
zpa_tf_compare.py
─────────────────
Compare a Terraform state file against ZPA Ansible bulk-download exports
for four resource types:
  • Server Groups        (zpa_server_group)
  • Segment Groups       (zpa_segment_group)
  • Application Segments (zpa_application_segment)
  • Policy Access Rules  (zpa_policy_access_rule)

Optionally generates an Ansible cleanup playbook that:
  1. Removes rogue app segments from policy access rules that TF manages
     (i.e. app segments added to a TF-managed rule outside of Terraform)
  2. Deletes policy access rules that exist in ZPA but not in TF state
  3. Deletes application segments that exist in ZPA but not in TF state

The cleanup order ensures no referential conflicts:
  Step 1  – Patch drifted policy rules  → strip out-of-state app segments
  Step 2  – Delete rogue policy rules
  Step 3  – Delete rogue app segments

Usage
─────
  python zpa_tf_compare.py \\
      --state               terraform.tfstate \\
      --server-groups       zpa_server_groups.yaml \\
      --segment-groups      zpa_segment_groups.yaml \\
      --app-segments        zpa_app_segments.yaml \\
      --policy-rules        zpa_policy_rules.yaml \\
      [--output report.txt] \\
      [--format text|json] \\
      [--ignore-fields field1,field2] \\
      [--playbook cleanup_zpa.yaml] \\
      [--zpa-cloud PRODUCTION|BETA|GOV|PREVIEW] \\
      [--dry-run]

All --*-groups / --*-segments / --*-rules flags accept either a single file
or a glob pattern (e.g. "exports/server_groups*.yaml").
"""

import argparse
import glob
import json
import os
import sys
import textwrap
from datetime import datetime
from typing import Any

# ── optional colour support ───────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

# ── optional YAML support ─────────────────────────────────────────────────────
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────

def _c(text: str, colour: str) -> str:
    if not _HAS_COLOR:
        return text
    colours = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "bold":   Style.BRIGHT,
        "reset":  Style.RESET_ALL,
    }
    return f"{colours.get(colour, '')}{text}{Style.RESET_ALL}"


# ─────────────────────────────────────────────────────────────────────────────
# File loading helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_yaml(path: str) -> Any:
    if not _HAS_YAML:
        sys.exit(
            "PyYAML is required to read YAML files.\n"
            "Install it with:  pip install pyyaml"
        )
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_file(path: str) -> Any:
    """Auto-detect JSON or YAML by extension, fall back to trying both."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        return _load_yaml(path)
    if ext == ".json":
        return _load_json(path)
    try:
        return _load_json(path)
    except json.JSONDecodeError:
        return _load_yaml(path)


def _expand_paths(pattern: str) -> list[str]:
    """Expand a file path or glob pattern to a list of existing files."""
    paths = glob.glob(pattern, recursive=True)
    if not paths:
        return [pattern]
    return sorted(paths)


# ─────────────────────────────────────────────────────────────────────────────
# Terraform state parsing
# ─────────────────────────────────────────────────────────────────────────────

_TF_TYPE_MAP = {
    "zpa_server_group":        "server_groups",
    "zpa_segment_group":       "segment_groups",
    "zpa_application_segment": "app_segments",
    "zpa_policy_access_rule":  "policy_rules",
}

_TF_NAME_ATTRS = ("name",)


def _attr(resource_attrs: dict, *keys: str, default="") -> Any:
    for k in keys:
        if k in resource_attrs:
            return resource_attrs[k]
    return default


def parse_tf_state(state_path: str) -> dict[str, dict[str, dict]]:
    """
    Return a dict keyed by category -> {name: attributes_dict}.
    Handles both Terraform 0.12 (flat list) and 0.13+ (module tree) formats.
    """
    state = _load_json(state_path)
    result: dict[str, dict[str, dict]] = {k: {} for k in _TF_TYPE_MAP.values()}

    raw_resources: list[dict] = []
    tf_version = state.get("version", 1)

    if tf_version >= 3:
        def _walk_resources(node: dict):
            for r in node.get("resources", []):
                raw_resources.append(r)
            for mod in (node.get("modules", {}).values()
                        if isinstance(node.get("modules"), dict) else []):
                _walk_resources(mod)
            for mod in node.get("child_modules", []):
                _walk_resources(mod)
        _walk_resources(state)
    else:
        for mod in state.get("modules", []):
            for res_val in mod.get("resources", {}).values():
                raw_resources.append(res_val)

    for res in raw_resources:
        res_type = res.get("type", "")
        if res_type not in _TF_TYPE_MAP:
            continue
        category = _TF_TYPE_MAP[res_type]

        for instance in res.get("instances", [res]):
            attrs = instance.get(
                "attributes",
                instance.get("primary", {}).get("attributes", {})
            )
            if not attrs:
                continue
            name = _attr(attrs, *_TF_NAME_ATTRS) or res.get("name", "<unknown>")
            result[category][name] = attrs

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Ansible ZPA bulk-download parsing
# ─────────────────────────────────────────────────────────────────────────────

def _extract_list_from_ansible(data: Any, hint_key: str = "") -> list[dict]:
    """Best-effort extraction of a list of resource dicts from Ansible output."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]

    if isinstance(data, dict):
        for key in ("data", "result", "resources", "response"):
            val = data.get(key)
            if isinstance(val, list):
                return [d for d in val if isinstance(d, dict)]
            if isinstance(val, dict):
                inner = val.get("data") or val.get("list") or []
                if isinstance(inner, list):
                    return [d for d in inner if isinstance(d, dict)]

        if hint_key and hint_key in data and isinstance(data[hint_key], list):
            return [d for d in data[hint_key] if isinstance(d, dict)]

        for val in data.values():
            if isinstance(val, list) and all(isinstance(i, dict) for i in val[:3]):
                return val

    return []


def parse_ansible_export(
    paths: list[str],
    hint_key: str = "",
) -> dict[str, dict]:
    """
    Load one or more Ansible export files and return {name: record_dict}.
    Multiple files are merged (later files win on name collision).
    """
    combined: dict[str, dict] = {}
    for path in paths:
        raw = _load_file(path)
        records = _extract_list_from_ansible(raw, hint_key)
        for rec in records:
            name = rec.get("name") or rec.get("display_name") or ""
            if name:
                combined[name] = rec
    return combined


# ─────────────────────────────────────────────────────────────────────────────
# Field normalisation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_value(v: Any) -> Any:
    if isinstance(v, list):
        normalised = [_normalise_value(i) for i in v]
        try:
            return sorted(normalised, key=lambda x: str(x))
        except TypeError:
            return normalised
    if isinstance(v, dict):
        return {k: _normalise_value(val) for k, val in sorted(v.items())}
    if isinstance(v, str):
        if v.lower() in ("true", "false"):
            return v.lower() == "true"
        try:
            return int(v)
        except ValueError:
            pass
        try:
            return float(v)
        except ValueError:
            pass
    return v


def _flatten(obj: Any, prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten a nested dict/list into dot-separated keys."""
    items: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            items.update(_flatten(v, new_key, sep))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{prefix}[{i}]"
            items.update(_flatten(v, new_key, sep))
    else:
        items[prefix] = obj
    return items


# ─────────────────────────────────────────────────────────────────────────────
# App-segment membership helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_app_segment_names_from_tf_rule(rule_attrs: dict) -> set[str]:
    """
    Extract the set of application segment names/ids referenced by a TF
    policy rule.

    TF state stores IDs in conditions -> operands -> values.
    Some provider versions also emit a flat name list; we capture both.
    The returned set may contain a mix of names and IDs — the caller
    reconciles against the Ansible export by matching on both.
    """
    refs: set[str] = set()

    # Flat name lists (some provider versions)
    for key in ("app_segment_names", "application_segment_names"):
        val = rule_attrs.get(key)
        if isinstance(val, list):
            refs.update(str(v) for v in val if v)

    # conditions -> operands -> values (IDs in most TF provider versions)
    for cond in rule_attrs.get("conditions", []) or []:
        for operand in cond.get("operands", []) or []:
            if operand.get("object_type", "").upper() == "APP":
                for v in operand.get("values", []) or []:
                    if v:
                        refs.add(str(v))

    return refs


def _extract_app_segment_refs_from_ans_rule(rule_record: dict) -> dict[str, str]:
    """
    Extract app segment references from an Ansible/ZPA API policy rule.

    Returns {name_or_id: id} so callers can match on either identifier.

    ZPA API conditions shape:
      conditions:
        - operands:
            - objectType: APP
              values:
                - {name: "...", id: "..."}
    """
    refs: dict[str, str] = {}  # name -> id

    for cond in rule_record.get("conditions", []) or []:
        for operand in cond.get("operands", []) or []:
            obj_type = (
                operand.get("objectType") or operand.get("object_type") or ""
            ).upper()
            if obj_type == "APP":
                for v in operand.get("values", []) or []:
                    if isinstance(v, dict):
                        seg_name = v.get("name", "")
                        seg_id   = v.get("id", "")
                    else:
                        seg_name = ""
                        seg_id   = str(v)
                    if seg_name:
                        refs[seg_name] = seg_id
                    if seg_id:
                        refs[seg_id] = seg_id

    # Flat app_segments list sometimes present in collection output
    for seg in rule_record.get("app_segments", []) or []:
        if isinstance(seg, dict):
            seg_name = seg.get("name", "")
            seg_id   = seg.get("id", "")
        else:
            seg_name = ""
            seg_id   = str(seg)
        if seg_name:
            refs[seg_name] = seg_id
        if seg_id:
            refs[seg_id] = seg_id

    return refs


def _build_cleaned_conditions(
    ans_rule: dict,
    segments_to_remove: set[str],
) -> list[dict]:
    """
    Return a copy of the rule's conditions list with the specified app
    segments stripped out (matched by name or id).

    Operands whose values list becomes empty are dropped entirely.
    Conditions whose operands list becomes empty are dropped entirely.
    All other condition types (SAML, SCIM, etc.) are preserved unchanged.
    """
    cleaned_conditions = []

    for cond in ans_rule.get("conditions", []) or []:
        cleaned_operands = []

        for operand in cond.get("operands", []) or []:
            obj_type = (
                operand.get("objectType") or operand.get("object_type") or ""
            ).upper()

            # Non-APP operands pass through untouched
            if obj_type != "APP":
                cleaned_operands.append(operand)
                continue

            kept_values = []
            for v in operand.get("values", []) or []:
                if isinstance(v, dict):
                    identity_candidates = {v.get("name", ""), v.get("id", "")} - {""}
                else:
                    identity_candidates = {str(v)}

                if identity_candidates.isdisjoint(segments_to_remove):
                    kept_values.append(v)
                # else: this segment is being removed — skip it

            if kept_values:
                new_op = dict(operand)
                new_op["values"] = kept_values
                cleaned_operands.append(new_op)
            # Operand with no remaining values is dropped

        if cleaned_operands:
            new_cond = dict(cond)
            new_cond["operands"] = cleaned_operands
            cleaned_conditions.append(new_cond)
        # Condition with no remaining operands is dropped

    return cleaned_conditions


# ─────────────────────────────────────────────────────────────────────────────
# Core comparison logic
# ─────────────────────────────────────────────────────────────────────────────

ALWAYS_IGNORE = {
    # TF-internal metadata
    "id", "timeouts", "microtenant_id",
    # ZPA/Ansible metadata
    "createdBy", "modifiedBy", "creationTime", "modifiedTime",
    "microtenantName",
}


def _compare_records(
    tf_attrs: dict,
    ans_record: dict,
    ignore_fields: set[str],
) -> list[dict]:
    skip = ALWAYS_IGNORE | ignore_fields

    tf_flat  = _flatten({k: _normalise_value(v) for k, v in tf_attrs.items()})
    ans_flat = _flatten({k: _normalise_value(v) for k, v in ans_record.items()})

    def _prune(d: dict) -> dict:
        return {
            k: v for k, v in d.items()
            if not any(
                k == s or k.startswith(f"{s}.") or k.startswith(f"{s}[")
                for s in skip
            )
        }

    tf_flat  = _prune(tf_flat)
    ans_flat = _prune(ans_flat)

    drifts = []
    for key in sorted(set(tf_flat) | set(ans_flat)):
        tf_val  = tf_flat.get(key, "<not present>")
        ans_val = ans_flat.get(key, "<not present>")
        if tf_val != ans_val:
            drifts.append({"field": key, "tf": tf_val, "zpa": ans_val})

    return drifts


CategoryResult = dict  # {"only_in_tf": list, "only_in_zpa": list, "drift": dict}


def compare_category(
    tf_resources: dict[str, dict],
    ans_resources: dict[str, dict],
    ignore_fields: set[str],
) -> CategoryResult:
    tf_names  = set(tf_resources)
    ans_names = set(ans_resources)

    only_tf  = sorted(tf_names  - ans_names)
    only_ans = sorted(ans_names - tf_names)
    common   = tf_names & ans_names

    drift: dict[str, list[dict]] = {}
    for name in sorted(common):
        diffs = _compare_records(tf_resources[name], ans_resources[name], ignore_fields)
        if diffs:
            drift[name] = diffs

    return {"only_in_tf": only_tf, "only_in_zpa": only_ans, "drift": drift}


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup analysis
# ─────────────────────────────────────────────────────────────────────────────

class CleanupPlan:
    """
    Captures all changes the cleanup playbook needs to make.

    rogue_policy_rules : list[dict]
        Rules in ZPA but absent from TF state — will be deleted.
        Each entry: {"name": str, "id": str, "record": dict}

    rogue_app_segments : list[dict]
        App segments in ZPA but absent from TF state — will be deleted.
        Each entry: {"name": str, "id": str, "record": dict}

    rules_needing_patch : list[dict]
        TF-managed rules that have extra app segments not in TF state.
        Will be updated (not deleted) to remove those segment references.
        Each entry:
          {
            "name":               str,
            "id":                 str,
            "record":             dict,          # full live Ansible record
            "rogue_segments":     set[str],      # names/ids to strip
            "cleaned_conditions": list[dict],    # updated conditions payload
          }
    """

    def __init__(self):
        self.rogue_policy_rules:  list[dict] = []
        self.rogue_app_segments:  list[dict] = []
        self.rules_needing_patch: list[dict] = []


def build_cleanup_plan(
    tf_data:  dict[str, dict[str, dict]],
    ans_data: dict[str, dict[str, dict]],
    results:  dict[str, CategoryResult],
) -> CleanupPlan:
    """
    Derive what the cleanup playbook must do:

    1. Identify rogue policy rules (only_in_zpa).
    2. Identify rogue app segments (only_in_zpa).
    3. For each TF-managed policy rule, compare which app segments are
       referenced in ZPA vs TF state.  Any extra segments (whether they
       are wholly rogue or just manually added to an existing rule) are
       flagged for removal from the rule's conditions block.
    """
    plan = CleanupPlan()

    # Names of app segments not tracked by TF
    rogue_seg_names: set[str] = set(results["app_segments"]["only_in_zpa"])

    # Build a name->id lookup from the Ansible app segment export so we can
    # match TF IDs (stored in conditions) to rogue segment names.
    seg_id_to_name: dict[str, str] = {
        rec.get("id", ""): name
        for name, rec in ans_data["app_segments"].items()
        if rec.get("id")
    }

    # ── 1. Rogue policy rules ─────────────────────────────────────────────────
    for name in results["policy_rules"]["only_in_zpa"]:
        rec = ans_data["policy_rules"].get(name, {})
        plan.rogue_policy_rules.append({
            "name":   name,
            "id":     rec.get("id", ""),
            "record": rec,
        })

    # ── 2. Rogue app segments ─────────────────────────────────────────────────
    for name in rogue_seg_names:
        rec = ans_data["app_segments"].get(name, {})
        plan.rogue_app_segments.append({
            "name":   name,
            "id":     rec.get("id", ""),
            "record": rec,
        })

    # ── 3. TF-managed rules with extra app segment refs ───────────────────────
    tf_rules  = tf_data["policy_rules"]
    ans_rules = ans_data["policy_rules"]

    for rule_name in sorted(set(tf_rules) & set(ans_rules)):
        # What TF thinks should be in this rule (IDs and/or names)
        tf_refs = _extract_app_segment_names_from_tf_rule(tf_rules[rule_name])

        # What ZPA actually has in this rule right now (name -> id mapping)
        ans_refs = _extract_app_segment_refs_from_ans_rule(ans_rules[rule_name])
        ans_names_in_rule = set(ans_refs.keys())

        # Resolve TF IDs to names where possible so we can compare apples/apples
        tf_refs_resolved: set[str] = set()
        for ref in tf_refs:
            tf_refs_resolved.add(ref)
            if ref in seg_id_to_name:
                tf_refs_resolved.add(seg_id_to_name[ref])

        # Extra segments in ZPA rule: not accounted for by TF and either:
        #   a) the segment name/id is in the rogue set, OR
        #   b) the reference simply doesn't appear in TF state at all
        extra_in_zpa: set[str] = set()
        for ref in ans_names_in_rule:
            if ref in rogue_seg_names:
                # Rogue segment referenced in a TF-managed rule
                extra_in_zpa.add(ref)
            elif ref not in tf_refs_resolved:
                # Segment exists in TF state but was manually added to this rule
                extra_in_zpa.add(ref)

        if extra_in_zpa:
            ans_rec  = ans_rules[rule_name]
            cleaned  = _build_cleaned_conditions(ans_rec, extra_in_zpa)
            plan.rules_needing_patch.append({
                "name":               rule_name,
                "id":                 ans_rec.get("id", ""),
                "record":             ans_rec,
                "rogue_segments":     extra_in_zpa,
                "cleaned_conditions": cleaned,
            })

    return plan


# ─────────────────────────────────────────────────────────────────────────────
# Ansible playbook generation
# ─────────────────────────────────────────────────────────────────────────────

def _safe_var(name: str) -> str:
    """Convert a resource name to a safe Ansible variable-name suffix."""
    return "".join(c if c.isalnum() else "_" for c in name).strip("_")[:40]


def _to_yaml_block(obj: Any, indent: int = 8) -> str:
    """Serialise obj to an indented YAML block (or JSON if PyYAML unavailable)."""
    if _HAS_YAML:
        raw = yaml.dump(
            obj,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        ).rstrip()
    else:
        raw = json.dumps(obj, indent=2)
    pad = " " * indent
    return "\n".join(pad + line for line in raw.splitlines())


def _rule_update_params(entry: dict) -> dict:
    """
    Build the zpa_policy_access_rule module param dict for a patch.
    We keep all live values and only replace the conditions list.
    """
    rec: dict = entry["record"]
    params: dict[str, Any] = {
        "state":      "present",
        "name":       rec.get("name", ""),
        "action":     rec.get("action", "ALLOW"),
        "conditions": entry["cleaned_conditions"],
    }
    for field in ("description", "rule_order", "operator",
                  "custom_msg", "lss_default_rule"):
        val = rec.get(field)
        if val not in (None, "", [], {}):
            params[field] = val
    for field in ("app_connector_groups", "app_server_groups"):
        val = rec.get(field)
        if val:
            params[field] = val
    return params


def generate_playbook(
    plan:      CleanupPlan,
    zpa_cloud: str  = "PRODUCTION",
    dry_run:   bool = False,
) -> str:
    """
    Emit a multi-play Ansible YAML playbook as a string.

    Play ordering (safe dependency order):
      Play 1 – Patch TF-managed rules: strip rogue app segment refs
      Play 2 – Delete rogue policy access rules
      Play 3 – Delete rogue application segments
    """
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dry_tag = " [DRY-RUN — check_mode: true]" if dry_run else ""

    has_patches      = bool(plan.rules_needing_patch)
    has_rule_deletes = bool(plan.rogue_policy_rules)
    has_seg_deletes  = bool(plan.rogue_app_segments)

    L: list[str] = []  # output lines

    # ── File header ───────────────────────────────────────────────────────────
    L += [
        "# " + "=" * 77,
        f"# ZPA Cleanup Playbook{dry_tag}",
        f"# Generated : {ts}",
        f"# Cloud     : {zpa_cloud}",
        "#",
        "# Purpose: Remove resources created outside of Terraform so that a",
        "#          subsequent 'terraform apply' succeeds without name conflicts.",
        "#",
        "# Execution order:",
        "#   Play 1 — Patch TF-managed policy rules (strip rogue app-segment refs)",
        "#   Play 2 — Delete rogue policy access rules  (not in TF state)",
        "#   Play 3 — Delete rogue application segments (not in TF state)",
        "#",
        "# CAUTION: Review carefully before running. Deletions are irreversible.",
        "#",
        "# Required environment variables (or pass via -e / vault):",
        "#   ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID",
        "#",
        "# Recommended first run:",
        "#   ansible-playbook cleanup_zpa.yaml --check   # dry-run / check mode",
        "# " + "=" * 77,
        "",
        "---",
        "",
    ]

    play_number = 0  # incremented before each play

    # =========================================================================
    # Play 1 — Patch TF-managed rules to remove rogue app segment refs
    # =========================================================================
    if has_patches:
        play_number += 1
        L += [
            "# " + "-" * 77,
            f"# Play {play_number} — Patch TF-managed policy rules",
            "#              Strip app segment references not present in TF state",
            "# " + "-" * 77,
            f"- name: >-",
            f"    [Play {play_number}] ZPA Cleanup | Remove rogue app-segment refs from managed rules",
            "  hosts: localhost",
            "  connection: local",
            "  gather_facts: false",
            "",
            "  vars:",
            f'    zpa_cloud: "{zpa_cloud}"',
            '    zpa_client_id:     "{{ lookup(\'env\', \'ZPA_CLIENT_ID\') }}"',
            '    zpa_client_secret: "{{ lookup(\'env\', \'ZPA_CLIENT_SECRET\') }}"',
            '    zpa_customer_id:   "{{ lookup(\'env\', \'ZPA_CUSTOMER_ID\') }}"',
            "",
            "  tasks:",
            "",
        ]

        for entry in plan.rules_needing_patch:
            var_suffix = _safe_var(entry["name"])
            rogue_list = sorted(entry["rogue_segments"])
            params     = _rule_update_params(entry)

            # Emit a comment block describing the change
            L += [
                f"    # ── Rule: {entry['name']}",
                f"    #    ZPA id : {entry['id'] or 'unknown'}",
                f"    #    Removing {len(rogue_list)} rogue app segment reference(s):",
            ]
            for seg in rogue_list:
                L.append(f"    #      - {seg}")
            L.append("")

            L += [
                f"    - name: >-",
                f"        Patch '{entry['name']}'",
                f"        — remove {len(rogue_list)} out-of-state app segment ref(s)",
                f"      zscaler.zpacloud.zpa_policy_access_rule:",
                f"        provider:",
                f"          client_id:     \"{{{{ zpa_client_id }}}}\"",
                f"          client_secret: \"{{{{ zpa_client_secret }}}}\"",
                f"          customer_id:   \"{{{{ zpa_customer_id }}}}\"",
                f"          cloud:         \"{{{{ zpa_cloud }}}}\"",
            ]

            # Inline the module params as indented YAML
            params_yaml = _to_yaml_block(params, indent=8)
            L.append(params_yaml)

            if dry_run:
                L.append("      check_mode: true")

            L += [
                f"      register: patch_{var_suffix}",
                "",
                f"    - name: \"Show result | '{entry['name']}'\"",
                "      ansible.builtin.debug:",
                f"        var: patch_{var_suffix}",
                f"      when: patch_{var_suffix} is defined",
                "",
            ]

    # =========================================================================
    # Play 2 — Delete rogue policy access rules
    # =========================================================================
    if has_rule_deletes:
        play_number += 1
        L += [
            "# " + "-" * 77,
            f"# Play {play_number} — Delete policy access rules not in Terraform state",
            "# " + "-" * 77,
            f"- name: \"[Play {play_number}] ZPA Cleanup | Delete rogue policy access rules\"",
            "  hosts: localhost",
            "  connection: local",
            "  gather_facts: false",
            "",
            "  vars:",
            f'    zpa_cloud: "{zpa_cloud}"',
            '    zpa_client_id:     "{{ lookup(\'env\', \'ZPA_CLIENT_ID\') }}"',
            '    zpa_client_secret: "{{ lookup(\'env\', \'ZPA_CLIENT_SECRET\') }}"',
            '    zpa_customer_id:   "{{ lookup(\'env\', \'ZPA_CUSTOMER_ID\') }}"',
            "",
            "    # Policy rules to delete (exist in ZPA, absent from TF state)",
            "    rogue_policy_rules:",
        ]
        for entry in plan.rogue_policy_rules:
            L.append(f'      - name: "{entry["name"]}"')
            if entry["id"]:
                L.append(f'        id:   "{entry["id"]}"')
        L += [
            "",
            "  tasks:",
            "",
            "    - name: \"Delete rogue policy rule '{{ item.name }}'\"",
            "      zscaler.zpacloud.zpa_policy_access_rule:",
            "        provider:",
            '          client_id:     "{{ zpa_client_id }}"',
            '          client_secret: "{{ zpa_client_secret }}"',
            '          customer_id:   "{{ zpa_customer_id }}"',
            '          cloud:         "{{ zpa_cloud }}"',
            "        state: absent",
            '        name:  "{{ item.name }}"',
        ]
        if dry_run:
            L.append("      check_mode: true")
        L += [
            "      loop: \"{{ rogue_policy_rules }}\"",
            "      loop_control:",
            "        label: \"{{ item.name }}\"",
            "      register: rule_delete_results",
            "",
            "    - name: Summarise policy rule deletions",
            "      ansible.builtin.debug:",
            "        msg: >-",
            "          Rule '{{ item.item.name }}'",
            "          changed={{ item.changed }}",
            "          failed={{ item.failed }}",
            '      loop: "{{ rule_delete_results.results }}"',
            "      loop_control:",
            "        label: \"{{ item.item.name }}\"",
            "      when: rule_delete_results.results is defined",
            "",
        ]

    # =========================================================================
    # Play 3 — Delete rogue application segments
    # =========================================================================
    if has_seg_deletes:
        play_number += 1
        L += [
            "# " + "-" * 77,
            f"# Play {play_number} — Delete application segments not in Terraform state",
            "# " + "-" * 77,
            f"- name: \"[Play {play_number}] ZPA Cleanup | Delete rogue application segments\"",
            "  hosts: localhost",
            "  connection: local",
            "  gather_facts: false",
            "",
            "  vars:",
            f'    zpa_cloud: "{zpa_cloud}"',
            '    zpa_client_id:     "{{ lookup(\'env\', \'ZPA_CLIENT_ID\') }}"',
            '    zpa_client_secret: "{{ lookup(\'env\', \'ZPA_CLIENT_SECRET\') }}"',
            '    zpa_customer_id:   "{{ lookup(\'env\', \'ZPA_CUSTOMER_ID\') }}"',
            "",
            "    # Application segments to delete (exist in ZPA, absent from TF state)",
            "    rogue_app_segments:",
        ]
        for entry in plan.rogue_app_segments:
            L.append(f'      - name: "{entry["name"]}"')
            if entry["id"]:
                L.append(f'        id:   "{entry["id"]}"')
        L += [
            "",
            "  tasks:",
            "",
            "    - name: \"Delete rogue app segment '{{ item.name }}'\"",
            "      zscaler.zpacloud.zpa_application_segment:",
            "        provider:",
            '          client_id:     "{{ zpa_client_id }}"',
            '          client_secret: "{{ zpa_client_secret }}"',
            '          customer_id:   "{{ zpa_customer_id }}"',
            '          cloud:         "{{ zpa_cloud }}"',
            "        state: absent",
            '        name:  "{{ item.name }}"',
        ]
        if dry_run:
            L.append("      check_mode: true")
        L += [
            "      loop: \"{{ rogue_app_segments }}\"",
            "      loop_control:",
            "        label: \"{{ item.name }}\"",
            "      register: seg_delete_results",
            "",
            "    - name: Summarise application segment deletions",
            "      ansible.builtin.debug:",
            "        msg: >-",
            "          Segment '{{ item.item.name }}'",
            "          changed={{ item.changed }}",
            "          failed={{ item.failed }}",
            '      loop: "{{ seg_delete_results.results }}"',
            "      loop_control:",
            "        label: \"{{ item.item.name }}\"",
            "      when: seg_delete_results.results is defined",
            "",
        ]

    # ── Nothing to do ─────────────────────────────────────────────────────────
    if not has_patches and not has_rule_deletes and not has_seg_deletes:
        L += [
            "# No rogue resources were found — no cleanup actions required.",
            "",
            "- name: ZPA Cleanup | Nothing to do",
            "  hosts: localhost",
            "  gather_facts: false",
            "  tasks:",
            "    - name: Report clean state",
            "      ansible.builtin.debug:",
            "        msg: >-",
            "          No rogue resources detected.",
            "          ZPA is consistent with the Terraform state file.",
            "",
        ]

    return "\n".join(L) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_LABELS = {
    "server_groups":  "Server Groups",
    "segment_groups": "Segment Groups",
    "app_segments":   "Application Segments",
    "policy_rules":   "Policy Access Rules",
}

ANSIBLE_HINT_KEYS = {
    "server_groups":  "serverGroups",
    "segment_groups": "segmentGroups",
    "app_segments":   "appSegments",
    "policy_rules":   "policyRules",
}


def _hr(char: str = "─", width: int = 72) -> str:
    return char * width


def build_text_report(
    results:   dict[str, CategoryResult],
    tf_counts: dict[str, int],
    ans_counts: dict[str, int],
    plan:      "CleanupPlan | None" = None,
) -> str:
    lines: list[str] = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append(_hr("═"))
    lines.append(f"  ZPA Terraform <-> Ansible Comparison Report   [{ts}]")
    lines.append(_hr("═"))
    lines.append("")

    # Summary table
    lines.append("SUMMARY")
    lines.append(_hr())
    lines.append(
        f"{'Category':<28} {'TF':>5} {'ZPA':>5} "
        f"{'Only TF':>8} {'Only ZPA':>9} {'Drifted':>8}"
    )
    lines.append(_hr("-"))

    total_only_tf = total_only_zpa = total_drift = 0
    for cat, label in CATEGORY_LABELS.items():
        r   = results[cat]
        ot  = len(r["only_in_tf"])
        oz  = len(r["only_in_zpa"])
        dr  = len(r["drift"])
        total_only_tf  += ot
        total_only_zpa += oz
        total_drift    += dr
        lines.append(
            f"{label:<28} {tf_counts[cat]:>5} {ans_counts[cat]:>5} "
            f"{ot:>8} {oz:>9} {dr:>8}"
        )

    lines.append(_hr("-"))
    lines.append(
        f"{'TOTAL':<28} {sum(tf_counts.values()):>5} "
        f"{sum(ans_counts.values()):>5} "
        f"{total_only_tf:>8} {total_only_zpa:>9} {total_drift:>8}"
    )
    lines.append("")

    # Per-category detail
    for cat, label in CATEGORY_LABELS.items():
        r = results[cat]
        lines.append(_hr("═"))
        lines.append(f"  {label.upper()}")
        lines.append(_hr("═"))

        if r["only_in_tf"]:
            lines.append(f"\n  > In Terraform only ({len(r['only_in_tf'])}):")
            for name in r["only_in_tf"]:
                lines.append(f"      - {name}")

        if r["only_in_zpa"]:
            lines.append(f"\n  > In ZPA/Ansible only ({len(r['only_in_zpa'])}):")
            for name in r["only_in_zpa"]:
                lines.append(f"      - {name}")

        if r["drift"]:
            lines.append(f"\n  > Field-level drift ({len(r['drift'])} resource(s)):")
            for name, diffs in r["drift"].items():
                lines.append(f"\n    [{name}]")
                for d in diffs:
                    lines.append(f"      Field : {d['field']}")
                    lines.append(f"        TF  : {d['tf']}")
                    lines.append(f"        ZPA : {d['zpa']}")

        if not r["only_in_tf"] and not r["only_in_zpa"] and not r["drift"]:
            lines.append("\n  No differences found.")

        lines.append("")

    # Cleanup plan summary
    if plan is not None:
        lines.append(_hr("═"))
        lines.append("  CLEANUP PLAN SUMMARY")
        lines.append(_hr("═"))

        if plan.rules_needing_patch:
            lines.append(
                f"\n  > Policy rules to PATCH "
                f"(remove rogue app-segment refs): {len(plan.rules_needing_patch)}"
            )
            for entry in plan.rules_needing_patch:
                lines.append(f"      Rule : {entry['name']}  (id: {entry['id'] or 'unknown'})")
                for seg in sorted(entry["rogue_segments"]):
                    lines.append(f"        remove: {seg}")

        if plan.rogue_policy_rules:
            lines.append(
                f"\n  > Policy rules to DELETE "
                f"(not in TF state): {len(plan.rogue_policy_rules)}"
            )
            for entry in plan.rogue_policy_rules:
                lines.append(f"      - {entry['name']}  (id: {entry['id'] or 'unknown'})")

        if plan.rogue_app_segments:
            lines.append(
                f"\n  > Application segments to DELETE "
                f"(not in TF state): {len(plan.rogue_app_segments)}"
            )
            for entry in plan.rogue_app_segments:
                lines.append(f"      - {entry['name']}  (id: {entry['id'] or 'unknown'})")

        if (not plan.rules_needing_patch
                and not plan.rogue_policy_rules
                and not plan.rogue_app_segments):
            lines.append("\n  No cleanup actions required.")

        lines.append("")

    lines.append(_hr("═"))
    lines.append("  End of report")
    lines.append(_hr("═"))
    return "\n".join(lines)


def build_json_report(
    results:    dict[str, CategoryResult],
    tf_counts:  dict[str, int],
    ans_counts: dict[str, int],
    plan:       "CleanupPlan | None" = None,
) -> str:
    output: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            cat: {
                "tf_count":    tf_counts[cat],
                "zpa_count":   ans_counts[cat],
                "only_in_tf":  len(results[cat]["only_in_tf"]),
                "only_in_zpa": len(results[cat]["only_in_zpa"]),
                "drifted":     len(results[cat]["drift"]),
            }
            for cat in CATEGORY_LABELS
        },
        "details": {
            cat: {
                "only_in_tf":  results[cat]["only_in_tf"],
                "only_in_zpa": results[cat]["only_in_zpa"],
                "drift": {
                    name: diffs
                    for name, diffs in results[cat]["drift"].items()
                },
            }
            for cat in CATEGORY_LABELS
        },
    }

    if plan is not None:
        output["cleanup_plan"] = {
            "rules_to_patch": [
                {
                    "name":           e["name"],
                    "id":             e["id"],
                    "rogue_segments": sorted(e["rogue_segments"]),
                }
                for e in plan.rules_needing_patch
            ],
            "policy_rules_to_delete": [
                {"name": e["name"], "id": e["id"]}
                for e in plan.rogue_policy_rules
            ],
            "app_segments_to_delete": [
                {"name": e["name"], "id": e["id"]}
                for e in plan.rogue_app_segments
            ],
        }

    return json.dumps(output, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=textwrap.dedent("""\
            Compare a Terraform state file against ZPA Ansible bulk-download
            exports for server groups, segment groups, application segments,
            and policy access rules.

            Optionally generates an Ansible playbook (--playbook) to clean up
            resources that exist in ZPA but were created outside of Terraform,
            enabling a conflict-free 'terraform apply'.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    grp_in = p.add_argument_group("Input files")
    grp_in.add_argument(
        "--state", "-s", required=True, metavar="FILE",
        help="Path to terraform.tfstate (JSON)",
    )
    grp_in.add_argument(
        "--server-groups", "-sg", metavar="FILE_OR_GLOB", default=None,
        help="Ansible export for Server Groups (YAML or JSON)",
    )
    grp_in.add_argument(
        "--segment-groups", "-segg", metavar="FILE_OR_GLOB", default=None,
        help="Ansible export for Segment Groups (YAML or JSON)",
    )
    grp_in.add_argument(
        "--app-segments", "-as", metavar="FILE_OR_GLOB", default=None,
        help="Ansible export for Application Segments (YAML or JSON)",
    )
    grp_in.add_argument(
        "--policy-rules", "-pr", metavar="FILE_OR_GLOB", default=None,
        help="Ansible export for Policy Access Rules (YAML or JSON)",
    )

    grp_rpt = p.add_argument_group("Report output")
    grp_rpt.add_argument(
        "--output", "-o", metavar="FILE", default=None,
        help="Write comparison report to this file (default: stdout)",
    )
    grp_rpt.add_argument(
        "--format", "-f", choices=["text", "json"], default="text",
        help="Report format: text (default) or json",
    )
    grp_rpt.add_argument(
        "--ignore-fields", "-i", metavar="FIELDS", default="",
        help="Comma-separated field names to exclude from comparison",
    )

    grp_pb = p.add_argument_group("Playbook generation")
    grp_pb.add_argument(
        "--playbook", "-p", metavar="FILE", default=None,
        help=(
            "Generate an Ansible cleanup playbook and write it to FILE. "
            "The playbook (in safe dependency order): "
            "(1) patches TF-managed rules to strip rogue app-segment refs, "
            "(2) deletes rogue policy access rules, "
            "(3) deletes rogue application segments."
        ),
    )
    grp_pb.add_argument(
        "--zpa-cloud", metavar="CLOUD", default="PRODUCTION",
        choices=["PRODUCTION", "BETA", "GOV", "PREVIEW"],
        help="ZPA cloud environment written into the playbook (default: PRODUCTION)",
    )
    grp_pb.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Add 'check_mode: true' to every task in the generated playbook "
            "so it previews changes without touching ZPA."
        ),
    )

    p.add_argument("--no-color", action="store_true", help="Disable colour output")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    global _HAS_COLOR
    if args.no_color:
        _HAS_COLOR = False

    ignore_fields: set[str] = {
        f.strip() for f in args.ignore_fields.split(",") if f.strip()
    }

    # ── Load Terraform state ──────────────────────────────────────────────────
    print(_c(f"Loading Terraform state: {args.state}", "cyan"), file=sys.stderr)
    tf_data = parse_tf_state(args.state)
    tf_counts = {cat: len(v) for cat, v in tf_data.items()}
    for cat, label in CATEGORY_LABELS.items():
        print(
            _c(f"  {label}: {tf_counts[cat]} resource(s) in state", "cyan"),
            file=sys.stderr,
        )

    # ── Load Ansible exports ──────────────────────────────────────────────────
    category_file_args = {
        "server_groups":  args.server_groups,
        "segment_groups": args.segment_groups,
        "app_segments":   args.app_segments,
        "policy_rules":   args.policy_rules,
    }
    ans_data:   dict[str, dict[str, dict]] = {}
    ans_counts: dict[str, int]             = {}

    for cat, file_arg in category_file_args.items():
        if file_arg is None:
            print(
                _c(
                    f"  WARNING: No export provided for {CATEGORY_LABELS[cat]} — skipping.",
                    "yellow",
                ),
                file=sys.stderr,
            )
            ans_data[cat]   = {}
            ans_counts[cat] = 0
            continue
        paths = _expand_paths(file_arg)
        print(
            _c(f"Loading {CATEGORY_LABELS[cat]}: {', '.join(paths)}", "cyan"),
            file=sys.stderr,
        )
        records = parse_ansible_export(paths, hint_key=ANSIBLE_HINT_KEYS[cat])
        ans_data[cat]   = records
        ans_counts[cat] = len(records)
        print(
            _c(f"  {CATEGORY_LABELS[cat]}: {ans_counts[cat]} record(s)", "cyan"),
            file=sys.stderr,
        )

    # ── Compare ───────────────────────────────────────────────────────────────
    print(_c("\nRunning comparison ...", "cyan"), file=sys.stderr)
    results: dict[str, CategoryResult] = {
        cat: compare_category(tf_data[cat], ans_data[cat], ignore_fields)
        for cat in CATEGORY_LABELS
    }

    # ── Build cleanup plan ────────────────────────────────────────────────────
    plan = build_cleanup_plan(tf_data, ans_data, results)
    total_actions = (
        len(plan.rules_needing_patch)
        + len(plan.rogue_policy_rules)
        + len(plan.rogue_app_segments)
    )
    colour = "yellow" if total_actions else "green"
    print(
        _c(
            f"\nCleanup plan: "
            f"{len(plan.rules_needing_patch)} rule(s) to patch | "
            f"{len(plan.rogue_policy_rules)} rule(s) to delete | "
            f"{len(plan.rogue_app_segments)} app segment(s) to delete",
            colour,
        ),
        file=sys.stderr,
    )

    # ── Emit report ───────────────────────────────────────────────────────────
    if args.format == "json":
        report = build_json_report(results, tf_counts, ans_counts, plan=plan)
    else:
        report = build_text_report(results, tf_counts, ans_counts, plan=plan)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(_c(f"Report written to: {args.output}", "green"), file=sys.stderr)
    else:
        print(report)

    # ── Generate playbook ─────────────────────────────────────────────────────
    if args.playbook:
        if not _HAS_YAML:
            print(
                _c(
                    "WARNING: pyyaml not installed — conditions will be serialised "
                    "as JSON (still valid YAML). Install pyyaml for cleaner output.",
                    "yellow",
                ),
                file=sys.stderr,
            )

        pb_text = generate_playbook(plan, zpa_cloud=args.zpa_cloud, dry_run=args.dry_run)
        with open(args.playbook, "w", encoding="utf-8") as fh:
            fh.write(pb_text)

        mode_tag = " (check_mode / dry-run)" if args.dry_run else ""
        print(
            _c(f"Cleanup playbook written to: {args.playbook}{mode_tag}", "green"),
            file=sys.stderr,
        )

        if total_actions:
            print(
                _c(
                    "\nREVIEW the generated playbook before executing.\n"
                    "To preview without making changes:\n"
                    f"  ansible-playbook {args.playbook} --check",
                    "yellow",
                ),
                file=sys.stderr,
            )
        else:
            print(
                _c("Playbook contains no destructive actions — ZPA matches TF state.", "green"),
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
