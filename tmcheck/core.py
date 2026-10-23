"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"

SECTIONS = ("zones", "elements", "flows", "threats")
STRIDE_ORDER = {c: i for i, c in enumerate("STRIDE")}
CATEGORIES = set("STRIDE")
KINDS = {"external_entity", "process", "data_store"}
SECURE_PROTOCOLS = {"https", "tls", "mtls", "sftp", "ssh"} 

def _items(model: dict, section: str) -> list:
    value = model.get(section, [])
    return value if isinstance(value, list) else []


def _id_map(items: list) -> dict:
    result = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        ident = item.get("id")
        if isinstance(ident, str) and ident and ident not in result:
            result[ident] = item
    return result


def _score_valid(value) -> bool:
    return type(value) is int and 1 <= value <= 5

def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        with open(path, "r", encoding="utf-8") as stream:
            model = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ModelError(f"cannot load model: {exc}") from exc

    if not isinstance(model, dict):
        raise ModelError("top-level YAML value must be a mapping")

    for section in SECTIONS:
        if model.get(section) is None:
            model[section] = []
        elif not isinstance(model[section], list):
            raise ModelError(f"{section} must be a list")

    return model
    
   


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
   
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set("STRIDE")
    if kind == "data_flow":
        return {"T", "I", "D"}
    if kind == "data_store":
        categories = {"T", "I", "D"}
        if is_log:
            categories.add("R")
        return categories
    raise ValueError(f"unknown element kind: {kind!r}")
    


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = set()
    sections = {name: _items(model, name) for name in SECTIONS}

    seen = set()
    for section in SECTIONS:
        for item in sections[section]:
            if not isinstance(item, dict):
                continue
            ident = item.get("id")
            if isinstance(ident, str) and ident:
                if ident in seen:
                    issues.add(Issue(
                        ident, "DUPLICATE_ID", f"duplicate id {ident!r}"
                    ))
                seen.add(ident)

    zones = _id_map(sections["zones"])
    elements = _id_map(sections["elements"])
    flows = _id_map(sections["flows"])
    targets = {**elements, **flows}

    for element in sections["elements"]:
        if not isinstance(element, dict):
            continue

        ref = str(element.get("id", ""))
        kind = element.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            issues.add(Issue(
                ref, "BAD_KIND", f"unsupported element kind {kind!r}"
            ))

        zone = element.get("zone")
        if not isinstance(zone, str) or zone not in zones:
            issues.add(Issue(
                ref, "UNKNOWN_ZONE", f"unknown zone {zone!r}"
            ))

    # Flow validation.
    for flow in sections["flows"]:
        if not isinstance(flow, dict):
            continue

        ref = str(flow.get("id", ""))
        source = flow.get("source")
        target = flow.get("target")
        source_element = elements.get(source) if isinstance(source, str) else None
        target_element = elements.get(target) if isinstance(target, str) else None

        if source_element is None:
            issues.add(Issue(
                ref, "UNKNOWN_REF", f"unknown flow source {source!r}"
            ))
        if target_element is None:
            issues.add(Issue(
                ref, "UNKNOWN_REF", f"unknown flow target {target!r}"
            ))

        if source_element is not None and target_element is not None:
            source_kind = source_element.get("kind")
            target_kind = target_element.get("kind")

            if (
                source == target
                or (
                    source_kind != "process"
                    and target_kind != "process"
                )
            ):
                issues.add(Issue(
                    ref,
                    "INVALID_FLOW",
                    "flow must not be a self-loop and must connect to a process",
                ))

    for threat in sections["threats"]:
        if not isinstance(threat, dict):
            continue

        ref = str(threat.get("id", ""))
        target = threat.get("target")
        target_item = targets.get(target) if isinstance(target, str) else None

        if target_item is None:
            issues.add(Issue(
                ref, "UNKNOWN_REF", f"unknown threat target {target!r}"
            ))

        category = threat.get("category")
        if not isinstance(category, str) or category not in CATEGORIES:
            issues.add(Issue(
                ref, "BAD_CATEGORY", f"invalid STRIDE category {category!r}"
            ))
        elif target_item is not None:
            kind = "data_flow" if target in flows else target_item.get("kind")

            if kind in KINDS or kind == "data_flow":
                is_log = (
                    target_item.get("is_log") is True
                    if kind == "data_store"
                    else False
                )
                if category not in applicable(kind, is_log=is_log):
                    issues.add(Issue(
                        ref,
                        "INAPPLICABLE_CATEGORY",
                        f"category {category} does not apply to "
                        f"{kind} target {target!r}",
                    ))

        for field in ("likelihood", "impact"):
            if not _score_valid(threat.get(field)):
                issues.add(Issue(
                    ref, "BAD_SCORE",
                    f"{field} must be an integer from 1 to 5",
                ))

        status = threat.get("status")
        if not isinstance(status, str) or status not in {
            "open", "mitigated", "accepted"
        }:
            issues.add(Issue(
                ref, "BAD_STATUS", f"invalid status {status!r}"
            ))
        elif status == "mitigated":
            mitigation = threat.get("mitigation")
            if not isinstance(mitigation, str) or not mitigation.strip():
                issues.add(Issue(
                    ref, "MISSING_MITIGATION",
                    "mitigated threats require a non-empty mitigation",
                ))
        elif status == "accepted":
            justification = threat.get("justification")
            if not isinstance(justification, str) or not justification.strip():
                issues.add(Issue(
                    ref, "MISSING_JUSTIFICATION",
                    "accepted threats require a non-empty justification",
                ))

    return sorted(issues, key=lambda issue: (
        issue.ref, issue.code, issue.message
    ))


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elements = _id_map(_items(model, "elements"))
    zones = _id_map(_items(model, "zones"))
    result = []

    for flow in _items(model, "flows"):
        if not isinstance(flow, dict):
            continue

        source = flow.get("source")
        target = flow.get("target")
        source_element = elements.get(source) if isinstance(source, str) else None
        target_element = elements.get(target) if isinstance(target, str) else None

        if source_element is None or target_element is None:
            continue

        source_zone = source_element.get("zone")
        target_zone = target_element.get("zone")

        if (
            isinstance(source_zone, str)
            and isinstance(target_zone, str)
            and source_zone in zones
            and target_zone in zones
            and source_zone != target_zone
        ):
            result.append(str(flow.get("id", "")))

    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = _id_map(_items(model, "elements"))
    flows = _id_map(_items(model, "flows"))

    # Scope: crossing flows and both endpoint elements.
    scope = set(crossing_flows(model))
    for flow_id in list(scope):
        flow = flows.get(flow_id)
        if flow:
            source, target = flow.get("source"), flow.get("target")
            if isinstance(source, str):
                scope.add(source)
            if isinstance(target, str):
                scope.add(target)

    # A threat in any status counts as coverage.
    covered = {
        (threat.get("target"), threat.get("category"))
        for threat in _items(model, "threats")
        if isinstance(threat, dict)
    }

    gaps = []
    for ref in scope:
        if ref in flows:
            kind, is_log = "data_flow", False
        elif ref in elements:
            element = elements[ref]
            kind = element.get("kind")
            is_log = (
                element.get("is_log") is True
                if kind == "data_store"
                else False
            )
        else:
            continue

        if kind not in KINDS and kind != "data_flow":
            continue

        for category in applicable(kind, is_log=is_log):
            if (ref, category) not in covered:
                gaps.append(Gap(ref, category))

    return sorted(gaps, key=lambda gap: (
        gap.ref, STRIDE_ORDER[gap.category]
    ))



def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    elements = _id_map(_items(model, "elements"))
    zones = _id_map(_items(model, "zones"))
    flows = _id_map(_items(model, "flows"))
    threats = [
        threat for threat in _items(model, "threats")
        if isinstance(threat, dict)
    ]
    findings = set()

    for flow_id in crossing_flows(model):
        flow = flows.get(flow_id)
        if flow is None:
            continue

        protocol = flow.get("protocol")
        if (
            not isinstance(protocol, str)
            or protocol.lower() not in SECURE_PROTOCOLS
        ):
            findings.add(Issue(
                flow_id,
                "UNENCRYPTED_CROSSING",
                "cross-zone flow does not use an approved encrypted protocol",
            ))

        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))
        if source is None or target is None:
            continue

        source_zone = zones.get(source.get("zone"))
        target_zone = zones.get(target.get("zone"))
        if source_zone is None or target_zone is None:
            continue

        source_trust = source_zone.get("trust")
        target_trust = target_zone.get("trust")

        if (
            type(source_trust) in (int, float)
            and type(target_trust) in (int, float)
            and target_trust > source_trust
            and flow.get("authenticated") is not True
        ):
            findings.add(Issue(
                flow_id,
                "UNAUTHENTICATED_INBOUND",
                "flow enters a higher-trust zone without authentication",
            ))

    for element_id, element in elements.items():
        if (
            element.get("kind") == "data_store"
            and element.get("holds_pii") is True
        ):
            has_disclosure_threat = any(
                threat.get("target") == element_id
                and threat.get("category") == "I"
                for threat in threats
            )
            if not has_disclosure_threat:
                findings.add(Issue(
                    element_id,
                    "PII_STORE_WITHOUT_I_THREAT",
                    "PII data store has no information-disclosure threat",
                ))

    return sorted(findings, key=lambda issue: (issue.ref, issue.code))


def _natural_key(value: str):
    return tuple(
        int(part) if part.isdigit() else part.casefold()
        for part in re.split(r"(\d+)", value)
    )



def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    ranked = []

    for threat in _items(model, "threats"):
        if not isinstance(threat, dict) or threat.get("status") != "open":
            continue

        likelihood = threat.get("likelihood")
        impact = threat.get("impact")
        if not _score_valid(likelihood) or not _score_valid(impact):
            continue

        score = likelihood * impact
        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"

        ranked.append((
            RankedThreat(str(threat.get("id", "")), score, level),
            impact,
        ))

    ranked.sort(key=lambda pair: (
        -pair[0].score,
        -pair[1],
        _natural_key(pair[0].id),
    ))
    return [item for item, _impact in ranked]

