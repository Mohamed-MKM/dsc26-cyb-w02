"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked" (each a list of
objects with the dataclass fields, for example {"ref": "f01", "category": "T"}).
Exit code 2 if the file cannot be loaded, 1 if there are any issues, gaps or policy findings,
otherwise 0. If there are structural issues you may leave "gaps" and "policy" empty.
"""
import sys
import json
from dataclasses import asdict

from tmcheck.core import (
    ModelError,
    coverage_gaps,
    load_model,
    policy_findings,
    rank,
    validate,
)

def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]
    try:
        model = load_model(path)
    except ModelError as e:
        print(f"Error loading model: {e}", file=sys.stderr)
        return 2

    issues = policy_findings(model)
    gaps = coverage_gaps(model)
    ranked = rank(model)

    result = {
        "issues": [asdict(issue) for issue in issues],
        "gaps": [asdict(gap) for gap in gaps],
        "policy": [asdict(finding) for finding in policy_findings(model)],
        "ranked": [asdict(threat) for threat in ranked],
    }

    print(json.dumps(result))

    if issues or gaps or ranked:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
