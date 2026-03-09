from __future__ import annotations

from typing import Any


REQUIRED_METADATA_FIELDS = ("verdict", "risk", "keyFinding", "commit", "ecosystem")
ALLOWED_VERDICTS = {"approve", "conditional", "reject"}
ALLOWED_RISKS = {"low", "medium", "high"}


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _normalize_scores(raw_scores: Any) -> dict[str, int]:
    scores = raw_scores if isinstance(raw_scores, dict) else {}
    normalized = {}
    for key in ("supplyChain", "runtimeSafety", "maintainability", "overall"):
        score = _coerce_int(scores.get(key), -1)
        if score < 0:
            continue
        normalized[key] = max(0, min(100, score))
    return normalized


def normalize_metadata(args: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_METADATA_FIELDS if not args.get(field)]
    if missing:
        raise ValueError(f"Missing required metadata fields: {', '.join(missing)}")

    verdict = str(args["verdict"]).strip().lower()
    if verdict not in ALLOWED_VERDICTS:
        raise ValueError(f"Invalid verdict: {verdict}")

    risk = str(args["risk"]).strip().lower()
    if risk not in ALLOWED_RISKS:
        raise ValueError(f"Invalid risk: {risk}")

    key_finding = str(args["keyFinding"]).strip()
    if not key_finding:
        raise ValueError("keyFinding cannot be empty")

    commit = str(args["commit"]).strip()
    ecosystem = str(args["ecosystem"]).strip()
    created = str(args.get("created", "unknown")).strip() or "unknown"
    license_name = str(args.get("license", "unknown")).strip() or "unknown"

    approval_conditions = args.get("approvalConditions", [])
    if not isinstance(approval_conditions, list):
        approval_conditions = []
    approval_conditions = [str(item).strip() for item in approval_conditions if str(item).strip()]

    scores = _normalize_scores(args.get("scores"))
    stats = {
        "stars": f"{_coerce_int(args.get('stars'), 0):,}",
        "forks": f"{_coerce_int(args.get('forks'), 0):,}",
        "contributors": f"{_coerce_int(args.get('contributors'), 0):,}",
        "openIssues": _coerce_int(args.get("openIssues"), 0),
        "created": created,
        "license": license_name,
        "hasSecurityMd": _coerce_bool(args.get("hasSecurityMd", False)),
    }

    badges: list[dict[str, str]] = [
        {"group": "risk", "label": "Risk", "value": risk.upper()},
        {"group": "verdict", "label": "Verdict", "value": verdict.upper()},
        {"group": "ecosystem", "label": "Ecosystem", "value": ecosystem},
    ]
    if scores.get("overall") is not None:
        badges.append(
            {"group": "score", "label": "Overall Score", "value": str(scores["overall"])}
        )

    return {
        "verdict": verdict,
        "risk": risk,
        "keyFinding": key_finding[:500],
        "commit": commit,
        "ecosystem": ecosystem,
        "stats": stats,
        "approvalConditions": approval_conditions,
        "scores": scores,
        "badges": badges,
    }


def build_report(
    *,
    job: dict[str, Any],
    markdown_content: str,
    analyzed_date: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    report = {
        "id": job["id"],
        "url": job["url"],
        "owner": job["owner"],
        "repo": job["repo"],
        "analyzed": analyzed_date,
        "format": "markdown",
        "content": markdown_content,
    }
    report.update(metadata)
    return report


def validate_markdown_report(report: dict[str, Any]) -> None:
    required_string_fields = (
        "id",
        "url",
        "owner",
        "repo",
        "analyzed",
        "format",
        "content",
        "verdict",
        "risk",
        "keyFinding",
        "commit",
        "ecosystem",
    )
    for field in required_string_fields:
        value = report.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid report field: {field}")

    if report["format"] != "markdown":
        raise ValueError("Report format must be markdown")

    if report["verdict"] not in ALLOWED_VERDICTS:
        raise ValueError("Invalid verdict")
    if report["risk"] not in ALLOWED_RISKS:
        raise ValueError("Invalid risk")

    if not isinstance(report.get("stats"), dict):
        raise ValueError("Report stats must be an object")
    if not isinstance(report.get("approvalConditions", []), list):
        raise ValueError("approvalConditions must be an array")
    if not isinstance(report.get("scores", {}), dict):
        raise ValueError("scores must be an object")
