"""Expose native error categories without copying free-form session content."""

from core import GovernanceError, require
from evidence import artifact_record


CATEGORIES = {
    "model_not_supported_error": ("model_unavailable", "Select an explicitly supported model and compile the workflow before a manual retry."),
    "missing_model_pricing_error": ("model_pricing_unavailable", "Select a model with known native pricing before another request."),
    "inference_access_error": ("inference_access_denied", "Read the organization inference policy and the run diagnostics."),
    "authentication_failed": ("authentication_failed", "Correct the inference credentials before another request."),
    "capi_quota_exceeded_error": ("provider_quota_exhausted", "Read the organization usage and budget before another request."),
    "max_ai_credits_exceeded": ("review_budget_exhausted", "Read the native usage before authorizing a different review limit."),
    "invocation_cap_exceeded": ("request_limit_exhausted", "Read the native request count and review progress."),
    "max_cache_misses_exceeded": ("context_cache_limit", "Read the context and cache metrics before another request."),
    "agentic_engine_timeout": ("review_timeout", "Read the last request outcome before authorizing another review."),
    "capi_server_error": ("provider_server_error", "Reconcile the request outcome before authorizing another review."),
    "http_400_response_error": ("provider_protocol_error", "Read the native error codes and correct the request protocol."),
}


def native_error_diagnostic(api, repository, run):
    try:
        rows = artifact_record(api, repository, run, "agent", "agent-errors.jsonl", json_lines=True)
        require(isinstance(rows, list), "invalid_native_error_record")
        records = [r["data"] for r in rows if isinstance(r, dict) and r.get("type") == "agent.execution"
                   and isinstance(r.get("data"), dict)]
        require(records and all(isinstance(r.get(key, []), list) for r in records for key in ("categories", "errorCodes")),
                "invalid_native_error_record")
        categories = {c for r in records for c in r.get("categories", []) if isinstance(c, str) and c in CATEGORIES}
        codes = {c for r in records for c in r.get("errorCodes", []) if type(c) is int and 100 <= c <= 599}
        result = {"native_diagnostics": "available", "native_categories": sorted(categories), "http_codes": sorted(codes)}
        if categories:
            name = next(c for c in CATEGORIES if c in categories)
            category, detail = CATEGORIES[name]
            result.update(category=category, detail=detail)
        else:
            result.update(category="unclassified_native_failure",
                          detail="Read the native run diagnostics. The available structured record does not identify a precise cause.")
        return result
    except GovernanceError as error:
        return {"native_diagnostics": "unavailable", "diagnostic_code": error.code,
                "detail": "Read the failed native steps. The structured error artifact is missing or unreadable."}
