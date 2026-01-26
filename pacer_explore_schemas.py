from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

EXPLORE_PACER_UI_IGNORE_KEYS: Set[str] = {
    "csrf_token",
    "submit",
    "submit_button",
}

EXPLORE_PACER_UI_FIELDS: Dict[str, Set[str]] = {
    "cases": {
        "mode",
        "search_mode",
        "court_id",
        "region_code",
        "date_filed_from",
        "date_filed_to",
        "page",
        "max_records",
        "case_types",
        "sort_field",
        "sort_order",
    },
    "parties": {
        "mode",
        "search_mode",
        "last_name",
        "exact_name_match",
        "first_name",
        "ssn",
        "date_filed_from",
        "date_filed_to",
        "court_id",
        "region_code",
        "page",
        "max_records",
        "sort_field",
        "sort_order",
    },
}

EXPLORE_PACER_PCL_FIELDS: Dict[str, Set[str]] = {
    "cases": {
        "courtId",
        "dateFiledFrom",
        "dateFiledTo",
        "caseType",
    },
    "parties": {
        "lastName",
        "exactNameMatch",
        "firstName",
        "ssn",
        "courtId",
        "dateFiledFrom",
        "dateFiledTo",
    },
}

EXPLORE_PACER_PCL_REQUIRED_FIELDS: Dict[str, Set[str]] = {
    "cases": {"courtId", "dateFiledFrom", "dateFiledTo"},
    "parties": {"lastName"},
}


def _is_ignored_ui_key(key: str) -> bool:
    return key in EXPLORE_PACER_UI_IGNORE_KEYS or key.startswith("submit")


def _clean_value(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return [item.strip() if isinstance(item, str) else item for item in value]
    return value


def collect_ui_inputs(
    form_data: Mapping[str, Iterable[str]],
    *,
    multi_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    multi_keys = multi_keys or set()
    for key, values in form_data.items():
        if key in multi_keys:
            payload[key] = _clean_value(list(values))
            continue
        if isinstance(values, list):
            payload[key] = _clean_value(values[0]) if values else ""
        else:
            payload[key] = _clean_value(values)
    return payload


def validate_ui_inputs(mode: str, ui_inputs: Mapping[str, Any]) -> List[str]:
    allowed = EXPLORE_PACER_UI_FIELDS.get(mode, set())
    unexpected = sorted(
        key
        for key in ui_inputs.keys()
        if key not in allowed and not _is_ignored_ui_key(key)
    )
    return unexpected


def build_case_search_payload(ui_inputs: Mapping[str, Any]) -> Dict[str, Any]:
    court_value = ui_inputs.get("court_id") or ui_inputs.get("region_code")
    body: Dict[str, Any] = {
        "dateFiledFrom": ui_inputs.get("date_filed_from"),
        "dateFiledTo": ui_inputs.get("date_filed_to"),
    }
    if court_value:
        body["courtId"] = [court_value]
    case_types = ui_inputs.get("case_types") or []
    if isinstance(case_types, list):
        case_types = [value for value in case_types if value]
    else:
        case_types = [case_types] if case_types else []
    if case_types:
        body["caseType"] = case_types
    return body


def build_party_search_payload(
    ui_inputs: Mapping[str, Any],
    *,
    include_date_range: bool = False,
) -> Dict[str, Any]:
    last_name = ui_inputs.get("last_name")
    body: Dict[str, Any] = {"lastName": last_name}
    exact_match = ui_inputs.get("exact_name_match")
    if exact_match is not None:
        if isinstance(exact_match, bool):
            body["exactNameMatch"] = exact_match
        else:
            body["exactNameMatch"] = str(exact_match).strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
    if ui_inputs.get("first_name"):
        body["firstName"] = ui_inputs.get("first_name")
    if ui_inputs.get("ssn"):
        body["ssn"] = ui_inputs.get("ssn")
    court_value = ui_inputs.get("court_id") or ui_inputs.get("region_code")
    if court_value:
        body["courtId"] = [court_value]
    if include_date_range:
        body["dateFiledFrom"] = ui_inputs.get("date_filed_from")
        body["dateFiledTo"] = ui_inputs.get("date_filed_to")
    return body


def validate_pcl_payload(mode: str, payload: Mapping[str, Any]) -> Tuple[bool, List[str], List[str]]:
    allowed = EXPLORE_PACER_PCL_FIELDS.get(mode, set())
    required = EXPLORE_PACER_PCL_REQUIRED_FIELDS.get(mode, set())
    invalid_keys = sorted(key for key in payload.keys() if key not in allowed)

    def _is_missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return not value.strip()
        if isinstance(value, list):
            return not any(item not in (None, "") for item in value)
        return False

    missing_keys = sorted(
        key for key in required if key not in payload or _is_missing(payload.get(key))
    )
    return (not invalid_keys and not missing_keys, invalid_keys, missing_keys)
