"""Generate a CrowdStrike Recon report of exposed passwords grouped by monitoring rule.

This script reads Falcon API credentials from environment variables or a local .env file,
retrieves Recon monitoring rules, notification details, and exposed data records, and prints
exposed-password findings grouped by monitoring rule.

To avoid CrowdStrike Recon's 10,000-row pagination ceiling, the script applies a date filter
to notification queries by default. Override it with command-line arguments if needed.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator


PAGE_SIZE = 500
BATCH_SIZE = 100
MAX_QUERY_WINDOW = 10_000
EXPOSED_RECORD_BATCH_SIZE = 100
DAY_OPTIONS = (1, 3, 7, 15, 30)
MIN_SEGMENT_WINDOW = timedelta(minutes=1)
FALCON_ENV_KEYS = (
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FALCON_BASE_URL",
)
DEFAULT_FALCON_BASE_URL = "https://api.eu-1.crowdstrike.com"

PASSWORD_KEYWORDS = {
    "password",
    "passwd",
    "passphrase",
    "cleartextpassword",
    "credentialpassword",
    "credentialsecret",
    "loginpassword",
    "plaintextpassword",
    "pwd",
    "secret",
}
PASSWORD_EXCLUDES = {
    "credentialstatus",
    "hash",
    "hashtype",
    "passwordhash",
    "passwordhistory",
    "passwordlastchanged",
}
USERNAME_KEYWORDS = {
    "account",
    "accountname",
    "email",
    "login",
    "loginid",
    "loginname",
    "screenname",
    "userid",
    "username",
    "userlogin",
    "usermail",
    "username",
}
USERNAME_EXCLUDES = {
    "assignedtouuid",
    "authorid",
    "useridhash",
    "uuid",
}


@dataclass
class Finding:
    rule_name: str
    rule_topic: str
    notification_id: str
    usernames: list[str]
    passwords: list[str]


@dataclass
class SelectedRule:
    rule_id: str
    rule_name: str


@dataclass
class RuleChoice:
    rule_id: str
    rule_name: str
    notification_count: str


class FalconAPIError(RuntimeError):
    """Raised when a Falcon API request fails."""


class RestartRequested(RuntimeError):
    """Raised when the user wants to restart the interactive flow."""


class QuitRequested(RuntimeError):
    """Raised when the user wants to quit the interactive flow."""


@dataclass
class DateWindow:
    start: datetime
    end: datetime


def clear_screen() -> None:
    print("\033[2J\033[H", end="")


def print_logo() -> None:
    logo = r"""
    ____                             ____                        __
   / __ \___  _________  ____       / __ \___  ____  ____  _____/ /_
  / /_/ / _ \/ ___/ __ \/ __ \     / /_/ / _ \/ __ \/ __ \/ ___/ __/
 / _, _/  __/ /__/ /_/ / / / /    / _, _/  __/ /_/ / /_/ / /  / /_
/_/ |_|\___/\___/\____/_/ /_/    /_/ |_|\___/ .___/\____/_/   \__/
                                           /_/
    """
    print(logo)
    print(f"Version 0.01a | {datetime.now().strftime('%d.%m.%Y')}")
    print("Query CrowdStrike Recon for exposed credential findings by monitoring rule.")
    print()


def is_recon_access_error(exc: FalconAPIError) -> bool:
    message = str(exc).lower()
    return any(token in message for token in ("status 401", "status 403", "forbidden", "unauthorized", "scope"))


def verify_recon_access(client: Any) -> None:
    status_message = "Running pre-flight access check..."
    print(f"[status] {status_message}", end="", flush=True)
    try:
        response = client.query_rules(limit=1, offset=0)
        ensure_success(response, "QueryRulesV1")
    except FalconAPIError as exc:
        print(f"\r\033[31m[status] {status_message} ERROR\033[0m")
        if is_recon_access_error(exc):
            raise RuntimeError(
                    "API client details might be incorrect, or API client does not have Recon read access.\n"
                    'Hint: "Support and resources" > "API clients and keys" > [API client] >\n'
                    '"Monitoring rules (Falcon Intelligence Recon)" > enable read scope\n'
                    "Please fix this and come back later."
            ) from exc
        raise
    print(f"\r[status] {status_message} done")
    print("[status] API client has access to CrowdStrike Recon... done")


def query_rule_ids(client: Any) -> list[str]:
    return run_with_spinner(
        "Getting list of monitoring rules...",
        paginate_query,
        client.query_rules,
        "QueryRulesV1",
    )


def print_status(message: str) -> None:
    print(f"[status] {message}")


def prompt_user(message: str) -> str:
    sys.stdout.write(message)
    sys.stdout.flush()
    response = input()
    print("------------------------------------------------------------------------")
    return response


class Spinner:
    def __init__(self, message: str):
        self.message = message
        self._frames = ("|", "/", "-", "\\")
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self) -> None:
        index = 0
        while not self._stop_event.is_set():
            frame = self._frames[index % len(self._frames)]
            print(f"\r[status] {self.message} {frame}", end="", flush=True)
            index += 1
            time.sleep(0.1)
        print(f"\r[status] {self.message} done", flush=True)

    def __enter__(self) -> "Spinner":
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._stop_event.set()
        self._thread.join()


def run_with_spinner(message: str, func: Any, *args: Any, **kwargs: Any) -> Any:
    with Spinner(message):
        return func(*args, **kwargs)


def read_dotenv_values(dotenv_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not dotenv_path.exists():
        return values

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value

    return values


def load_dotenv(dotenv_path: Path) -> None:
    """Populate missing environment variables from a .env file."""
    for key, value in read_dotenv_values(dotenv_path).items():
        if key and key not in os.environ:
            os.environ[key] = value


def write_dotenv_values(dotenv_path: Path, updates: dict[str, str]) -> None:
    lines = dotenv_path.read_text(encoding="utf-8").splitlines() if dotenv_path.exists() else []
    updated_keys: set[str] = set()
    output_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in line:
            key, _ = line.split("=", 1)
            key = key.strip()
            if key in updates:
                output_lines.append(f"{key}={updates[key]}")
                updated_keys.add(key)
                continue
        output_lines.append(line)

    for key in FALCON_ENV_KEYS:
        if key in updates and key not in updated_keys:
            output_lines.append(f"{key}={updates[key]}")

    content = "\n".join(output_lines)
    if output_lines:
        content += "\n"
    dotenv_path.write_text(content, encoding="utf-8")


def prompt_non_empty_value(name: str) -> str:
    while True:
        value = prompt_user(f"Enter {name}: ").strip()
        if value:
            return value
        print(f"{name} cannot be empty.")


def prompt_value_with_default(name: str, default: str) -> str:
    while True:
        value = prompt_user(f"Enter {name} [{default}]: ").strip()
        if value:
            return value
        if default:
            return default
        print(f"{name} cannot be empty.")


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    return "*" * (len(secret) - 4) + secret[-4:]


def prompt_falcon_credentials(dotenv_path: Path) -> None:
    dotenv_values = read_dotenv_values(dotenv_path)
    current_values = {
        key: dotenv_values.get(key) or os.environ.get(key, "")
        for key in FALCON_ENV_KEYS
    }

    print("Current API client details:")
    print(f"FALCON_CLIENT_ID: {current_values['FALCON_CLIENT_ID']}")
    print(f"FALCON_CLIENT_SECRET: {mask_secret(current_values['FALCON_CLIENT_SECRET'])}")
    print(f"FALCON_BASE_URL: {current_values['FALCON_BASE_URL']}")

    while True:
        response = prompt_user(
            "Would you like to update these credentials? [y/N]: "
        ).strip().lower()
        if response in {"", "n", "no"}:
            for key, value in current_values.items():
                if value:
                    os.environ[key] = value
            return
        if response in {"y", "yes", "update"}:
            new_values = {
                "FALCON_CLIENT_ID": prompt_non_empty_value("FALCON_CLIENT_ID"),
                "FALCON_CLIENT_SECRET": prompt_non_empty_value("FALCON_CLIENT_SECRET"),
                "FALCON_BASE_URL": prompt_value_with_default("FALCON_BASE_URL", DEFAULT_FALCON_BASE_URL),
            }
            write_dotenv_values(dotenv_path, new_values)
            for key, value in new_values.items():
                os.environ[key] = value
            return
        print("Invalid selection. Enter 'Y' to update these credentials or 'N' to keep them.")


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value

    raise RuntimeError(f"Missing required environment variable: {name}")


def build_client() -> Any:
    try:
        from falconpy import Recon
    except ImportError as exc:
        raise RuntimeError(
            "falconpy is not installed. Install dependencies with 'pip install -r requirements.txt'."
        ) from exc

    return Recon(
        client_id=require_env("FALCON_CLIENT_ID"),
        client_secret=require_env("FALCON_CLIENT_SECRET"),
        base_url=require_env("FALCON_BASE_URL"),
    )


def get_resources(response: dict[str, Any]) -> list[Any]:
    body = response.get("body", response)
    if isinstance(body, dict):
        resources = body.get("resources", [])
        if isinstance(resources, list):
            return resources
        if resources:
            return [resources]
        return []
    if isinstance(body, list):
        return body
    return []


def ensure_success(response: dict[str, Any], operation: str) -> None:
    status_code = int(response.get("status_code", 0) or 0)
    body = response.get("body", {})
    errors = []
    if isinstance(body, dict):
        errors = body.get("errors", []) or []

    if status_code and status_code < 400 and not errors:
        return

    message_parts = []
    for error in errors:
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            if code or message:
                message_parts.append(f"{code or 'error'}: {message or 'Unknown error'}")

    detail = "; ".join(message_parts) if message_parts else "No error details returned"
    raise FalconAPIError(f"{operation} failed with status {status_code or 'unknown'}: {detail}")


def chunked(values: Iterable[str], size: int) -> Iterator[list[str]]:
    batch: list[str] = []
    for value in values:
        batch.append(value)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def paginate_query(method: Any, operation: str, **query_kwargs: Any) -> list[str]:
    results, truncated = paginate_query_segment(method, operation, **query_kwargs)
    if truncated:
        print(
            f"Warning: {operation} reached the CrowdStrike pagination ceiling of {MAX_QUERY_WINDOW} results. "
            "Narrow the reporting window to avoid truncation.",
            file=sys.stderr,
        )

    return results


def paginate_query_segment(method: Any, operation: str, **query_kwargs: Any) -> tuple[list[str], bool]:
    results: list[str] = []
    offset = 0
    truncated = False

    while offset < MAX_QUERY_WINDOW:
        limit = min(PAGE_SIZE, MAX_QUERY_WINDOW - offset)
        response = method(limit=limit, offset=offset, **query_kwargs)
        ensure_success(response, operation)
        page = [str(item) for item in get_resources(response)]
        if not page:
            break

        results.extend(page)
        if len(page) < limit:
            break

        offset += limit

    if offset >= MAX_QUERY_WINDOW and len(results) >= MAX_QUERY_WINDOW:
        truncated = True

    return results, truncated


def count_notifications_for_rule(client: Any, rule_id: str) -> str:
    ids, truncated = paginate_query_segment(
        client.query_notifications,
        "QueryNotificationsV1",
        filter=build_rule_filter("rule_id", rule_id),
    )
    if truncated:
        return f"{MAX_QUERY_WINDOW}+"

    return str(len(ids))


def build_rule_choices(rules: list[dict[str, Any]], client: Any) -> list[RuleChoice]:
    choices: list[RuleChoice] = []
    for rule in sorted(rules, key=lambda item: entity_rule_name(item).lower()):
        rule_id = entity_rule_id(rule) or entity_id(rule)
        rule_name = entity_rule_name(rule)
        if not rule_id or not rule_name:
            continue
        choices.append(
            RuleChoice(
                rule_id=rule_id,
                rule_name=rule_name,
                notification_count=count_notifications_for_rule(client, rule_id),
            )
        )
    return choices


def fetch_entities(method: Any, ids: Iterable[str], operation: str) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []

    for batch in chunked(ids, BATCH_SIZE):
        response = method(ids=batch)
        ensure_success(response, operation)
        entities.extend(item for item in get_resources(response) if isinstance(item, dict))

    return entities


def first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
            continue
        if value:
            return str(value)
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report CrowdStrike Recon exposed passwords grouped by monitoring rule."
    )
    parser.add_argument(
        "--days",
        type=int,
        choices=DAY_OPTIONS,
        help="Look back this many days when querying notifications.",
    )
    return parser.parse_args()


def prompt_day_selection() -> int:
    print("Select a date filter:")
    for index, option in enumerate(DAY_OPTIONS, start=1):
        suffix = "day" if option == 1 else "days"
        print(f"{index}. Last {option} {suffix}")
    print("q. Quit")
    print("s. Start over")

    while True:
        selection = prompt_user("Choose 1, 2, 3, 4, or 5 [default 1]: ").strip()
        if not selection:
            return DAY_OPTIONS[0]
        lowered = selection.lower()
        if lowered == "q":
            raise QuitRequested()
        if lowered == "s":
            raise RestartRequested()
        if selection in {str(index) for index in range(1, len(DAY_OPTIONS) + 1)}:
            return DAY_OPTIONS[int(selection) - 1]
        print("Invalid selection. Choose 1, 2, 3, 4, or 5, or enter Q to quit or S to start over.")


def prompt_rule_selection(rule_choices: list[RuleChoice]) -> SelectedRule:
    if not rule_choices:
        raise RuntimeError(
            "Could not find Monitoring rules, please set them up first. "
            "(hint: Counter Adversary Operations > External Cyber Risk > Recon > Monitoring rules)"
        )

    selectable_rule_choices = [
        rule for rule in rule_choices if rule.notification_count.endswith("+") or int(rule.notification_count) > 1
    ]
    if not selectable_rule_choices:
        raise RuntimeError(
            "Monitoring rules were found, but none have more than one notification to report. "
            "Generate more notifications first, then run the tool again."
        )

    print("------------------------------------------------------------------------")
    print("Found monitoring rules:")
    for index, rule in enumerate(rule_choices, start=1):
        selectable = rule.notification_count.endswith("+") or int(rule.notification_count) > 1
        suffix = "" if selectable else " [not selectable]"
        print(f"{index}. {rule.rule_name} ({rule.notification_count}){suffix}")
    print("q. Quit")
    print("s. Start over")

    while True:
        selection = prompt_user("Choose a rule number: ").strip()
        lowered = selection.lower()
        if lowered == "q":
            raise QuitRequested()
        if lowered == "s":
            raise RestartRequested()
        if selection.isdigit():
            selected_index = int(selection)
            if 1 <= selected_index <= len(rule_choices):
                selected_rule = rule_choices[selected_index - 1]
                selectable = selected_rule.notification_count.endswith("+") or int(selected_rule.notification_count) > 1
                if not selectable:
                    print("That monitoring rule is not selectable because it has fewer than two notifications.")
                    continue
                return SelectedRule(rule_id=selected_rule.rule_id, rule_name=selected_rule.rule_name)
        print(
            f"Invalid selection. Choose a number from 1 to {len(rule_choices)}, "
            "or enter Q to quit or S to start over."
        )


def build_date_window(days: int) -> DateWindow:
    if days not in DAY_OPTIONS:
        raise RuntimeError(f"--days must be one of: {', '.join(str(option) for option in DAY_OPTIONS)}")

    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    return DateWindow(start=start, end=end)


def format_fql_datetime(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_display_datetime(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%d.%m.%Y %H:%M:%S UTC")


def join_filters(*clauses: str) -> str:
    return "+".join(clause for clause in clauses if clause)


def build_date_filter(field_name: str, window: DateWindow) -> str:
    start = format_fql_datetime(window.start)
    end = format_fql_datetime(window.end)
    return join_filters(f"{field_name}:>='{start}'", f"{field_name}:<='{end}'")


def build_rule_filter(field_name: str, rule_id: str) -> str:
    return f"{field_name}:'{rule_id}'"


def split_date_window(window: DateWindow) -> tuple[DateWindow, DateWindow]:
    midpoint = window.start + (window.end - window.start) / 2
    midpoint = midpoint.replace(microsecond=0)
    if midpoint <= window.start:
        midpoint = window.start + MIN_SEGMENT_WINDOW
    if midpoint >= window.end:
        midpoint = window.end - MIN_SEGMENT_WINDOW

    return (
        DateWindow(start=window.start, end=midpoint),
        DateWindow(start=midpoint, end=window.end),
    )


def build_date_filter_bounds(
    field_name: str,
    window: DateWindow,
    *,
    include_start: bool,
    include_end: bool,
) -> str:
    start_operator = ">=" if include_start else ">"
    end_operator = "<=" if include_end else "<"
    start = format_fql_datetime(window.start)
    end = format_fql_datetime(window.end)
    return join_filters(f"{field_name}:{start_operator}'{start}'", f"{field_name}:{end_operator}'{end}'")


def paginate_segmented_by_date(
    method: Any,
    operation: str,
    field_name: str,
    window: DateWindow,
    base_filter: str = "",
    skip_results: int = 0,
    max_results: int | None = None,
) -> list[str]:
    segments: list[tuple[DateWindow, bool, bool]] = [(window, True, True)]
    results: list[str] = []
    seen: set[str] = set()
    skipped = 0

    while segments:
        segment, include_start, include_end = segments.pop(0)
        segment_filter = build_date_filter_bounds(
            field_name,
            segment,
            include_start=include_start,
            include_end=include_end,
        )
        combined_filter = join_filters(base_filter, segment_filter)
        segment_results, truncated = paginate_query_segment(
            method,
            operation,
            filter=combined_filter or None,
        )

        if truncated:
            if segment.end - segment.start <= MIN_SEGMENT_WINDOW:
                print(
                    f"Warning: {operation} still exceeded {MAX_QUERY_WINDOW} results within a "
                    f"{int(MIN_SEGMENT_WINDOW.total_seconds() // 60)} minute window. Results may be truncated.",
                    file=sys.stderr,
                )
            else:
                left, right = split_date_window(segment)
                segments.insert(0, (right, True, include_end))
                segments.insert(0, (left, include_start, False))
                continue

        for item in segment_results:
            if item in seen:
                continue
            seen.add(item)
            if skipped < skip_results:
                skipped += 1
                continue
            results.append(item)
            if max_results is not None and len(results) >= max_results:
                return results

    return results


def notification_ids_from_records(records: list[dict[str, Any]]) -> list[str]:
    notification_ids = [record_notification_id(record) for record in records]
    return dedupe_preserve_order(notification_id for notification_id in notification_ids if notification_id)


def fetch_findings_batch(
    client: Any,
    rules: list[dict[str, Any]],
    selected_rule: SelectedRule,
    date_window: DateWindow,
    exposed_rule_filter: str,
    skip_results: int,
    max_results: int | None,
) -> tuple[list[Finding], int]:
    exposed_record_ids = run_with_spinner(
        "Querying exposed data records... (this may take a little while)",
        paginate_segmented_by_date,
        client.query_notifications_exposed_data_records,
        "QueryNotificationsExposedDataRecordsV1",
        "created_date",
        date_window,
        base_filter=exposed_rule_filter,
        skip_results=skip_results,
        max_results=max_results,
    )
    print_status(f"Loaded {len(exposed_record_ids)} exposed data record IDs.")

    records = (
        run_with_spinner(
            "Getting exposed data record details...",
            fetch_entities,
            client.get_notifications_exposed_data_records,
            exposed_record_ids,
            "GetNotificationsExposedDataRecordsV1",
        )
        if exposed_record_ids
        else []
    )
    print_status(f"Loaded {len(records)} exposed data records.")

    findings = run_with_spinner(
        "Building report output... this may take a while",
        build_findings,
        rules,
        selected_rule,
        records,
    )
    return findings, len(exposed_record_ids)


def get_nested(data: Any, *path: str) -> Any:
    current = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalize_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and not isinstance(value, bool)


def stringify(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def collect_field_values(node: Any, matcher: Any) -> list[str]:
    matches: list[str] = []

    if isinstance(node, dict):
        for key, value in node.items():
            normalized = normalize_key(str(key))
            if matcher(normalized):
                if isinstance(value, list):
                    for item in value:
                        if is_scalar(item):
                            text = stringify(item)
                            if text:
                                matches.append(text)
                elif is_scalar(value):
                    text = stringify(value)
                    if text:
                        matches.append(text)

            matches.extend(collect_field_values(value, matcher))
    elif isinstance(node, list):
        for item in node:
            matches.extend(collect_field_values(item, matcher))

    return matches


def collect_direct_field_values(node: dict[str, Any], matcher: Any) -> list[str]:
    matches: list[str] = []
    for key, value in node.items():
        normalized = normalize_key(str(key))
        if not matcher(normalized):
            continue

        if isinstance(value, list):
            for item in value:
                if is_scalar(item):
                    text = stringify(item)
                    if text:
                        matches.append(text)
        elif is_scalar(value):
            text = stringify(value)
            if text:
                matches.append(text)

    return matches


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
    return unique


def dedupe_pairs(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    return unique


def password_matcher(normalized_key: str) -> bool:
    if any(excluded in normalized_key for excluded in PASSWORD_EXCLUDES):
        return False
    return normalized_key in PASSWORD_KEYWORDS or normalized_key.endswith("password")


def username_matcher(normalized_key: str) -> bool:
    if normalized_key in USERNAME_EXCLUDES:
        return False
    return (
        normalized_key in USERNAME_KEYWORDS
        or normalized_key.endswith("username")
        or normalized_key.endswith("loginid")
        or normalized_key.endswith("email")
    )


def extract_credential_pairs(node: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []

    if isinstance(node, dict):
        usernames = dedupe_preserve_order(collect_direct_field_values(node, username_matcher))
        passwords = dedupe_preserve_order(collect_direct_field_values(node, password_matcher))

        if usernames and passwords:
            for username in usernames:
                for password in passwords:
                    pairs.append((username, password))

        for value in node.values():
            pairs.extend(extract_credential_pairs(value))
    elif isinstance(node, list):
        for item in node:
            pairs.extend(extract_credential_pairs(item))

    return dedupe_pairs(pairs)


def record_notification_id(record: dict[str, Any]) -> str:
    return first_non_empty(
        record.get("notification_id"),
        record.get("notificationId"),
        get_nested(record, "notification", "id"),
    )


def entity_rule_id(entity: dict[str, Any]) -> str:
    return first_non_empty(
        entity.get("rule_id"),
        entity.get("ruleId"),
        get_nested(entity, "rule", "id"),
    )


def entity_rule_name(entity: dict[str, Any]) -> str:
    return first_non_empty(
        entity.get("rule_name"),
        entity.get("ruleName"),
        get_nested(entity, "rule", "name"),
        entity.get("name"),
    )


def entity_rule_topic(entity: dict[str, Any]) -> str:
    return first_non_empty(
        entity.get("rule_topic"),
        entity.get("ruleTopic"),
        get_nested(entity, "rule", "topic"),
        entity.get("topic"),
    )


def entity_id(entity: dict[str, Any]) -> str:
    return first_non_empty(entity.get("id"), entity.get("notification_id"), entity.get("rule_id"))


def build_rule_lookup(rules: Iterable[dict[str, Any]]) -> dict[str, dict[str, str]]:
    lookup: dict[str, dict[str, str]] = {}
    for rule in rules:
        rule_id = entity_rule_id(rule) or entity_id(rule)
        if not rule_id:
            continue
        lookup[rule_id] = {
            "name": entity_rule_name(rule),
            "topic": entity_rule_topic(rule),
        }
    return lookup


def build_findings(
    rules: list[dict[str, Any]],
    selected_rule: SelectedRule,
    records: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    rules_by_id = build_rule_lookup(rules)

    for record in records:
        notification_id = record_notification_id(record)

        credential_pairs = extract_credential_pairs(record)
        if not credential_pairs:
            usernames = dedupe_preserve_order(collect_field_values(record, username_matcher))
            passwords = dedupe_preserve_order(collect_field_values(record, password_matcher))
            if len(usernames) == 1 and len(passwords) == 1:
                credential_pairs = [(usernames[0], passwords[0])]

        if not credential_pairs:
            continue

        rule_id = entity_rule_id(record) or selected_rule.rule_id
        rule_meta = rules_by_id.get(rule_id, {}) if rule_id else {}
        rule_name = first_non_empty(
            entity_rule_name(record),
            selected_rule.rule_name,
            rule_meta.get("name"),
            "Unmapped monitoring rule",
        )
        rule_topic = first_non_empty(
            entity_rule_topic(record),
            rule_meta.get("topic"),
            "Unknown topic",
        )

        for username, password in credential_pairs:
            findings.append(
                Finding(
                    rule_name=rule_name,
                    rule_topic=rule_topic,
                    notification_id=notification_id or "unknown-notification",
                    usernames=[username],
                    passwords=[password],
                )
            )

    return findings


def format_finding_line(finding: Finding) -> str:
    usernames = ", ".join(finding.usernames)
    passwords = ", ".join(finding.passwords)
    return f"Username: {usernames} | Password: {passwords}"


def aggregate_finding_rows(findings: list[Finding]) -> list[tuple[str, str, str, str]]:
    aggregated: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        usernames = finding.usernames or ["Unknown username"]
        passwords = dedupe_preserve_order(finding.passwords or ["Unknown password"])
        for username in usernames:
            for password in passwords:
                aggregated.add((finding.rule_name, finding.notification_id, username, password))

    rows = list(aggregated)
    rows.sort(key=lambda item: (item[0].lower(), item[1].lower(), item[2].lower(), item[3].lower()))
    return rows


def build_csv_rows(findings: list[Finding]) -> list[dict[str, str]]:
    return [
        {
            "monitoring_rule": rule_name,
            "notification_id": notification_id,
            "username": username,
            "password": password,
        }
        for rule_name, notification_id, username, password in aggregate_finding_rows(findings)
    ]


def prompt_write_csv() -> bool:
    response = prompt_user("Write these findings to a CSV file? [y/N]: ").strip().lower()
    return response in {"y", "yes"}


def prompt_more_exposed_records() -> str:
    response = prompt_user("Show [n]ext 100 exposed data records, [a]ll remaining, or [q]uit? [q]: ").strip().lower()
    if response in {"n", "next"}:
        return "next"
    if response in {"a", "all"}:
        return "all"
    return "quit"


def sanitize_filename_component(value: str) -> str:
    sanitized = "".join("_" if character in '<>:"/\\|?*' else character for character in value)
    sanitized = sanitized.strip().rstrip(".")
    return sanitized or "monitoring rule"


def csv_filename(rule_name: str, created_at: datetime) -> str:
    eu_date = created_at.astimezone(UTC).strftime("%d.%m.%Y")
    safe_rule_name = sanitize_filename_component(rule_name)
    return f'{safe_rule_name}-{eu_date}.csv'


def write_csv_report(output_dir: Path, findings: list[Finding], selected_rule: SelectedRule | None) -> Path:
    export_rule_name = selected_rule.rule_name if selected_rule else "All monitoring rules"
    file_path = output_dir / csv_filename(export_rule_name, datetime.now(UTC))
    rows = build_csv_rows(findings)

    with file_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["monitoring_rule", "notification_id", "username", "password"])
        writer.writeheader()
        writer.writerows(rows)

    return file_path


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("No exposed passwords were found in the retrieved Recon notifications.")
        return

    ordered_rows = aggregate_finding_rows(findings)
    last_rule_name = None
    for rule_name, notification_id, username, password in ordered_rows:
        if rule_name != last_rule_name:
            if last_rule_name is not None:
                print()
            print(f"Monitoring Rule: {rule_name}")
            print("-" * 72)
            last_rule_name = rule_name
        print(f"Username: {username} | Password: {password} [{notification_id}]")


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    dotenv_path = script_dir / ".env"
    load_dotenv(dotenv_path)
    args = parse_args()

    while True:
        clear_screen()
        print_logo()
        prompt_falcon_credentials(dotenv_path)

        try:
            client = build_client()
            verify_recon_access(client)
            rule_ids = query_rule_ids(client)
            rules = (
                run_with_spinner(
                    "Getting monitoring rule details...", fetch_entities, client.get_rules, rule_ids, "GetRulesV1"
                )
                if rule_ids
                else []
            )
            print_status(f"Loaded {len(rules)} monitoring rules... done")
            rule_choices = run_with_spinner(
                "Getting notification counts for monitoring rules...", build_rule_choices, rules, client
            )
            selected_rule = prompt_rule_selection(rule_choices)

            selected_days = args.days if args.days is not None else prompt_day_selection()
            date_window = build_date_window(selected_days)

            notification_rule_filter = build_rule_filter("rule_id", selected_rule.rule_id) if selected_rule else ""
            exposed_rule_filter = build_rule_filter("rule.id", selected_rule.rule_id) if selected_rule else ""
            notification_filter = join_filters(notification_rule_filter, build_date_filter("created_date", date_window))
            exposed_filter = join_filters(exposed_rule_filter, build_date_filter("created_date", date_window))

            if selected_rule:
                print(f"Selected monitoring rule: {selected_rule.rule_name}", file=sys.stderr)

            if date_window:
                print(
                    "Applying date filter: "
                    f"{format_display_datetime(date_window.start)} to {format_display_datetime(date_window.end)}",
                    file=sys.stderr,
                )
            break
        except RestartRequested:
            print("Starting over...", file=sys.stderr)
            continue
        except QuitRequested:
            print("Exiting Recon Password Report.")
            return 0
        except (FalconAPIError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    all_findings: list[Finding] = []
    shown_records = 0

    while True:
        batch_limit = EXPOSED_RECORD_BATCH_SIZE if shown_records == 0 else EXPOSED_RECORD_BATCH_SIZE
        findings, fetched_record_count = fetch_findings_batch(
            client,
            rules,
            selected_rule,
            date_window,
            exposed_rule_filter,
            skip_results=shown_records,
            max_results=batch_limit,
        )

        if fetched_record_count == 0:
            if shown_records == 0:
                print("No exposed data records were found for the selected monitoring rule and date filter.")
            else:
                print("No more exposed data records were found.")
            break

        shown_records += fetched_record_count
        all_findings.extend(findings)
        print_report(findings)

        if fetched_record_count < EXPOSED_RECORD_BATCH_SIZE:
            break

        action = prompt_more_exposed_records()
        if action == "quit":
            break
        if action == "all":
            findings, fetched_record_count = fetch_findings_batch(
                client,
                rules,
                selected_rule,
                date_window,
                exposed_rule_filter,
                skip_results=shown_records,
                max_results=None,
            )
            if fetched_record_count == 0:
                print("No more exposed data records were found.")
                break
            shown_records += fetched_record_count
            all_findings.extend(findings)
            print_report(findings)
            break

    if all_findings and prompt_write_csv():
        file_path = write_csv_report(script_dir, all_findings, selected_rule)
        print(f"CSV written to: {file_path}")

    print("Thanks for using Recon Password Report.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())