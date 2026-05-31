#!/usr/bin/env python3

"""CrowdStrike Recon report of exposed credentials grouped by monitoring rule.

Reads Falcon API credentials from environment variables or a local .env file,
retrieves Recon monitoring rules, notification details, and exposed data records, and prints
exposed-credential findings grouped by monitoring rule.

To avoid CrowdStrike Recon's 10,000-row pagination ceiling, the script applies a date filter
to notification queries by default. Override it with command-line arguments if needed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import getpass
import json
import os
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib import error, parse, request


PAGE_SIZE = 500
BATCH_SIZE = 100
MAX_QUERY_WINDOW = 10_000
EXPOSED_RECORD_BATCH_SIZE = 100
COUNT_CAP = 1000
COUNT_CAP_LABEL = "999+"
DAY_OPTIONS = (1, 3, 7, 15, 30, 60, 90)
MIN_SEGMENT_WINDOW = timedelta(minutes=1)
FALCON_ENV_KEYS = (
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FALCON_BASE_URL",
)
DEFAULT_FALCON_BASE_URL = "https://api.eu-1.crowdstrike.com"
APP_VERSION = "0.02a"
CONFIG_DIR_NAME = "recon-exposed-credentials-report"

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
    created_at: str = ""
    updated_at: str = ""


class FalconAPIError(RuntimeError):
    """Raised when a Falcon API request fails."""


class ReconClient:
    def __init__(self, client_id: str, client_secret: str, base_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.access_token = ""
        self.token_expires_at = 0.0
        self.ssl_context = self._build_ssl_context()
        self._token_lock = threading.Lock()

    def query_rules(self, **params: Any) -> dict[str, Any]:
        return self._get("/recon/queries/rules/v1", params)

    def get_rules(self, ids: Iterable[str]) -> dict[str, Any]:
        return self._get("/recon/entities/rules/v1", {"ids": list(ids)})

    def query_notifications(self, **params: Any) -> dict[str, Any]:
        return self._get("/recon/queries/notifications/v1", params)

    def query_notifications_exposed_data_records(self, **params: Any) -> dict[str, Any]:
        return self._get("/recon/queries/notifications-exposed-data-records/v1", params)

    def get_notifications_exposed_data_records(self, ids: Iterable[str]) -> dict[str, Any]:
        return self._get("/recon/entities/notifications-exposed-data-records/v1", {"ids": list(ids)})

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._ensure_token()
        return self._request("GET", path, params=params, retry_on_unauthorized=True)

    def _ensure_token(self) -> None:
        with self._token_lock:
            if self.access_token and time.time() < self.token_expires_at - 60:
                return

            token_url = f"{self.base_url}/oauth2/token"
            body = parse.urlencode(
                {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                }
            ).encode("utf-8")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = self._send_request("POST", token_url, headers=headers, body=body)
            status_code = int(response.get("status_code", 0) or 0)
            response_body = response.get("body", {})
            if status_code >= 400:
                raise FalconAPIError(
                    f"oauth2/token failed with status {status_code or 'unknown'}: {self._format_error_details(response_body)}"
                )

            if not isinstance(response_body, dict) or not response_body.get("access_token"):
                raise FalconAPIError("oauth2/token did not return an access token.")

            self.access_token = str(response_body["access_token"])
            expires_in = int(response_body.get("expires_in", 1800) or 1800)
            self.token_expires_at = time.time() + max(expires_in, 60)

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        retry_on_unauthorized: bool = False,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        if params:
            query = parse.urlencode(self._normalize_params(params), doseq=True)
            if query:
                url = f"{url}?{query}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        response = self._send_request(method, url, headers=headers)
        status_code = int(response.get("status_code", 0) or 0)
        if retry_on_unauthorized and status_code == 401:
            self.access_token = ""
            self.token_expires_at = 0.0
            self._ensure_token()
            headers["Authorization"] = f"Bearer {self.access_token}"
            response = self._send_request(method, url, headers=headers)

        return response

    def _send_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> dict[str, Any]:
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=120, context=self.ssl_context) as response:
                payload = response.read()
                return {
                    "status_code": response.getcode(),
                    "body": self._decode_body(payload),
                }
        except error.HTTPError as exc:
            return {
                "status_code": exc.code,
                "body": self._decode_body(exc.read()),
            }
        except error.URLError as exc:
            raise FalconAPIError(f"Request to {url} failed: {exc.reason}") from exc

    def _build_ssl_context(self) -> ssl.SSLContext:
        explicit_cert_file = os.environ.get("SSL_CERT_FILE", "").strip()
        if explicit_cert_file and Path(explicit_cert_file).is_file():
            return ssl.create_default_context(cafile=explicit_cert_file)

        for candidate in (
            "/etc/ssl/cert.pem",
            "/private/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ):
            if Path(candidate).is_file():
                return ssl.create_default_context(cafile=candidate)

        return ssl.create_default_context()

    def _decode_body(self, payload: bytes) -> Any:
        if not payload:
            return {}
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"raw": payload.decode("utf-8", errors="replace")}

    def _normalize_params(self, params: dict[str, Any]) -> list[tuple[str, str]]:
        normalized: list[tuple[str, str]] = []
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    if item is None:
                        continue
                    normalized.append((key, str(item)))
                continue
            if value == "":
                continue
            normalized.append((key, str(value)))
        return normalized

    def _format_error_details(self, body: Any) -> str:
        if isinstance(body, dict):
            errors = body.get("errors") or []
            if isinstance(errors, list) and errors:
                parts = []
                for item in errors:
                    if not isinstance(item, dict):
                        continue
                    code = item.get("code")
                    message = item.get("message")
                    if code or message:
                        parts.append(f"{code or 'error'}: {message or 'Unknown error'}")
                if parts:
                    return "; ".join(parts)
        return "No error details returned"


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
    print("Query CrowdStrike Recon for exposed credential findings by monitoring rule.")
    print(f"Version {APP_VERSION} | built on 31.05.2026 | This is not an official CrowdStrike tool.")
    print()


def resolve_dotenv_path() -> Path:
    return Path.cwd() / ".env"


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
                    "Pre-flight check failed. Possible reasons are:\n"
                    "- Invalid API client details. Please enter valid credentials.\n"
                    "- API client does not have Recon read access.\n"
                    'Hint: "Support and resources" > "API clients and keys" > [API client] >\n'
                    '"Monitoring rules (Falcon Intelligence Recon)" > enable read scope\n'
                    "Please correct this and try again."
            ) from exc
        raise
    print(f"\r[status] {status_message} done")
    print("\033[32m[status] API client has access to CrowdStrike Recon... done\033[0m")


def query_rule_ids(client: Any) -> list[str]:
    return run_with_spinner(
        "Getting list of monitoring rules...",
        paginate_query,
        client.query_rules,
        "QueryRulesV1",
    )


def print_status(message: str) -> None:
    print(f"[status] {message}")


def prompt_user(message: str, separator: bool = True) -> str:
    sys.stdout.write(message)
    sys.stdout.flush()
    response = input()
    if separator:
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
    """Load environment variables from a .env file on each startup."""
    for key, value in read_dotenv_values(dotenv_path).items():
        if key:
            os.environ[key] = value


def write_dotenv_values(dotenv_path: Path, updates: dict[str, str | None]) -> None:
    dotenv_path.parent.mkdir(parents=True, exist_ok=True)
    lines = dotenv_path.read_text(encoding="utf-8").splitlines() if dotenv_path.exists() else []
    updated_keys: set[str] = set()
    output_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in line:
            key, _ = line.split("=", 1)
            key = key.strip()
            if key in updates:
                value = updates[key]
                updated_keys.add(key)
                if value:
                    output_lines.append(f"{key}={value}")
                continue
        output_lines.append(line)

    for key, value in updates.items():
        if key not in updated_keys and value:
            output_lines.append(f"{key}={value}")

    content = "\n".join(output_lines)
    if output_lines:
        content += "\n"
    dotenv_path.write_text(content, encoding="utf-8")
    try:
        dotenv_path.chmod(0o600)
    except OSError:
        pass


def apply_falcon_values(values: dict[str, str]) -> None:
    for key, value in values.items():
        if key:
            os.environ[key] = value


def prompt_non_empty_value(name: str) -> str:
    while True:
        value = prompt_user(f"Enter {name}: ", separator=False).strip()
        if value:
            return value
        print(f"{name} cannot be empty.")


def prompt_secret_value(name: str) -> str:
    while True:
        if sys.stdin.isatty() and sys.stderr.isatty():
            value = getpass.getpass(f"Enter {name}: ").strip()
        else:
            value = prompt_user(f"Enter {name}: ", separator=False).strip()

        if value:
            return value
        print(f"{name} cannot be empty.")


def prompt_value_with_default(name: str, default: str) -> str:
    while True:
        value = prompt_user(f"Enter {name} [{default}]: ", separator=False).strip()
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


def prompt_falcon_values() -> dict[str, str]:
    return {
        "FALCON_CLIENT_ID": prompt_non_empty_value("FALCON_CLIENT_ID"),
        "FALCON_CLIENT_SECRET": prompt_secret_value("FALCON_CLIENT_SECRET"),
        "FALCON_BASE_URL": prompt_value_with_default("FALCON_BASE_URL", DEFAULT_FALCON_BASE_URL),
    }


def build_client_from_values(values: dict[str, str]) -> Any:
    return ReconClient(
        client_id=values["FALCON_CLIENT_ID"],
        client_secret=values["FALCON_CLIENT_SECRET"],
        base_url=values["FALCON_BASE_URL"],
    )


def prompt_for_valid_falcon_credentials(dotenv_path: Path) -> Any:
    while True:
        new_values = prompt_falcon_values()
        try:
            client = build_client_from_values(new_values)
            verify_recon_access(client)
        except (FalconAPIError, RuntimeError) as exc:
            print("Current API client details are invalid. Please enter valid credentials.")
            print(exc)
            continue

        write_dotenv_values(dotenv_path, new_values)
        apply_falcon_values(new_values)
        return client


def prompt_falcon_credentials(dotenv_path: Path) -> Any:
    dotenv_values = read_dotenv_values(dotenv_path)
    current_values = {
        key: dotenv_values.get(key, "")
        for key in FALCON_ENV_KEYS
    }

    print("Current API client details:")
    print(f"FALCON_CLIENT_ID: {current_values['FALCON_CLIENT_ID']}")
    print(f"FALCON_CLIENT_SECRET: {mask_secret(current_values['FALCON_CLIENT_SECRET'])}")
    print(f"FALCON_BASE_URL: {current_values['FALCON_BASE_URL']}")

    try:
        client = build_client_from_values(current_values)
        verify_recon_access(client)
    except (FalconAPIError, RuntimeError) as exc:
        print(exc)
        return prompt_for_valid_falcon_credentials(dotenv_path)

    while True:
        response = prompt_user(
            "Would you like to update these credentials? [y/N]: "
        ).strip().lower()
        if response in {"", "n", "no"}:
            apply_falcon_values(current_values)
            return client
        if response in {"y", "yes", "update"}:
            return prompt_for_valid_falcon_credentials(dotenv_path)
        print("Invalid selection. Enter 'Y' to update these credentials or 'N' to keep them.")


def has_complete_falcon_configuration(dotenv_path: Path) -> bool:
    dotenv_values = read_dotenv_values(dotenv_path)
    if not dotenv_path.exists():
        return False
    return all(dotenv_values.get(key, "").strip() for key in FALCON_ENV_KEYS)


def run_initial_setup(dotenv_path: Path) -> Any:
    print("Welcome to Recon Report. This is the initial setup.")
    print("[status] No configuration was found. We need to set up access first.")
    print(
        "[note] Requirement: API client with read scope \"Monitoring rules (Falcon Intelligence Recon)\"."
    )
    print("[hint] \"Support and resources\" > \"API clients and keys\".")
    print("[hint] Monitoring rules must be configured in the Falcon console before they can be queried.")
    print("------------------------------------------------------------------------")
    client = prompt_for_valid_falcon_credentials(dotenv_path)
    print("[status] Saving configuration. done")
    return client


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value

    raise RuntimeError(f"Missing required environment variable: {name}")


def build_client() -> Any:
    return ReconClient(
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
    for entry in errors:
        if isinstance(entry, dict):
            code = entry.get("code")
            message = entry.get("message")
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


def paginate_query_segment(
    method: Any,
    operation: str,
    max_results: int | None = None,
    **query_kwargs: Any,
) -> tuple[list[str], bool]:
    results: list[str] = []
    offset = 0
    truncated = False
    ceiling = MAX_QUERY_WINDOW if max_results is None else min(max_results, MAX_QUERY_WINDOW)

    while offset < ceiling:
        limit = min(PAGE_SIZE, ceiling - offset)
        response = method(limit=limit, offset=offset, **query_kwargs)
        ensure_success(response, operation)
        page = [str(item) for item in get_resources(response)]
        if not page:
            break

        results.extend(page)
        if len(page) < limit:
            break

        offset += limit

    if max_results is None and offset >= MAX_QUERY_WINDOW and len(results) >= MAX_QUERY_WINDOW:
        truncated = True

    return results, truncated


def count_pairs_in_records(client: Any, ids: list[str]) -> int:
    """Fetch record entities and count unique extractable (username, password) pairs."""
    if not ids:
        return 0
    records = fetch_entities(
        client.get_notifications_exposed_data_records, ids, "GetNotificationsExposedDataRecordsV1"
    )
    seen: set[tuple[str, str]] = set()
    for record in records:
        pairs = extract_credential_pairs(record)
        if not pairs:
            usernames = dedupe_preserve_order(collect_field_values(record, username_matcher))
            passwords = dedupe_preserve_order(collect_field_values(record, password_matcher))
            if len(usernames) == 1 and len(passwords) == 1:
                pairs = [(usernames[0], passwords[0])]
        for username, password in pairs:
            seen.add((username, password))
    return len(seen)


def count_exposed_records_for_rule(client: Any, rule_id: str) -> str:
    ids, _ = paginate_query_segment(
        client.query_notifications_exposed_data_records,
        "QueryNotificationsExposedDataRecordsV1",
        max_results=COUNT_CAP,
        filter=build_rule_filter("rule.id", rule_id),
    )
    if len(ids) >= COUNT_CAP:
        return COUNT_CAP_LABEL

    return str(count_pairs_in_records(client, ids))


def count_exposed_records_in_window(client: Any, rule_id: str, date_window: DateWindow) -> str:
    ids = paginate_segmented_by_date(
        client.query_notifications_exposed_data_records,
        "QueryNotificationsExposedDataRecordsV1",
        "created_date",
        date_window,
        base_filter=build_rule_filter("rule.id", rule_id),
        max_results=COUNT_CAP,
    )
    if len(ids) >= COUNT_CAP:
        return COUNT_CAP_LABEL
    count = count_pairs_in_records(client, ids)
    return str(count)


def fetch_day_option_counts(client: Any, rule_id: str) -> dict[int, str]:
    def fetch_one(days: int) -> tuple[int, str]:
        window = build_date_window(days)
        return days, count_exposed_records_in_window(client, rule_id, window)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DAY_OPTIONS)) as executor:
        pairs = list(executor.map(fetch_one, DAY_OPTIONS))

    return dict(pairs)


def build_rule_choices(rules: list[dict[str, Any]], client: Any) -> list[RuleChoice]:
    choices: list[RuleChoice] = []
    for rule in sorted(rules, key=lambda item: entity_rule_name(item).lower()):
        rule_id = entity_rule_id(rule) or entity_id(rule)
        rule_name = entity_rule_name(rule)
        if not rule_id or not rule_name:
            continue
        topic = entity_rule_topic(rule)
        if "typosquatting" in topic.lower():
            continue
        exposed_count = count_exposed_records_for_rule(client, rule_id)
        if exposed_count == "0":
            continue
        created_at = format_rule_date(entity_rule_timestamp(
            rule, "created_timestamp", "createdTimestamp", "created_at", "createdAt"
        ))
        updated_at = format_rule_date(entity_rule_timestamp(
            rule, "updated_timestamp", "last_updated_timestamp", "lastUpdatedTimestamp",
            "updatedTimestamp", "updated_at", "updatedAt", "last_modified_timestamp",
            "lastModifiedTimestamp", "modified_timestamp", "modifiedTimestamp",
        ))
        choices.append(
            RuleChoice(
                rule_id=rule_id,
                rule_name=rule_name,
                notification_count=exposed_count,
                created_at=created_at,
                updated_at=updated_at,
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
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )
    parser.add_argument(
        "--days",
        type=int,
        choices=DAY_OPTIONS,
        help="Look back this many days when querying notifications.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run the initial setup routine and save Falcon credentials.",
    )
    return parser.parse_args()


def prompt_day_selection(day_counts: dict[int, str] | None = None) -> int:
    print("Select a date filter:")
    for index, option in enumerate(DAY_OPTIONS, start=1):
        suffix = "day" if option == 1 else "days"
        count_str = f" ({day_counts[option]})" if day_counts and option in day_counts else ""
        print(f"{index}. Last {option} {suffix}{count_str}")
    print("q. Quit")
    print("s. Start over")

    while True:
        selection = prompt_user("Choose 1–7 [default 1]: ").strip()
        if not selection:
            return DAY_OPTIONS[0]
        lowered = selection.lower()
        if lowered == "q":
            raise QuitRequested()
        if lowered == "s":
            raise RestartRequested()
        if selection in {str(index) for index in range(1, len(DAY_OPTIONS) + 1)}:
            return DAY_OPTIONS[int(selection) - 1]
        print("Invalid selection. Choose 1–7, or enter Q to quit or S to start over.")


def prompt_rule_selection(rule_choices: list[RuleChoice]) -> SelectedRule:
    if not rule_choices:
        raise RuntimeError(
            "Could not find Monitoring rules, please set them up first. "
            "(hint: Counter Adversary Operations > External Cyber Risk > Recon > Monitoring rules)"
        )

    selectable_rule_choices = [
        rule for rule in rule_choices if rule.notification_count.endswith("+") or int(rule.notification_count) > 0
    ]
    if not selectable_rule_choices:
        raise RuntimeError(
            "Monitoring rules were found, but none have exposed credential records to report. "
            "Wait for new exposed data records to appear, then run the tool again."
        )

    print("------------------------------------------------------------------------")
    print("Found monitoring rules with exposed credentials:")
    print("[note] Only listing exposed credentials after rule creation date.")
    for index, rule in enumerate(selectable_rule_choices, start=1):
        dates = ""
        if rule.created_at:
            dates = f"  created {rule.created_at}"
        if rule.updated_at:
            dates += f", last changed {rule.updated_at}"
        print(f"{index}. {rule.rule_name} ({rule.notification_count}){dates}")
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
            if 1 <= selected_index <= len(selectable_rule_choices):
                selected_rule = selectable_rule_choices[selected_index - 1]
                return SelectedRule(rule_id=selected_rule.rule_id, rule_name=selected_rule.rule_name)
        print(
            f"Invalid selection. Choose a number from 1 to {len(selectable_rule_choices)}, "
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
        segment_cap: int | None = None
        if max_results is not None:
            segment_cap = max_results + skip_results - len(results) - skipped
            if segment_cap <= 0:
                break
        segment_results, truncated = paginate_query_segment(
            method,
            operation,
            max_results=segment_cap,
            filter=combined_filter or None,
        )

        if truncated and max_results is None:
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
    records = fetch_entities(
        client.get_notifications_exposed_data_records,
        exposed_record_ids,
        "GetNotificationsExposedDataRecordsV1",
    )

    findings = run_with_spinner(
        "Building report output... (this may take a while)",
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


def entity_rule_timestamp(entity: dict[str, Any], *keys: str) -> str:
    return first_non_empty(*(entity.get(k) for k in keys))


def format_rule_date(timestamp: str) -> str:
    """Parse an ISO-8601 timestamp string and return DD.MM.YYYY, or empty string on failure."""
    if not timestamp:
        return ""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.astimezone(UTC).strftime("%d.%m.%Y")
    except ValueError:
        return ""


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


def aggregate_finding_rows(findings: list[Finding]) -> list[tuple[str, str, str, str]]:
    seen: dict[tuple[str, str, str], str] = {}
    for finding in findings:
        usernames = finding.usernames or ["Unknown username"]
        passwords = dedupe_preserve_order(finding.passwords or ["Unknown password"])
        for username in usernames:
            for password in passwords:
                key = (finding.rule_name, username, password)
                if key not in seen:
                    seen[key] = finding.notification_id

    rows = [(rule_name, notification_id, username, password)
            for (rule_name, username, password), notification_id in seen.items()]
    rows.sort(key=lambda item: (item[0].lower(), item[2].lower(), item[3].lower()))
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


def sanitize_csv_cell(value: str) -> str:
    """Prevent CSV formula injection by prefixing risky leading characters with a single quote."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv_report(output_dir: Path, findings: list[Finding], selected_rule: SelectedRule | None) -> Path:
    export_rule_name = selected_rule.rule_name if selected_rule else "All monitoring rules"
    file_path = output_dir / csv_filename(export_rule_name, datetime.now(UTC))
    rows = build_csv_rows(findings)
    safe_rows = [{key: sanitize_csv_cell(value) for key, value in row.items()} for row in rows]

    with file_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["monitoring_rule", "notification_id", "username", "password"])
        writer.writeheader()
        writer.writerows(safe_rows)

    return file_path


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("No extractable credential pairs were found in the loaded records.")
        return

    ordered_rows = aggregate_finding_rows(findings)
    last_rule_name = None
    for rule_name, _notification_id, username, password in ordered_rows:
        if rule_name != last_rule_name:
            if last_rule_name is not None:
                print()
            print(f"Monitoring Rule: {rule_name}")
            print("-" * 72)
            last_rule_name = rule_name
        print(f"Username: {username} | Password: {password}")


def main() -> int:
    dotenv_path = resolve_dotenv_path()
    args = parse_args()

    while True:
        load_dotenv(dotenv_path)
        clear_screen()
        print_logo()
        if args.setup or not dotenv_path.exists() or not has_complete_falcon_configuration(dotenv_path):
            client = run_initial_setup(dotenv_path)
        else:
            client = prompt_falcon_credentials(dotenv_path)

        try:
            rule_ids = query_rule_ids(client)
            rules = (
                run_with_spinner(
                    "Getting monitoring rule details...", fetch_entities, client.get_rules, rule_ids, "GetRulesV1"
                )
                if rule_ids
                else []
            )
            rule_choices = run_with_spinner(
                "Verifying exposed credentials for monitoring rules...", build_rule_choices, rules, client
            )
            print_status(f"Loaded {len(rules)} monitoring rules... {len(rule_choices)} include exposed credentials done")
            selected_rule = prompt_rule_selection(rule_choices)

            if args.days is not None:
                selected_days = args.days
            else:
                rule_id_for_counts = selected_rule.rule_id if selected_rule else ""
                day_counts: dict[int, str] | None = None
                if rule_id_for_counts:
                    day_counts = run_with_spinner(
                        "Counting exposed credentials per date range...",
                        fetch_day_option_counts,
                        client,
                        rule_id_for_counts,
                    )
                selected_days = prompt_day_selection(day_counts)
            date_window = build_date_window(selected_days)

            exposed_rule_filter = build_rule_filter("rule.id", selected_rule.rule_id) if selected_rule else ""

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
            return 2
        except (FalconAPIError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1

    all_findings: list[Finding] = []
    shown_records = 0

    while True:
        findings, fetched_record_count = fetch_findings_batch(
            client,
            rules,
            selected_rule,
            date_window,
            exposed_rule_filter,
            skip_results=shown_records,
            max_results=EXPOSED_RECORD_BATCH_SIZE,
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
        file_path = write_csv_report(Path.cwd(), all_findings, selected_rule)
        print(f"CSV written to: {file_path}")
        print("------------------------------------------------------------------------")

    return 0


if __name__ == "__main__":
    try:
        while True:
            exit_code = main()
            if exit_code == 2:
                print("Thanks for using Recon Report. Stay safe out there!")
                raise SystemExit(0)
            if exit_code != 0:
                raise SystemExit(exit_code)
            while True:
                response = prompt_user("Would you like to start over? [y/N]: ").strip().lower()
                if response in {"y", "yes"}:
                    break
                if response in {"n", "no", ""}:
                    print("Thanks for using Recon Report. Stay safe out there!")
                    raise SystemExit(0)
                print("Invalid selection. Enter Y to start over or N to quit.")
    except KeyboardInterrupt:
        print("\nAborted by user.")
        raise SystemExit(130)