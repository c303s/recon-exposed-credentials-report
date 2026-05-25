# Recon Exposed Credentials Report

Generate a report of exposed usernames and passwords from CrowdStrike Falcon Intelligence Recon, grouped by monitoring rule.

> **Version 0.02a** — Not an official CrowdStrike tool.

## Requirements

- `bash`, `curl`, and `python3` on the local machine.
- A CrowdStrike Falcon API client with **read** scope to **Monitoring rules (Falcon Intelligence Recon)**.
  Create one in the Falcon console under **Support and resources** > **API clients and keys**.

## Install

Run from the directory where you want the project files to live. The installer downloads the project from GitHub into the current working directory, creates a local launcher, and starts the script.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main/install.sh)"
```

Files placed in the current directory:

```text
./install.sh
./.gitignore
./recon_exposed_credentials_report.py
./requirements.txt
./README.md
./recon-exposed-credentials-report
```

## Setup

On first launch the script runs setup automatically and prompts for:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL` (default: `https://api.eu-1.crowdstrike.com`)

Credentials are stored in `./.env` with mode `0600`. To re-run setup later:

```bash
./recon-exposed-credentials-report --setup
```

## Run

```bash
./recon-exposed-credentials-report
```

### Workflow

1. **Monitoring rule selection.** Lists active rules that have at least one extractable exposed credential pair. Typosquatting rules are excluded. Each entry shows the credential-pair count (capped at `999+`), creation date, and last change date.
2. **Date filter.** Pick how far back to look (1, 3, 7, 15, 30, 60, or 90 days). Each option shows the credential-pair count for that window. Default is 1 day.
3. **Report output.** Findings are printed grouped by monitoring rule. Duplicate `(username, password)` pairs are deduplicated across records.
4. **CSV export.** You are asked whether to write findings to a CSV file in the current directory.
5. **Start over or quit.**

## Command-line options

| Option | Description |
|--------|-------------|
| `--days N` | Skip the date filter prompt. Valid values: `1`, `3`, `7`, `15`, `30`, `60`, `90`. |
| `--setup` | Re-run setup to update saved credentials. |

Example:

```bash
./recon-exposed-credentials-report --days 7
```

## Notes

- Credentials exposed **before** a monitoring rule was created will not appear; the Recon API only indexes records against a rule from the point it was set up.
- `999+` means the per-rule or per-window count was capped to keep the listing fast; the actual count may be higher.
- The tool does not persist results between runs except via the optional CSV export.
