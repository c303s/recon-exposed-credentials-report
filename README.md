# Recon Exposed Credentials Report

Query CrowdStrike Falcon Intelligence Recon for exposed usernames and passwords by monitoring rule.

> **Version 0.02a** — This is not an official CrowdStrike tool.

## Install

Prerequisites: `bash`, `curl`, and `python3` must already be installed.

Run the install command from the directory where you want the project files to live. It downloads the project from GitHub into the current working directory, creates a local launcher there, and starts the main script. The Python script's own setup routine still handles credential onboarding.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main/install.sh)"
```

The installer places these files in the current working directory:

```text
./install.sh
./.gitignore
./recon_exposed_credentials_report.py
./requirements.txt
./README.md
./recon-exposed-credentials-report
```

## Setup

On first launch, the script runs its built-in setup routine automatically.

It will ask for:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL`

Suggested base URL:

```text
https://api.eu-1.crowdstrike.com
```

To run setup again later:

```bash
./recon-exposed-credentials-report --setup
```

Credentials are stored in:

```text
./.env
```

## Run

```bash
./recon-exposed-credentials-report
```

### Interactive workflow

**1. Optional email filter**

The tool asks whether to filter results to a specific email address or domain, for example `user@example.com` or `@example.com`. Press Enter to skip.

If a filter is already saved in `.env`, you can:
- Press Enter to keep it
- Type `D` to delete it
- Enter a new value directly

**2. Monitoring rule selection**

The tool lists all active monitoring rules that have at least one extractable exposed credential pair. Typosquatting rules are excluded automatically. Each rule shows:

- Total credential pair count (e.g. `14` or `10000+`)
- Rule creation date
- Last changed date (if available)

Example:

```
Found monitoring rules with exposed credentials:
[note] Only listing exposed credentials after rule creation date.
1. Domain – devk.de (10000+)  created 29.04.2026, last changed 15.05.2026
2. Mail – devk.de (14)  created 28.04.2026
```

**3. Date filter**

After selecting a rule, choose how far back to look. Each option shows the number of unique credential pairs found in that window for the selected rule and email filter:

```
Select a date filter:
1. Last 1 day (5)
2. Last 3 days (6)
3. Last 7 days (7)
4. Last 15 days (14)
5. Last 30 days (14)
6. Last 60 days (14)
7. Last 90 days (14)
```

The default is 1 day. Press Enter to accept it.

**4. Report output**

Matching credentials are printed grouped by monitoring rule. Duplicate `(username, password)` pairs are deduplicated across records.

**5. CSV export**

At the end of a run you are asked whether to save the results to a CSV file:

```
Write these findings to a CSV file? [y/N]:
```

If you choose yes, the file is written to the current working directory with a name based on the rule name and today's date.

**6. Start over or quit**

```
Would you like to start over? [y/N]:
```

Press `Y` to run again (credentials are reloaded from `.env`). Press Enter or `N` to exit.

## Command-line options

| Option | Description |
|--------|-------------|
| `--days N` | Skip the date filter prompt and use `N` days. Valid values: `1`, `3`, `7`, `15`, `30`, `60`, `90`. |
| `--setup` | Re-run the setup routine to update saved credentials or the email filter. |

Example:

```bash
./recon-exposed-credentials-report --days 7
```

## Notes

- Credentials exposed **before** a monitoring rule was created will not appear; the CrowdStrike Recon API only indexes records against the rule from the point it was set up.
- The `10000+` indicator means the API result cap was reached. The full credential count may be higher.
- Results are not stored by the tool between runs except in the optional CSV export.
