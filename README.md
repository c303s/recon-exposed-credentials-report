# Recon Exposed Credentials Report

Query CrowdStrike Falcon Intelligence Recon for exposed usernames and passwords by monitoring rule.

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

If you want to run setup again later:

```bash
./recon-exposed-credentials-report --setup
```

The tool asks for:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL`

Suggested base URL:

```text
https://api.eu-1.crowdstrike.com
```

Credentials are stored in:

```text
./.env
```

## Run

```bash
./recon-exposed-credentials-report
```