# Recon Exposed Credentials Report

Query CrowdStrike Falcon Intelligence Recon for exposed usernames and passwords by monitoring rule.

## Install

Prerequisite: Python 3.10, 3.11, 3.12, or 3.13 must already be installed.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main/install.sh)"
```

## Setup

The installer runs setup automatically.

If only Python 3.14+ is installed, install a supported Python version first and rerun the installer.

If you want to run setup again later:

```bash
recon-exposed-credentials-report --setup
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
~/.config/recon-exposed-credentials-report/.env
```

The setup routine asks for:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL`

Suggested base URL:

```text
https://api.eu-1.crowdstrike.com
```

## Run

```bash
recon-exposed-credentials-report
```