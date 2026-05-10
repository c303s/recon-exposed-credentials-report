# Recon Exposed Credentials Report

Query CrowdStrike Falcon Intelligence Recon for exposed usernames and passwords by monitoring rule.

## Install

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python
python3 -m pip install falconpy
curl -fsSL https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main/recon_exposed_credentials_report.py \
  -o /usr/local/bin/recon-exposed-credentials-report
chmod +x /usr/local/bin/recon-exposed-credentials-report
```

## Setup

Run:

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

## Run

```bash
recon-exposed-credentials-report
```