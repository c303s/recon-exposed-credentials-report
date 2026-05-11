# Recon Exposed Credentials Report

Query CrowdStrike Falcon Intelligence Recon for exposed usernames and passwords by monitoring rule.

## Install

Prerequisite: Python 3 must already be installed.

No separate Python package install is needed.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main/install.sh)"
```

## Setup

The installer downloads the CLI locally, installs it, and then runs setup from the local file.

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
./.env
```

## Run

```bash
recon-exposed-credentials-report
```