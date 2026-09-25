# KeyScan

Find leaked credentials in your code and git history.  
Requires **Python 3.9+** only (no pip packages).

---

## Setup

1. Put this folder on your machine (or clone the repo).
2. Open a terminal in this folder.
3. Check Python works:

```bash
python3 --version
```

That’s it. No install step.

---

## Quick start (most common)

Scan a project and check if secrets look active:

```bash
python3 keyscan.py scan-all --repo /path/to/your/project -o secrets-report --store-raw --no-alert
```

Reports appear in the `secrets-report/` folder.

---

## Step by step

### 1. Scan current files

```bash
python3 keyscan.py scan --repo /path/to/your/project -o secrets-report --store-raw --no-alert
```

### 2. Scan git history

```bash
python3 keyscan.py scan-history --repo /path/to/your/project --commits 500 -o secrets-report --store-raw --no-alert
```

### 3. Check if secrets are still valid

```bash
python3 keyscan.py verify-compromise -f secrets-report/secrets-report.json -o secrets-report
```

### 4. (Optional) Block bad commits

```bash
python3 keyscan.py install-hook --repo /path/to/your/project
```

### 5. (Optional) Add GitHub Actions

```bash
python3 keyscan.py install-ci --repo /path/to/your/project
```

Then commit the new `.github/workflows/secrets-scan.yml` file.

---

## What KeyScan looks for

About **65 built-in patterns**, plus optional high-entropy detection.

| Category | Examples |
|----------|----------|
| Cloud | AWS keys/session, Azure storage/client secret, GCP service account JSON, DigitalOcean, Heroku |
| Payments | Stripe (`sk_` / `pk_` / `whsec_`), Square, PayPal, Shopify |
| Git / CI | GitHub, GitLab (`glpat-`), Bitbucket, npm, PyPI, CircleCI, Terraform Cloud, Vault (`hvs.`) |
| AI APIs | OpenAI, Anthropic, Hugging Face, Replicate |
| Chat | Slack tokens/webhooks, Discord webhooks, Telegram bots |
| Email / SMS | SendGrid, Mailgun, Mailchimp, Twilio |
| Monitoring / SaaS | Datadog, Sentry DSN, New Relic, Cloudflare, Notion, Airtable |
| Auth / hosting | Auth0, Okta, Vercel, Netlify |
| Generic tokens | JWT, Bearer, Basic Auth, `api_key=`, `secret_key=`, `access_token=` |
| Databases | `password=`, Mongo/Postgres/MySQL/Redis/AMQP URIs with user:pass |
| Keys | PEM/OpenSSH/PGP/PuTTY private keys, age secret keys |
| Other | `.env` long values, Dockerfile `ENV`/`ARG`, pip URLs with passwords, high-entropy strings |

Also scans: `.py`, `.js/.ts`, YAML, JSON, shell, Terraform (`.tf`), Dockerfiles, `requirements*.txt`, and `.env*`.

---

## What you get

| File | Meaning |
|------|---------|
| `secrets-report/secrets-report.md` | Easy-to-read results |
| `secrets-report/secrets-report.json` | Machine-readable results |
| `secrets-report/history-report.md` | Secrets found in old commits |
| `secrets-report/compromise-status.json` | Are keys still active? |

Open the `.md` files first.

---

## Tips

- Replace `/path/to/your/project` with `.` to scan the current folder.
- `--store-raw` saves secret values in a protected vault file so live checks can run. Keep that folder private.
- `--no-alert` skips Slack/email notifications.
- `--no-entropy` turns off the high-entropy heuristic (fewer false positives).
- To ignore false positives, create a `.secretsignore` file in the project (one pattern per line).

---

## Need help?

```bash
python3 keyscan.py --help
```
