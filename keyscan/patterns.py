"""Built-in secret detection patterns."""
from __future__ import annotations

from typing import List

from .models import SecretPattern


SECRET_PATTERNS: List[SecretPattern] = [
    # --- Cloud ---
    SecretPattern("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}", "CRITICAL", "AWS Access Key ID"),
    SecretPattern(
        "AWS_SECRET_KEY",
        r"aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "CRITICAL",
        "AWS Secret Access Key",
    ),
    SecretPattern(
        "AWS_SESSION_TOKEN",
        r"(?:aws)?_?session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        "CRITICAL",
        "AWS Session Token",
    ),
    SecretPattern(
        "AZURE_STORAGE_KEY",
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
        "CRITICAL",
        "Azure Storage Connection String",
    ),
    SecretPattern(
        "AZURE_CLIENT_SECRET",
        r"(?:azure[_-]?)?client[_-]?secret\s*[=:]\s*['\"]([A-Za-z0-9~._-]{20,})['\"]",
        "CRITICAL",
        "Azure Client Secret",
    ),
    SecretPattern(
        "GCP_SERVICE_ACCOUNT",
        r'"type"\s*:\s*"service_account"',
        "CRITICAL",
        "GCP Service Account JSON marker",
    ),
    SecretPattern(
        "DIGITALOCEAN_TOKEN",
        r"dop_v1_[a-f0-9]{64}",
        "CRITICAL",
        "DigitalOcean Personal Access Token",
    ),
    SecretPattern(
        "HEROKU_API_KEY",
        r"(?:heroku)?[_-]?api[_-]?key\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})['\"]?",
        "CRITICAL",
        "Heroku API Key",
    ),
    # --- Payments ---
    SecretPattern("STRIPE_API_KEY", r"sk_(?:live|test)_[0-9a-zA-Z]{20,}", "CRITICAL", "Stripe Secret Key"),
    SecretPattern(
        "STRIPE_PUBLISHABLE_KEY", r"pk_(?:live|test)_[0-9a-zA-Z]{20,}", "HIGH", "Stripe Publishable Key"
    ),
    SecretPattern("STRIPE_WEBHOOK_SECRET", r"whsec_[0-9a-zA-Z]{24,}", "HIGH", "Stripe Webhook Secret"),
    SecretPattern("SQUARE_ACCESS_TOKEN", r"sq0atp-[0-9A-Za-z\-_]{22}", "CRITICAL", "Square Access Token"),
    SecretPattern(
        "PAYPAL_TOKEN",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "CRITICAL",
        "PayPal Access Token",
    ),
    SecretPattern("SHOPIFY_TOKEN", r"shpat_[a-fA-F0-9]{32}", "CRITICAL", "Shopify Admin API Token"),
    # --- Source control / CI ---
    SecretPattern("GITHUB_TOKEN", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "CRITICAL", "GitHub PAT"),
    SecretPattern("GITLAB_TOKEN", r"glpat-[A-Za-z0-9\-_]{20,}", "CRITICAL", "GitLab Personal Access Token"),
    SecretPattern("BITBUCKET_TOKEN", r"(?:ATBB|ATCTT)[A-Za-z0-9]{20,}", "CRITICAL", "Bitbucket / Atlassian token"),
    SecretPattern("NPM_TOKEN", r"npm_[A-Za-z0-9]{36}", "CRITICAL", "npm Access Token"),
    SecretPattern("PYPI_TOKEN", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}", "CRITICAL", "PyPI API Token"),
    SecretPattern(
        "CIRCLECI_TOKEN",
        r"(?:circle[_-]?ci|CIRCLECI)[_-]?(?:token|TOKEN)\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
        "CRITICAL",
        "CircleCI API Token",
    ),
    SecretPattern(
        "TERRAFORM_CLOUD_TOKEN",
        r"(?:terraform[_-]?(?:cloud)?[_-]?token|TFE_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9.\-]{20,})['\"]?",
        "CRITICAL",
        "Terraform Cloud Token",
    ),
    SecretPattern("HASHICORP_VAULT", r"hvs\.[A-Za-z0-9_-]{90,}", "CRITICAL", "Vault Token"),
    # --- AI / ML ---
    SecretPattern(
        "OPENAI_API_KEY",
        r"sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48}",
        "CRITICAL",
        "OpenAI API Key",
    ),
    SecretPattern("ANTHROPIC_API_KEY", r"sk-ant-[A-Za-z0-9\-_]{40,}", "CRITICAL", "Anthropic API Key"),
    SecretPattern("HUGGINGFACE_TOKEN", r"hf_[A-Za-z0-9]{34,}", "CRITICAL", "Hugging Face Token"),
    SecretPattern("REPLICATE_TOKEN", r"r8_[A-Za-z0-9]{37}", "HIGH", "Replicate API Token"),
    # --- Messaging ---
    SecretPattern("SLACK_BOT_TOKEN", r"xox[baprs]-[0-9A-Za-z-]{10,}", "HIGH", "Slack Token"),
    SecretPattern(
        "SLACK_WEBHOOK",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "HIGH",
        "Slack Incoming Webhook",
    ),
    SecretPattern(
        "DISCORD_WEBHOOK",
        r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "HIGH",
        "Discord Webhook URL",
    ),
    SecretPattern("TELEGRAM_BOT_TOKEN", r"\d{8,10}:[A-Za-z0-9_-]{35}", "HIGH", "Telegram Bot Token"),
    # --- Email / SMS ---
    SecretPattern("SENDGRID_KEY", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "CRITICAL", "SendGrid API Key"),
    SecretPattern("MAILGUN_KEY", r"key-[0-9a-zA-Z]{32}", "HIGH", "Mailgun API Key"),
    SecretPattern("MAILCHIMP_KEY", r"[0-9a-f]{32}-us[0-9]{1,2}", "HIGH", "Mailchimp API Key"),
    SecretPattern(
        "TWILIO_AUTH_TOKEN",
        r"(?:twilio[_-]?)?auth[_-]?token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "HIGH",
        "Twilio Auth Token",
    ),
    SecretPattern("TWILIO_SID", r"AC[a-f0-9]{32}", "HIGH", "Twilio Account SID"),
    # --- Observability / SaaS ---
    SecretPattern(
        "DATADOG_API_KEY",
        r"(?:datadog)?[_-]?api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "HIGH",
        "Datadog API Key",
    ),
    SecretPattern(
        "SENTRY_DSN",
        r"https://[0-9a-f]{32}@[a-z0-9.-]+\.ingest\.[a-z]+\.sentry\.io/\d+",
        "HIGH",
        "Sentry DSN",
    ),
    SecretPattern("NEW_RELIC_KEY", r"NRAK-[A-Z0-9]{27}", "HIGH", "New Relic API Key"),
    SecretPattern(
        "CLOUDFLARE_TOKEN",
        r"(?:cloudflare)?[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_-]{40})['\"]?",
        "CRITICAL",
        "Cloudflare API Token",
    ),
    SecretPattern("NOTION_TOKEN", r"secret_[A-Za-z0-9]{43}", "HIGH", "Notion Integration Token"),
    SecretPattern("AIRTABLE_PAT", r"pat[A-Za-z0-9]{14}\.[0-9a-f]{16}", "HIGH", "Airtable PAT"),
    # --- Auth / platforms ---
    SecretPattern(
        "AUTH0_CLIENT_SECRET",
        r"auth0[_-]?client[_-]?secret\s*[=:]\s*['\"]([A-Za-z0-9_-]{32,})['\"]",
        "CRITICAL",
        "Auth0 Client Secret",
    ),
    # Okta tokens are 42 chars starting with 00; do NOT allow '_' (avoids Django migration names)
    SecretPattern("OKTA_TOKEN", r"(?<![0-9A-Za-z])00[A-Za-z0-9]{40}(?![A-Za-z0-9])", "HIGH", "Okta API Token"),
    SecretPattern(
        "VERCEL_TOKEN",
        r"(?:vercel)?[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9]{24})['\"]?",
        "HIGH",
        "Vercel Token",
    ),
    SecretPattern(
        "NETLIFY_TOKEN",
        r"(?:netlify)?[_-]?(?:auth[_-]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_-]{40,})['\"]?",
        "HIGH",
        "Netlify Access Token",
    ),
    # --- Tokens / generic ---
    SecretPattern(
        "JWT_TOKEN",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "HIGH",
        "JWT Token",
    ),
    SecretPattern("BEARER_TOKEN", r"(?:Bearer|bearer)\s+[A-Za-z0-9\-._~+/]{20,}=*", "HIGH", "Bearer Token"),
    SecretPattern(
        "BASIC_AUTH_HEADER",
        r"(?:Authorization|authorization)\s*[=:]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{20,}['\"]?",
        "HIGH",
        "HTTP Basic Auth header",
    ),
    SecretPattern(
        "API_KEY_GENERIC",
        r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]([A-Za-z0-9_-]{32,})['\"]",
        "HIGH",
        "Generic API Key",
    ),
    SecretPattern(
        "SECRET_KEY_GENERIC",
        r"(?:secret[_-]?key|app[_-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9_/=+\-]{16,})['\"]",
        "HIGH",
        "Generic secret key",
    ),
    SecretPattern(
        "INTEGRATION_TOKEN",
        r"(?:integration|webhook)[_-](?:token|key|secret)\s*[=:]\s*['\"]([A-Za-z0-9_-]{16,})['\"]",
        "HIGH",
        "Generic integration token",
    ),
    SecretPattern(
        "ACCESS_TOKEN_GENERIC",
        r"(?:access[_-]?token|refresh[_-]?token)\s*[=:]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]",
        "HIGH",
        "Generic access/refresh token",
    ),
    # --- Databases / brokers ---
    SecretPattern(
        "DATABASE_PASSWORD",
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s;#]{8,})['\"]",
        "CRITICAL",
        "Database Password",
    ),
    SecretPattern(
        "MONGODB_URI",
        r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "MongoDB URI with credentials",
    ),
    SecretPattern(
        "POSTGRES_URI",
        r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "PostgreSQL URI with credentials",
    ),
    SecretPattern(
        "MYSQL_URI", r"mysql://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+", "CRITICAL", "MySQL URI with credentials"
    ),
    SecretPattern(
        "REDIS_URI",
        r"rediss?://[^:\s]*:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "Redis URI with credentials",
    ),
    SecretPattern(
        "AMQP_URI",
        r"amqps?://[^:\s]+:[^@\s]+@[a-zA-Z0-9._-]+",
        "CRITICAL",
        "AMQP / RabbitMQ URI with credentials",
    ),
    SecretPattern(
        "PIP_URL_CREDENTIALS",
        r"(?:git\+)?https?://[^:\s/]+:[^@\s/]+@(?:github\.com|gitlab\.com|bitbucket\.org|pypi\.[^\s/]+|[^\s/]*artifacts?[^\s/]*)[^\s]*",
        "HIGH",
        "URL with embedded credentials",
    ),
    # --- Google / Firebase ---
    SecretPattern("FIREBASE_KEY", r"AIza[0-9A-Za-z\-_]{35}", "HIGH", "Firebase / Google API Key"),
    SecretPattern("GOOGLE_OAUTH", r"ya29\.[0-9A-Za-z\-_]+", "HIGH", "Google OAuth Access Token"),
    # --- Crypto / keys ---
    SecretPattern(
        "PRIVATE_KEY_PEM",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        "CRITICAL",
        "Private Key (PEM/OpenSSH)",
    ),
    SecretPattern("PGP_PRIVATE_KEY", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL", "PGP Private Key"),
    SecretPattern("PUTTY_PRIVATE_KEY", r"PuTTY-User-Key-File-[0-9.]+", "CRITICAL", "PuTTY Private Key"),
    SecretPattern("AGE_SECRET_KEY", r"AGE-SECRET-KEY-1[A-Z0-9]{58}", "CRITICAL", "age encryption secret key"),
]
