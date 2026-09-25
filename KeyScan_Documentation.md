# KeyScan

**Objective:** Discover exposed credentials in code and git history, verify if they've been compromised, and prevent future leaks via pre-commit hooks and CI/CD integration.

**Status:** Complete (stdlib implementation)  
**Estimated Time:** 3-4 weeks (55-60 hours)  
**Language:** Python 3.9+ (stdlib only, zero external dependencies)  
**Output:** secrets-report.json, secrets-report.md, history-report.json, compromise-status.json, rotation-report.json, .secrets-vault.json

---

## EPIC 1: Secrets Detection & Pattern Matching (12 pts)

**Objective:** Detect various types of secrets in current code using regex patterns

### STORY 1.1: AWS Credential Detection (3 pts)

**User Story:** As a security engineer, I want to detect exposed AWS credentials.

**Acceptance Criteria:**
- [x] Detect AWS Access Keys (`AKIA[0-9A-Z]{16}`)
- [x] Detect AWS Secret Keys (40+ char strings after `aws_secret_access_key=`)
- [x] Find in: Python, JavaScript, YAML, JSON, .env files
- [x] Extract context (surrounding code)
- [x] Mark as CRITICAL severity

**Tasks:**
1. Implement AWS Access Key regex pattern (0.5h)
2. Implement AWS Secret Key pattern (0.5h)
3. Test against real AWS credentials (1h)
4. Integration test with scanner (1h)

**Code Location:** `keyscan.py::SecretPatterns.get_patterns()` (AWS patterns)

---

### STORY 1.2: API Key Detection (Stripe, GitHub, Firebase, etc) (3 pts)

**User Story:** As a developer, I want all my API keys detected before they're committed.

**Acceptance Criteria:**
- [x] Stripe API Keys (sk_live_, sk_test_)
- [x] Stripe Publishable Keys (pk_live_, pk_test_)
- [x] GitHub Personal Access Tokens (gh*, ghp_*, gho_*)
- [x] GitHub SSH Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- [x] Firebase API Keys (AIza[...])
- [x] Generic API keys (api_key=, apikey=)
- [x] Generic integration tokens
- [x] Mark appropriate severity (CRITICAL or HIGH)

**Tasks:**
1. Implement Stripe key detection (1h)
2. Implement GitHub token detection (1h)
3. Implement Firebase + other providers (1h)

**Code Location:** `keyscan.py::SecretPatterns.get_patterns()` (Stripe, GitHub, Firebase)

---

### STORY 1.3: Database Credentials Detection (2 pts)

**User Story:** As a DBA, I want exposed database passwords detected immediately.

**Acceptance Criteria:**
- [x] Detect `password=xxx`, `passwd=xxx`, `pwd=xxx` patterns
- [x] Detect MongoDB connection strings with credentials
- [x] Detect PostgreSQL/MySQL connection strings
- [x] Extract both credential name and value
- [x] Handle quoted and unquoted values

**Tasks:**
1. Implement generic password pattern (1h)
2. Implement database-specific patterns (1h)

**Code Location:** `keyscan.py::SecretPatterns.get_patterns()` (DATABASE_PASSWORD, MONGODB_URI)

---

### STORY 1.4: Private Key Detection (2 pts)

**User Story:** As a security officer, I want all private keys detected.

**Acceptance Criteria:**
- [x] Detect RSA private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- [x] Detect EC private keys
- [x] Detect OpenSSH private keys
- [x] Detect PuTTY private keys
- [x] Mark as CRITICAL

**Tasks:**
1. Implement PEM key detection (1h)
2. Implement other key format detection (1h)

**Code Location:** `keyscan.py::SecretPatterns.get_patterns()` (PRIVATE_KEY_PEM)

---

### STORY 1.5: JWT & Bearer Token Detection (2 pts)

**User Story:** As an API security owner, I want exposed tokens detected.

**Acceptance Criteria:**
- [x] Detect JWT tokens (eyJ... format)
- [x] Detect Bearer tokens (Authorization header values)
- [x] Detect generic bearer tokens
- [x] Extract full token for later verification

**Tasks:**
1. Implement JWT regex (0.5h)
2. Implement Bearer token regex (0.5h)
3. Test against real tokens (1h)

**Code Location:** `keyscan.py::SecretPatterns.get_patterns()` (JWT_TOKEN, BEARER_TOKEN)

---

## EPIC 2: Code Scanning (8 pts)

**Objective:** Scan current codebase for secrets

### STORY 2.1: File-Based Secret Scanning (4 pts)

**User Story:** As a security team, I want to scan all files in the project for secrets.

**Acceptance Criteria:**
- [x] Scan Python, JavaScript, YAML, JSON, shell scripts, configs
- [x] Skip node_modules, .git, venv, __pycache__
- [x] Track file path and line number
- [x] Extract context (line content)
- [x] Handle binary files gracefully
- [x] Report findings with severity

**Tasks:**
1. Implement file discovery (1h)
2. Implement pattern matching per file (1h)
3. Implement context extraction (1h)
4. Implement error handling (1h)

**Code Location:** `keyscan.py::SecretScanner.scan_current_code()`

---

### STORY 2.2: .env File Scanning (2 pts)

**User Story:** As a DevOps engineer, I want .env and .env.* files scanned specifically.

**Acceptance Criteria:**
- [x] Find .env, .env.local, .env.production, .env.*.local
- [x] Parse KEY=VALUE format
- [x] Detect if values look like secrets (length > 20, not variables)
- [x] Report file path and key name (value redacted)
- [x] Skip comments and empty lines

**Tasks:**
1. Implement .env file discovery (1h)
2. Implement secret value detection (1h)

**Code Location:** `keyscan.py::SecretScanner.scan_env_file()`

---

### STORY 2.3: Requirements.txt Scanning (2 pts)

**User Story:** As a package manager, I want credentials in pip URLs detected.

**Acceptance Criteria:**
- [x] Detect credentials in requirements.txt
- [x] Pattern: `git+https://user:password@github.com/...`
- [x] Pattern: `https://user:password@pypi.example.com`
- [x] Extract username and password
- [x] Mark as HIGH severity

**Tasks:**
1. Implement URL credential extraction (1h)
2. Test with real pip URLs (1h)

---

## EPIC 3: Git History Scanning (10 pts)

**Objective:** Scan git commit history for secrets that were committed in the past

### STORY 3.1: Git Commit History Walker (4 pts)

**User Story:** As a security auditor, I want to scan all git commits for exposed secrets.

**Acceptance Criteria:**
- [x] Get list of recent commits (configurable limit, default 500)
- [x] For each commit, get the full diff
- [x] Apply all secret patterns to diff content
- [x] Track commit hash, author, date
- [x] Skip merge commits (optional)
- [x] Handle large repos efficiently (pagination)

**Tasks:**
1. Implement git log retrieval (1.5h)
2. Implement diff retrieval (1h)
3. Implement pattern matching on diffs (1h)
4. Implement metadata extraction (author, date) (0.5h)

**Code Location:** `keyscan.py::SecretScanner.scan_git_history()`

---

### STORY 3.2: Secret Removal Strategy (3 pts)

**User Story:** As a repo maintainer, I want to remove secrets from git history completely.

**Acceptance Criteria:**
- [x] Generate BFG Repo-Cleaner command to remove secret
- [x] Generate git filter-branch fallback command
- [x] Generate full cleanup instructions
- [x] Warn about deployment implications (need to rotate)
- [x] Provide safe removal checklist

**Tasks:**
1. Implement BFG command generation (1h)
2. Implement git filter-branch alternative (1h)
3. Create removal documentation (1h)

---

### STORY 3.3: Secrets Timeline Report (2 pts)

**User Story:** As a security analyst, I want to see when secrets were introduced and modified.

**Acceptance Criteria:**
- [x] For each secret, show first commit it appeared
- [x] Show last commit it appeared
- [x] Show how many commits it was present in
- [x] Generate timeline report

**Tasks:**
1. Implement first/last commit detection (1h)
2. Implement timeline report generation (1h)

---

## EPIC 4: Compromise Verification (9 pts)

**Objective:** Verify if discovered secrets have been compromised

### STORY 4.1: External Breach Database Checking (3 pts)

**User Story:** As a security officer, I want to check if secrets appear in known breach databases.

**Acceptance Criteria:**
- [x] Query HaveIBeenPwned API for email addresses
- [x] Query GitHub for token usage (API call)
- [x] Query Shodan for exposed credentials
- [x] Query Google Safe Browsing
- [x] Report compromise status

**Tasks:**
1. Implement HaveIBeenPwned check (1h)
2. Implement GitHub token validation (1h)
3. Implement Shodan + GSB checks (1h)

**Code Location:** `keyscan.py::CompromiseVerifier.check_haveibeenpwned()`

---

### STORY 4.2: Cloud Provider Credential Validation (3 pts)

**User Story:** As a cloud security engineer, I want to verify if AWS/Stripe/GitHub keys are still active.

**Acceptance Criteria:**
- [x] AWS: Try to list IAM users (requires key to be active)
- [x] Stripe: Check API key validity via API test
- [x] GitHub: Use token to fetch user info
- [x] Report key status (active, revoked, invalid)
- [x] Estimate damage scope (what can this key do)

**Tasks:**
1. Implement AWS key validation (1.5h)
2. Implement Stripe key validation (1h)
3. Implement GitHub token validation (0.5h)

**Code Location:** `keyscan.py::CompromiseVerifier`

---

### STORY 4.3: Compromise Remediation Plan (3 pts)

**User Story:** As a incident responder, I want a remediation plan for each compromised key.

**Acceptance Criteria:**
- [x] Generate rotation instructions for each key type
- [x] Estimate time to full remediation
- [x] Identify dependent systems (what uses this key)
- [x] Provide downtime minimization strategy
- [x] Generate audit trail requirements

**Tasks:**
1. Implement rotation instructions generator (1.5h)
2. Implement dependent system identification (1h)
3. Implement remediation timeline (0.5h)

---

## EPIC 5: Prevention & CI/CD Integration (11 pts)

**Objective:** Prevent future secret leaks via hooks and CI/CD

### STORY 5.1: Pre-commit Hook Installation (3 pts)

**User Story:** As a developer, I want my commits blocked if they contain secrets.

**Acceptance Criteria:**
- [x] Generate pre-commit hook script
- [x] Install into `.git/hooks/pre-commit`
- [x] Hook runs before commit
- [x] Blocks commit if secret detected
- [x] Provides helpful error message
- [x] Bypass option for emergencies (--no-verify, documented risks)

**Tasks:**
1. Implement pre-commit hook generation (1h)
2. Implement hook installation (1h)
3. Test with real git commits (1h)

**Code Location:** `keyscan.py::PreCommitHook.install_hook()`

---

### STORY 5.2: GitHub Actions CI/CD Integration (3 pts)

**User Story:** As a DevOps engineer, I want secrets scanning in GitHub Actions.

**Acceptance Criteria:**
- [x] Create `.github/workflows/secrets-scan.yml`
- [x] Run on: push to main, PRs, weekly schedule
- [x] Scan current code + git history
- [x] Fail build if CRITICAL/HIGH secrets found
- [x] Create issue if secrets found
- [x] Output summary to job summary

**Tasks:**
1. Create GitHub Actions workflow (1h)
2. Implement issue creation (1h)
3. Test in real GitHub repo (1h)

---

### STORY 5.3: Automated Secret Rotation (3 pts)

**User Story:** As a security automation owner, I want compromised keys rotated automatically.

**Acceptance Criteria:**
- [x] AWS Secrets Manager integration (rotate AWS keys)
- [x] HashiCorp Vault integration (alternative)
- [x] Stripe key regeneration API calls
- [x] GitHub token regeneration
- [x] Notification to developers
- [x] Rollback capability

**Tasks:**
1. Implement AWS Secrets Manager integration (1.5h)
2. Implement Vault integration (1h)
3. Implement provider-specific rotation (0.5h)

---

### STORY 5.4: Slack/Email Alerts (2 pts)

**User Story:** As a security team, I want instant notifications of secret leaks.

**Acceptance Criteria:**
- [x] Send Slack message when secret found
- [x] Send email to security team
- [x] Include: secret type, file, severity, action taken
- [x] Mention who committed the code
- [x] Link to remediation docs

**Tasks:**
1. Implement Slack integration (1h)
2. Implement email integration (1h)

---

## CLI Usage

```bash
# Scan current code (.env, requirements, Dockerfile, entropy)
python keyscan.py scan --repo /path/to/project -o secrets-report --store-raw

# Scan git history (last 500 commits)
python keyscan.py scan-history --repo /path/to/project --commits 500 -o secrets-report --store-raw

# Full pipeline: code + history + live verify
python keyscan.py scan-all --repo . -o secrets-report --store-raw --no-alert

# Verify compromise (AWS STS, Stripe, GitHub, Slack, HIBP Pwned Passwords)
python keyscan.py verify-compromise -f secrets-report/secrets-report.json -o secrets-report

# Rotation dry-run (default) or live with provider admin env vars
python keyscan.py rotate -f secrets-report/compromise-status.json -o secrets-report
python keyscan.py rotate --execute-rotation -f secrets-report/compromise-status.json -o secrets-report

# Install pre-commit hook + GitHub Actions workflow
python keyscan.py install-hook --repo /path/to/project
python keyscan.py install-ci --repo /path/to/project
```

### Optional environment variables

| Variable | Purpose |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack alerts |
| `SECURITY_ALERT_EMAIL` / `SMTP_*` | Email alerts |
| `HIBP_API_KEY` | HaveIBeenPwned email breach API |
| `SHODAN_API_KEY` | Shodan search |
| `GSB_API_KEY` | Google Safe Browsing |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SECRETS_MANAGER_ID` | Live Secrets Manager rotation |
| `VAULT_ADDR` / `VAULT_TOKEN` | HashiCorp Vault KV rotation |
| `GITHUB_ADMIN_TOKEN` | Assisted GitHub revoke flow |

Allowlist false positives via `.secretsignore` or `secrets-allowlist.txt` (regex or literal per line).

---

## Output Files

1. **secrets-report.json** — Secrets found in current code
2. **secrets-report.md** — Human-readable secrets report
3. **history-report.json** — Secrets found in git history
4. **history-report.md** — Git history findings (human-readable)
5. **compromise-status.json** — Compromise verification results
6. **.git/hooks/pre-commit** — Pre-commit hook (installed)

---

## Definition of Done

- [x] All secret patterns working correctly
- [x] File scanning functional (Python, JS, YAML, JSON)
- [x] .env scanning working
- [x] Git history scanning functional
- [x] Compromise verification API calls implemented
- [x] Pre-commit hook installed and tested
- [x] CI/CD workflow defined
- [x] No external dependencies (stdlib only)
- [x] Performance: <2 min for typical repo

---

## Backlog Totals

| Metric | Value |
|---|---|
| Epics | 5 |
| Stories | 12 |
| Tasks | ~30 |
| Story Points | 55 |
| Estimated Hours | 55-60 |

---

## Timeline

**Week 1:** Epic 1 (pattern matching) + Epic 2 (code scanning)  
**Week 2:** Epic 3 (git history) + Epic 4 (compromise verification)  
**Week 3:** Epic 5 (prevention + CI/CD)  
**Week 4:** Testing, refinements, documentation

---

## Secret Detection Examples

### AWS Credentials
```python
# Found: AKIA2EXAMPLE1234567
aws_access_key_id = "AKIA2EXAMPLE1234567"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
```

### JWT Token
```javascript
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
```

### Database Password
```yaml
database:
  host: db.example.com
  user: admin
  password: "super_secret_password_12345"
```

### Private Key
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z2X...
...
-----END RSA PRIVATE KEY-----
```

---

## Risk Assessment

**Critical Risks:**
- [ ] AWS key exposed in git history → Entire account compromise
- [ ] Database password exposed → Data breach possible
- [ ] GitHub token exposed → Repo access, CI/CD control
- [ ] Stripe key exposed → Fraudulent charges possible

**Medium Risks:**
- [ ] JWT tokens exposed → Impersonation possible
- [ ] API keys exposed → Rate limit, quota exhaustion
- [ ] Private keys exposed → Encrypted traffic compromise

---

## Assumptions

- Repository is a git repo (or can work with filesystem only)
- Python environment available
- Internet access for compromise verification (optional)
- Write access to .git/hooks for pre-commit hook

---

## Future Enhancements

- [ ] Machine learning to detect non-pattern secrets (entropy analysis)
- [ ] Integration with password managers (auto-rotation)
- [ ] Compliance reporting (SOC 2, HIPAA, PCI-DSS)
- [ ] Terraform/CloudFormation scanning (IaC secrets)
- [ ] Container image scanning (Dockerfile secrets)
- [ ] Kubernetes secrets detection

