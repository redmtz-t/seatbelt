# REDMTZ Seatbelt — AI Agent Governance

> **"No agent crosses the gate without passing through the law."**

[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Tests](https://img.shields.io/badge/tests-454%2F454%20passing-brightgreen.svg)]()
[![PyPI](https://img.shields.io/badge/pypi-redmtz-blue.svg)](https://pypi.org/project/redmtz/)
[![Supply Chain](https://img.shields.io/badge/supply%20chain-hash%20pinned-brightgreen.svg)]()
[![Patents](https://img.shields.io/badge/patents-USPTO%20filed-blue.svg)]()

---

## What Is Seatbelt?

Seatbelt is a Python library that wraps your AI agent's execution functions and does three things before any action runs:

1. **Blocks** destructive actions — DROP TABLE, rm -rf /, credential theft, SQL injection, and more
2. **Signs** every decision with Ed25519 cryptography — tamper-evident proof the decision happened
3. **Chains** every decision to the one before it — nothing can be deleted or modified without detection

The result: when a regulator asks "what did your AI agent do?" — you produce cryptographic proof, not a story.

**The one-liner that matters:**
> Guardrails are self-reported compliance. Seatbelt is audited enforcement.

---

## Quickstart — 5 Minutes

```bash
pip install redmtz
```

**Python decorator — 3 lines:**

```python
from redmtz import govern, GovernanceBlocked

@govern(rules="destructive_actions", policy="safe_defaults")
def execute_sql(query: str):
    db.execute(query)
```

**MCP agent (Claude Code, Cline, Cursor, Claude Desktop) — 1 command:**

```bash
redmtz serve
```

Then point your MCP client at it. → [Full connection guide](CONNECT.md)

```python
# Safe — passes through, signed envelope logged
execute_sql("SELECT * FROM users WHERE id = 42")

# Dangerous — blocked before execution, signed proof created
try:
    execute_sql("DROP TABLE users")
except GovernanceBlocked as e:
    print(f"Blocked:  {e.pattern.description}")
    print(f"Proof ID: {e.envelope['event_id']}")
    print(f"Fix:      {e.remediation_hint}")
```

---

## How Seatbelt Works

Think of Seatbelt as a bouncer with a law degree. Every action your AI agent tries to take passes through two checks before execution:

**Layer 1 — Blocklist (immutable, always runs):**
8 hardcoded patterns that can never be overridden. DROP TABLE, rm -rf /, SQL injection, credential theft. If the action matches — it's blocked. No exceptions.

**Layer 2 — Whitelist (role-based, your rules):**
Define exactly what your agent IS allowed to do. Everything outside that set is implicitly denied. A DevOps agent can `kubectl get` and `terraform plan`. It cannot `terraform destroy` — even if no blocklist pattern matches.

```
Action submitted
      │
      ▼
Layer 1: Blocklist (8 immutable patterns)
      │
      ├── MATCH → BLOCK (always, whitelist cannot override)
      │
      ▼
Layer 2: Whitelist (role-based allow set)
      │
      ├── MATCH  → ALLOW
      └── NO MATCH → BLOCK (implicit deny)
      │
      ▼
Build signed RDM-019 envelope
UUID v7 · SHA-256 digest · hash chain · Ed25519 signature
      │
      ▼
Write to audit ledger (before return — no crash gap)
      │
      ▼
Return decision to agent
```

**Key principle:** The audit entry is written before the function executes. Every decision — allow or block — is on the record. No gaps.

---

## What Gets Blocked — 8 Core Patterns

All patterns are hardcoded regex. Zero LLM. Zero AI. Deterministic and auditable.

| Pattern ID | Risk | What It Catches |
|------------|------|-----------------|
| `BLOCK_DROP_TABLE` | CRITICAL | `DROP TABLE users`, `DROP_TABLE`, `Drop-Table` |
| `BLOCK_TRUNCATE` | CRITICAL | `TRUNCATE TABLE users`, `truncate logs` |
| `BLOCK_DELETE_NO_WHERE` | CRITICAL | `DELETE FROM users` (no WHERE clause) |
| `BLOCK_SQL_INJECTION_OBVIOUS` | CRITICAL | `' OR '1'='1`, `'; DROP TABLE--`, `UNION SELECT NULL` |
| `BLOCK_RM_RF_ROOT` | CRITICAL | `rm -rf /`, `rm -rf /etc`, `rm -rf /bin` |
| `BLOCK_WILDCARD_RECURSIVE_DELETE` | CRITICAL | `rm -rf /var/log/*`, `find . -delete` |
| `BLOCK_CRED_THEFT` | HIGH | `api_key = 'sk-abc123...'`, hardcoded secrets |
| `BLOCK_SHELL_EXEC_DANGEROUS` | HIGH | `eval(user_input)`, `exec(cmd)`, `bash -c` |

**False positive rate: zero** — `DELETE FROM users WHERE id=123` passes. `SELECT * FROM drop_temp` passes.

---

## Policy Templates

| Policy | Behavior | Use When |
|--------|----------|----------|
| `safe_defaults` | Block CRITICAL + HIGH. Allow everything else. | Starting point for most agents |
| `read_only` | Block CRITICAL + HIGH + MEDIUM. Allow LOW only. | Reporting / analytics agents |
| `audit_mode` | Allow all. Log everything. No enforcement. | Integration testing, observability |
| `strict_prod` | Block all matched patterns + implicit deny on unmatched. | Zero-tolerance production |
| `strict_whitelist` | Two-layer defense. Blocklist floor + whitelist ALLOW set. | Role-based agent governance |

```python
@govern(rules="destructive_actions", policy="strict_prod")    # implicit deny
@govern(rules="destructive_actions", policy="audit_mode")     # observe, don't block
```

---

## Role-Based Whitelists

Define exactly what your agent is authorized to do. Ship the whitelist file with your agent. Version control it. Every decision records its hash — proving the authorization in effect at the time.

```bash
# Start with a role template
redmtz serve --policy strict_whitelist --whitelist role_devops_senior.json
```

**Three role templates ship with Seatbelt:**

| Template | Role | What It Allows |
|----------|------|----------------|
| `role_devops_senior.json` | Senior DevOps Engineer | kubectl get/describe/top/logs, terraform plan/show/validate, aws describe/list, CloudWatch metrics, scoped SQL SELECT |
| `role_mlops_engineer.json` | MLOps Engineer | S3 read/write, SageMaker describe/list, CloudWatch, docker build/images, python scripts, git read |
| `role_junior_admin.json` | Junior Admin | Read-only: ls, grep, ps, top, df, ping, curl GET, kubectl get/logs, git status |

**Decision matrix:**

```
Blocklist HIT              → BLOCK  (always — immutable floor)
Blocklist MISS + WL HIT    → ALLOW
Blocklist MISS + WL MISS   → BLOCK  (implicit deny)
```

**The security guarantee Ziggy signed off on:**
> The blocklist defines what's never allowed. The whitelist defines what's approved. Both run. Blocklist wins on conflict. You can't whitelist your way past DROP TABLE.

---

## MCP Server — 4 Tools

Start the server:
```bash
redmtz serve                                          # safe_defaults
redmtz serve --policy strict_prod                     # implicit deny
redmtz serve --policy strict_whitelist --whitelist role_devops_senior.json
```

| Tool | Description |
|------|-------------|
| `govern_action` | Evaluate any action. Returns ALLOW/BLOCK with signed envelope hash. |
| `audit_trail` | Query recent decisions. Returns environment, policy, patterns, envelope hash per row. |
| `verify_chain` | Walk the full ledger. Verify every hash link. Prove tamper-evidence. |
| `export_audit_csv` | Export full ledger as Ed25519-signed CSV. Hand it to a CISO. |

**`govern_action` response:**
```json
{
  "decision":         "BLOCK",
  "reason":           "BLOCK_DROP_TABLE",
  "patterns_matched": ["BLOCK_DROP_TABLE"],
  "envelope_hash":    "a59ed133...",
  "signature":        "fxgmFMU/...",
  "governance_mode":  "deterministic",
  "sig_alg":          "sha256+ed25519",
  "remediation":      "[BLOCK_DROP_TABLE] Use a migration runner (Alembic, Flyway)..."
}
```

---

## The Signed Envelope — Your Cryptographic Proof

Every decision produces one envelope. This is what you show auditors, regulators, and legal teams.

```json
{
  "event_id":        "019d31c3-b92a-7150-9d27-a9f897c0deef",
  "timestamp_utc":   "2026-04-04T02:14:33.421+00:00",
  "governance_mode": "deterministic",

  "actor": {
    "type":              "application",
    "identity":          "myapp.database.execute_sql",
    "credential_method": "decorator"
  },

  "input": {
    "digest": "a3f5c8d2e1b7f9c4...",
    "token_count": 3,
    "classification": "unknown"
  },

  "gate_decisions": [{
    "gate":     "seatbelt",
    "decision": "block",
    "reason":   "BLOCK_DROP_TABLE",
    "patterns": ["BLOCK_DROP_TABLE"]
  }],

  "policy": {
    "name":           "safe_defaults",
    "version":        "1.0.0",
    "whitelist_hash": "4f93ce7eff3f8106...",
    "whitelist_role": "devops_senior"
  },

  "hash_chain": {
    "previous_hash": "2edf56acc1fd16ca...",
    "current_hash":  "2405c42ff0d032c5..."
  },

  "signatures": [{
    "signer":    "myapp.database.execute_sql",
    "signature": "fxgmFMU/I8n6l/x+Mcj2...",
    "type":      "self"
  }]
}
```

- **`input.digest`** — SHA-256 of the raw query. Raw SQL is never stored. GDPR-safe by design.
- **`hash_chain`** — Modify any envelope and the chain breaks. Mathematical tamper detection.
- **`signatures`** — Ed25519. Any auditor with your public key can verify every decision, forever.
- **`whitelist_hash`** — SHA-256 of the whitelist file active at decision time. Proves authorization.
- **`governance_mode: "deterministic"`** — Proves this decision was made by pure logic, not an AI model.

---

## Schema v3 Audit Columns

Every row in the audit ledger includes:

| Column | Description |
|--------|-------------|
| `sig_alg` | Signature algorithm (`sha256+ed25519` today — labeled for PQC upgrade path) |
| `environment` | Deployment context (`prod`/`staging`/`dev`). Set via `REDMTZ_ENVIRONMENT`. |
| `policy` | Policy template active at decision time |
| `patterns_matched` | Pipe-separated list of matched pattern IDs |
| `envelope_hash` | Canonical signed envelope hash — single integrity proof |
| `remediation` | Remediation hint (BLOCKs only) |

---

## CISO CSV Export

```
govern_action tool → export_audit_csv
```

Or from Python:
```python
from redmtz import database
result = database.export_csv("/tmp/audit_export.csv")
print(result["csv_hash"])    # SHA-256 of the CSV content
print(result["signature"])   # Ed25519 signature — verify with your public key
```

The exported CSV is hashed and signed. Any auditor can verify the export was not tampered with after generation.

---

## Key Management — Zero Config

On first run, Seatbelt auto-generates an Ed25519 keypair:

```
~/.redmtz/keys/
  sudo_signing.key   ← private key (mode 0600)
  sudo_signing.pub   ← public key  (share with auditors)
```

**Override locations:**
```bash
export REDMTZ_SUDO_KEY_PATH=/path/to/sudo_signing.key
export REDMTZ_SUDO_PUBKEY_PATH=/path/to/sudo_signing.pub
export REDMTZ_DB_PATH=/path/to/redmtz_audit.db
export REDMTZ_ENVIRONMENT=prod
```

---

## Verify Your Audit Trail

```bash
# From MCP client
verify_chain

# From Python
from redmtz import database
print(database.get_chain_status())
```

```json
{
  "chain_valid":   true,
  "total_entries": 42,
  "last_hash":     "2405c42ff0d032c5...",
  "message":       "CHAIN INTACT. All 42 entries verified."
}
```

---

## Test Suite — 454/454 Passing

| Test File | Coverage | Tests |
|-----------|----------|-------|
| `test_envelope.py` | RDM-019 Canonical Envelope | 30 |
| `test_action_grammar.py` | RDM-015 Action Grammar | 54 |
| `test_sovereign_monotonic.py` | RDM-020 Monotonic Clock + Replay | 36 |
| `test_patterns.py` | RDM-021 Pattern Library | 72 |
| `test_decorator.py` | RDM-022 @govern Decorator | 50 |
| `test_database.py` | Hash-chained audit ledger | 7 |
| `test_sudo_signing.py` | Ed25519 signing + verification | 13 |
| `test_verify_chain.py` | Chain integrity + export | 9 |
| `test_schema_migration.py` | Schema v1/v2/v3 migration | 10 |
| `test_mcp_gates.py` | MCP server + gates | 14 |
| *(additional)* | Watchtower, resolver, integration | 159 |

```bash
source venv/bin/activate
pytest -q   # 454/454
```

---

## Compliance Mapping

### OWASP LLM Top 10

| Category | Seatbelt Response |
|----------|------------------|
| LLM01: Prompt Injection | All inputs validated against destructive patterns before execution |
| LLM02: Insecure Output Handling | LLM outputs treated as untrusted until governed |
| LLM05: Supply Chain | Hash-pinned lockfile, SHA-pinned GitHub Actions, pip-audit on every push, CycloneDX SBOM |
| LLM06: Sensitive Info Disclosure | Digest-only policy — raw inputs never stored in audit ledger |
| LLM08: Excessive Agency | 8 hardcoded patterns + role-based whitelist limit agent blast radius |
| LLM09: Overreliance | GovernanceBlocked forces visible failure; implicit deny stops unrecognized actions |

### NIST AI Risk Management Framework

| Function | Seatbelt Component |
|----------|-------------------|
| GOVERN | Policy templates, role-based whitelists, implicit deny |
| MAP | ActionGrammar — 12 verbs × 8 domains × risk matrix |
| MEASURE | risk_level in envelope, pattern match counts, sig_alg, environment |
| MANAGE | GovernanceBlocked + remediation hints = active risk management |

### EU AI Act

Seatbelt's signed envelope directly addresses **Article 12** (record-keeping and logging) for high-risk AI systems — automatic recording of events, tamper-evident chain, Ed25519 signatures, independently verifiable by any auditor.

---

## Supply Chain Security

| Control | Status | Detail |
|---------|--------|--------|
| pip-audit on every push | ✅ | `.github/workflows/security-audit.yml` |
| Hash-pinned lockfile | ✅ | `requirements.lock` via `uv pip compile --generate-hashes` |
| GitHub Actions SHA-pinned | ✅ | Immutable commit SHAs, not mutable version tags |
| Secret masking in CI | ✅ | All keys masked before any log step |
| CycloneDX SBOM | ✅ | `redmtz-1.3.1.sbom.json` ships with every release |
| 24-hour rule | Policy | Never install zero-day releases without community stress-testing |

---

## What's Coming

**Cockpit** — Centralized multi-agent governance with neuro-symbolic analysis, human-in-the-loop approval, and fleet-wide policy management. Active development.

**Sovereign AI** — AWS Nitro Enclaves, hardware-attested governance, post-quantum cryptography, indefinite audit retention. Enterprise tier.

Same envelope schema at every tier. Your Seatbelt audit history carries forward. You add gates — you replace nothing.

---

## Patent Status

**Provisional Patent Filed** — U.S. Provisional Application 63/994,312

**Claims include:**
- Canonical signed event envelope with hash-chain integrity (RDM-019)
- Ed25519 signing on AI governance decisions (Patent Claim 28)
- Role-based whitelist with signed hash in every envelope
- `governance_mode` field enabling deterministic → neuro-symbolic upgrade path

---

## Author

**Robert Benitez** — Founder & Sole Inventor
**REDMTZ** — Comanche, TX

*"AI agents should be provably safe, not just probably safe."*

---

## License

Apache License 2.0. Patent pending.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for full terms.
The Apache 2.0 patent grant applies to Seatbelt only.
Cockpit and Sovereign AI are offered under separate commercial terms.

*REDMTZ Seatbelt — Deterministic governance. Cryptographic proof. From line one.*
