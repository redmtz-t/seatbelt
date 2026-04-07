# Connecting an Agent to REDMTZ Seatbelt

Seatbelt governance in two steps:

1. Install the package and start the server
2. Point your agent at it

Every tool call your agent makes goes through the pattern library, gets a
policy decision, and a signed envelope is written to the audit ledger before
the agent gets an answer.

---

## Step 1 — Install and start the server

```bash
pip install redmtz
redmtz serve
```

First run is zero-config:
- Ed25519 keypair generated to `~/.redmtz/keys/`
- SQLite audit ledger initialized at `~/.redmtz/redmtz_audit.db`
- `safe_defaults` policy active: CRITICAL and HIGH risk actions blocked, everything else logged

The server runs on **stdio** — it speaks the MCP protocol over stdin/stdout.
Your MCP client manages the process; you don't need to keep a terminal open.

Optional: start with a stricter policy:

```bash
redmtz serve --policy strict_prod   # block all matched patterns
redmtz serve --policy read_only     # block everything except LOW risk
redmtz serve --policy audit_mode    # log everything, block nothing
```

---

## Step 2 — Connect your MCP client

### Claude Code

Add to your project's `.claude/mcp.json` or your global MCP config:

```json
{
  "mcpServers": {
    "redmtz-seatbelt": {
      "command": "redmtz",
      "args": ["serve"],
      "transport": "stdio"
    }
  }
}
```

Or from the Claude Code CLI:

```bash
claude mcp add redmtz-seatbelt -- redmtz serve
```

---

### Claude Desktop

Edit `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "redmtz-seatbelt": {
      "command": "redmtz",
      "args": ["serve"],
      "transport": "stdio"
    }
  }
}
```

Restart Claude Desktop after saving. Seatbelt will appear in the MCP tools list.

---

### Cline (VS Code)

Open VS Code settings → search **Cline MCP** → **Edit in settings.json**:

```json
{
  "cline.mcpServers": {
    "redmtz-seatbelt": {
      "command": "redmtz",
      "args": ["serve"],
      "transport": "stdio"
    }
  }
}
```

Or via the Cline sidebar → MCP Servers → Add Server → paste the config above.

---

### Cursor

Edit `~/.cursor/mcp.json` (create it if it doesn't exist):

```json
{
  "mcpServers": {
    "redmtz-seatbelt": {
      "command": "redmtz",
      "args": ["serve"],
      "transport": "stdio"
    }
  }
}
```

Restart Cursor after saving.

---

## What your agent can call

Once connected, Seatbelt exposes three tools to your agent:

### `govern_action`

Evaluate any action before executing it.

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `action`  | string | yes      | The action to evaluate — SQL, shell command, file path, or any string |
| `intent`  | string | no       | Agent's stated intent (logged for audit context) |
| `policy`  | string | no       | Policy override. Default: `safe_defaults` |

**ALLOW response:**
```json
{
  "decision": "ALLOW",
  "reason": "no patterns matched",
  "patterns_matched": [],
  "envelope_hash": "a3f1c9d2e8b04712...",
  "signature": "MEUCIQDx3k9mN2p...",
  "governance_mode": "deterministic"
}
```

**BLOCK response:**
```json
{
  "decision": "BLOCK",
  "reason": "BLOCK_DROP_TABLE",
  "patterns_matched": ["BLOCK_DROP_TABLE"],
  "envelope_hash": "7b2e4f1a9c3d8e05...",
  "signature": "MEUCIQDy7m2nP4q...",
  "governance_mode": "deterministic",
  "remediation": "[BLOCK_DROP_TABLE] Use a migration runner (Alembic, Flyway) with a rollback plan. Never issue DROP TABLE from an autonomous agent."
}
```

---

### `audit_trail`

Query recent governance decisions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit`   | int  | no       | Number of entries to return (max 100). Default: 10 |

```json
{
  "entries": [
    {
      "id": 12,
      "timestamp": "2026-03-30T04:21:33.441Z",
      "intent": "clean up old records",
      "command": "DROP TABLE sessions",
      "verdict": "BLOCK",
      "reason": "BLOCK_DROP_TABLE",
      "agent_id": "mcp-client"
    }
  ],
  "returned": 1
}
```

---

### `verify_chain`

Walk the entire audit ledger and verify every hash link.

```json
{
  "valid": true,
  "total_entries": 42,
  "first_break": null,
  "message": "CHAIN INTACT. All 42 entries verified."
}
```

---

## What gets blocked by default

`safe_defaults` blocks CRITICAL and HIGH risk patterns:

| Pattern | Risk | Example |
|---------|------|---------|
| `BLOCK_DROP_TABLE` | CRITICAL | `DROP TABLE users` |
| `BLOCK_TRUNCATE` | CRITICAL | `TRUNCATE TABLE logs` |
| `BLOCK_DELETE_NO_WHERE` | CRITICAL | `DELETE FROM sessions` |
| `BLOCK_RM_RF_ROOT` | CRITICAL | `rm -rf /etc` |
| `BLOCK_SQL_INJECTION_OBVIOUS` | CRITICAL | `' OR '1'='1` |
| `BLOCK_WILDCARD_RECURSIVE_DELETE` | CRITICAL | `rm -rf /var/log/*` |
| `BLOCK_CRED_THEFT` | HIGH | `api_key = 'sk-abc123...'` |
| `BLOCK_SHELL_EXEC_DANGEROUS` | HIGH | `eval(user_input)` |

---

## Python agents (LangChain, AutoGen, CrewAI)

If your agent framework doesn't support MCP, use the `@govern` decorator directly:

```python
from redmtz import govern, GovernanceBlocked

@govern(rules="destructive_actions", policy="safe_defaults")
def execute_sql(query: str):
    db.execute(query)
```

Same pattern library. Same signed envelopes. Same audit ledger.
See the [README](README.md) for full decorator documentation.

---

## Verify your audit trail

After your agent has made a few decisions:

```bash
python3 -c "
from redmtz import database
database.init_db()
status = database.get_chain_status()
print(status)
"
```

Or call `verify_chain` from your connected MCP client.

---

## Key locations

| File | Default path | Override |
|------|-------------|---------|
| Private key | `~/.redmtz/keys/sudo_signing.key` | `REDMTZ_SUDO_KEY_PATH` |
| Public key | `~/.redmtz/keys/sudo_signing.pub` | `REDMTZ_SUDO_PUBKEY_PATH` |
| Audit database | `~/.redmtz/redmtz_audit.db` | `REDMTZ_DB_PATH` |

---

*REDMTZ Seatbelt — redmtz.com*
