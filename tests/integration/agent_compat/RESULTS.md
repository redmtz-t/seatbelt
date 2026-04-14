# RDM-086 — Agent Compatibility Test Results
**Date:** 2026-04-14
**Version:** redmtz 1.4.1
**Tester:** Robert Benitez (Founder) + Claudius (Lead Architect)
**VM:** cline-agent (single instance, one `redmtz serve --policy audit_mode`)

---

## Results Matrix

| # | Agent | Path | ALLOW | BLOCK | Ledger | Signed | Result |
|---|-------|------|-------|-------|--------|--------|--------|
| 1 | Cline | MCP | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |
| 2 | Claude Desktop | MCP | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |
| 3 | Claude Code | Hook (PreToolUse) | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |
| 4 | Cursor | MCP | — | — | — | — | **DEFERRED** |
| 5 | LangChain | Decorator | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |
| 6 | AutoGen | Decorator | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |
| 7 | CrewAI | Decorator | ✅ | ✅ | ✅ | sha256+ed25519 | **PASS** |

**6/7 PASS — Cursor deferred to next session.**

---

## Bugs Found

| RDM | Description | Severity |
|-----|-------------|----------|
| RDM-087 | `redmtz hook install claude-code` writes to wrong path + no merge logic | HIGH |
| RDM-088 | Decorator ledger entries show `unknown` policy + digest instead of raw command | MEDIUM |

---

## Notes
- All three enforcement paths validated: MCP, Hook, Decorator
- Single VM, single `redmtz serve` instance — multi-agent scenario confirmed working
- Chain integrity verified: `CHAIN INTACT` after all sessions
- Cursor deferred — Robert wants dedicated session with full OBS recording
