╔════════════════════════════════════════════════════════════════╗
║           REDMTZ SEATBELT — Terminal Quick Reference           ║
║              AI Governance for Secure Decisions                ║
╚════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 START THE GOVERNANCE SERVER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Start with default policy (safe_defaults)
  $ redmtz serve

  # Start with specific policy
  $ redmtz serve --policy strict_prod
  $ redmtz serve --policy read_only
  $ redmtz serve --policy audit_mode

  # Start with a role-based whitelist
  $ redmtz serve --policy strict_whitelist --whitelist role_devops_senior.json

POLICIES:
  safe_defaults       — Log all, allow safe reads/writes. Default.
  read_only           — Block all writes (tool_use)
  audit_mode          — Allow all, log everything to ledger
  strict_prod         — Block destructive patterns by default
  strict_whitelist    — Only allow actions in whitelist JSON

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUERY THE AUDIT LEDGER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Show last 10 governance decisions
  $ redmtz audit

  # Show last N decisions
  $ redmtz audit --limit 50

  # Export full ledger as signed CSV (to ~/redmtz_audit.csv)
  $ redmtz audit --csv

  # Export to custom path
  $ redmtz audit --csv /path/to/export.csv

  OUTPUT: Signed CSV + hash + signature. Tamper-proof audit trail.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 INSTALL GOVERNANCE AS A CLAUDE CODE HOOK (ENFORCED)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Install Seatbelt hook in current project
  $ redmtz hook install claude-code

  # Control policy via env var
  $ export REDMTZ_HOOK_POLICY=strict_prod
  $ redmtz hook install claude-code

  # Use a custom whitelist
  $ export REDMTZ_HOOK_WHITELIST=/path/to/role_devops_senior.json
  $ redmtz hook install claude-code

  # Uninstall
  $ redmtz hook uninstall claude-code

  RESULT: Seatbelt gates are installed in .claude/settings.json
          Claude Code cannot bypass (ENFORCED mode)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CHECK VERSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  $ redmtz version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK WORKFLOWS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WORKFLOW 1: Quick Governance Check (in one terminal)
  # Terminal 1: Start server
  $ redmtz serve --policy safe_defaults

  # Terminal 2: Query decisions (as they happen)
  $ watch -n 1 'redmtz audit --limit 5'

WORKFLOW 2: Audit Export for Compliance
  $ redmtz audit --csv ~/compliance/redmtz_audit_$(date +%Y%m%d).csv
  (creates signed, tamper-proof CSV with Ed25519 signature)

WORKFLOW 3: Lock Down a Project
  # Install hook + set policy
  $ export REDMTZ_HOOK_POLICY=strict_prod
  $ redmtz hook install claude-code
  $ echo "Seatbelt gates installed and ENFORCED"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 THE PROMISE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Every decision leaves a cryptographically signed record.
Provable. Auditable. Enforceable.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
