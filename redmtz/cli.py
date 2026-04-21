# Copyright 2026 Robert Benitez
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
redmtz.cli — CLI entry point (RDM-033)
REDMTZ Seatbelt

Usage:
    redmtz serve                        Start MCP server (stdio, safe_defaults)
    redmtz serve --policy read_only     Start with specific policy
    redmtz version                      Print version and exit

Founder: Robert Benitez
"""

import json
import os
import re
import sys
import argparse


def _strip_ansi(s: str) -> str:
    """Strip ANSI escape sequences from ledger fields before terminal output."""
    return re.sub(r'\033\[[0-9;]*[mGKHF]', '', str(s))


def _cmd_serve(args):
    from .mcp_server import mcp, _initialize
    _initialize(policy_name=args.policy, whitelist_path=args.whitelist or "")
    mcp.run(transport="stdio")


def _cmd_version(args):
    from . import __version__
    print(f"redmtz {__version__}")


def _cmd_audit(args):
    """Query the most recent governance decisions from the audit ledger."""
    import sqlite3
    from . import database

    database.init_db()

    # CSV export path
    if args.csv:
        result = database.export_csv(args.csv)
        if "error" in result:
            print(f"Error exporting CSV: {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(
            f"[redmtz][SEATBELT] CSV export complete.\n"
            f"  File:       {args.csv}\n"
            f"  Rows:       {result['total_rows']}\n"
            f"  SHA-256:    {result['csv_hash']}\n"
            f"  Signature:  {result['signature'][:48]}...\n"
            f"  Public key: {result['public_key_path']}"
        )
        return

    limit = min(max(1, args.limit), 100)

    try:
        conn   = sqlite3.connect(database.DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp_utc, environment, agent_id, intent,
                   command, verdict, reason, policy, patterns_matched,
                   envelope_hash, sig_alg
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"Error reading audit ledger: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("Audit ledger is empty.")
        return

    print(f"{'ID':>4}  {'TIMESTAMP':<28}  {'AGENT':<18}  {'VERDICT':<8}  {'POLICY':<14}  {'COMMAND':<50}  {'REASON':<30}  {'PATTERNS':<20}  {'HASH':<20}  {'SIG_ALG'}")
    print("─" * 220)

    for row in rows:
        rid           = row[0]
        timestamp     = row[1]
        environment   = row[2] or "unknown"
        agent_id      = _strip_ansi(row[3] or "unknown")
        intent        = row[4]
        raw_cmd       = _strip_ansi(row[5]).replace("\n", " ")
        command       = raw_cmd[:48] + ".." if len(raw_cmd) > 48 else raw_cmd
        verdict       = row[6]
        raw_reason    = _strip_ansi(row[7])
        reason        = raw_reason[:28] + ".." if len(raw_reason) > 28 else raw_reason
        policy        = _strip_ansi(row[8] or "unknown")
        patterns      = row[9] if row[9] else ""
        envelope_hash = (row[10][:16] + "...") if row[10] else ""
        sig_alg       = row[11] or "sha256+ed25519"

        row = f"{rid:>4}  {timestamp:<28}  {agent_id:<18}  {verdict:<8}  {policy:<14}  {command:<50}  {reason:<30}  {patterns:<20}  {envelope_hash:<20}  {sig_alg}"
        if verdict == "BLOCK":
            print(f"\033[31m{row}\033[0m")   # red
        elif verdict == "ALLOW":
            print(f"\033[32m{row}\033[0m")   # green
        else:
            print(row)

    print(f"\n{len(rows)} entries shown. Total in ledger: use --limit to see more.")


def _cmd_seatbelt(args):
    """Print the Seatbelt quick-reference guide."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║           REDMTZ SEATBELT — Terminal Quick Reference           ║
║              AI Governance for Secure Decisions                ║
╚════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 START THE GOVERNANCE SERVER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  redmtz serve                              Start (safe_defaults)
  redmtz serve --policy strict_prod         Production lockdown
  redmtz serve --policy read_only           Block all writes
  redmtz serve --policy audit_mode          Allow all, log everything
  redmtz serve --policy strict_whitelist \\
    --whitelist role_devops_senior.json     Role-based enforcement

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUERY THE AUDIT LEDGER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  redmtz audit                              Last 10 decisions
  redmtz audit --limit 50                   Last 50 decisions
  redmtz audit --csv                        Export to ~/redmtz_audit.csv
  redmtz audit --csv /path/to/export.csv    Export to custom path

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 HOOKS — ENFORCED GOVERNANCE (AGENT CANNOT BYPASS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  redmtz hook install claude-code           Install enforced gate
  redmtz hook uninstall claude-code         Remove gate

  export REDMTZ_HOOK_POLICY=strict_prod     Set policy via env
  export REDMTZ_HOOK_WHITELIST=/path/to/role.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 THREE ENFORCEMENT PATHS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  @govern decorator    ENFORCED — wraps the function, no bypass
  hook install         ENFORCED — harness level, fires before tools
  redmtz serve (MCP)   COOPERATIVE — agent chooses to call it

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 POLICIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  safe_defaults     Log all, allow safe reads/writes     (default)
  read_only         Block all writes
  audit_mode        Allow all, log everything            (WARNING: never prod)
  strict_prod       Block destructive patterns
  strict_whitelist  Whitelist-only — requires role JSON

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OTHER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  redmtz verify                             Verify audit chain integrity
  redmtz version                            Print version
  redmtz seatbelt                           This help screen
  man redmtz                                Full man page (if installed)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Every decision leaves a cryptographically signed record.
 Provable. Auditable. Enforceable. Even after quantum.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)


def _cmd_seatbelt_unbuckle(args):
    """Human-initiated hook disable with audit trail. Agent cannot call this."""
    import datetime

    settings_path = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")

    if not os.path.exists(settings_path):
        print("No hook installed. Nothing to unbuckle.")
        return

    with open(settings_path, "r") as f:
        settings = json.load(f)

    if "hooks" not in settings:
        print("Seatbelt hook is not currently installed.")
        return

    print("\n⚠️  SEATBELT UNBUCKLE — Governance enforcement will be suspended.")
    print("   Every agent action until re-buckle is UNGOVERNED.")
    print("   This event will be logged to the audit ledger.\n")

    confirm = input("   Are you sure you want to unbuckle? (y/N): ").strip().lower()
    if confirm != "y":
        print("\n   Aborted. Seatbelt remains buckled. ✅\n")
        return

    # Stash the hook config so buckle can restore it
    stash_path = os.path.join(os.path.expanduser("~"), ".claude", ".seatbelt_stash.json")
    with open(stash_path, "w") as f:
        json.dump(settings["hooks"], f, indent=2)
    os.chmod(stash_path, 0o600)

    del settings["hooks"]
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    os.chmod(settings_path, 0o600)

    # Log unbuckle event to audit ledger
    try:
        from . import database
        database.init_db()
        database.log_audit(
            environment="operator",
            agent_id="human-operator",
            intent="seatbelt_unbuckle",
            command="redmtz seatbelt unbuckle",
            verdict="ALLOW",
            reason=f"Human operator suspended governance enforcement at {datetime.datetime.utcnow().isoformat()}Z",
            policy="operator_action",
            patterns_matched="",
        )
    except Exception:
        pass  # Never block unbuckle on ledger failure

    print("\n🔓 Seatbelt unbuckled. You have the wheel.")
    print("   Run 'redmtz seatbelt buckle' to restore governance.\n")


def _cmd_seatbelt_buckle(args):
    """Human-initiated hook restore with audit trail."""
    import datetime

    settings_path = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
    stash_path = os.path.join(os.path.expanduser("~"), ".claude", ".seatbelt_stash.json")

    if not os.path.exists(stash_path):
        print("\n   No stashed hook config found. Run 'redmtz hook install claude-code' to install fresh.\n")
        return

    print("\n🔒 SEATBELT BUCKLE — Restoring governance enforcement.\n")

    confirm = input("   Reinstall Seatbelt governance hook? (y/N): ").strip().lower()
    if confirm != "y":
        print("\n   Aborted. Seatbelt remains unbuckled.\n")
        return

    with open(stash_path, "r") as f:
        stashed_hooks = json.load(f)

    if os.path.exists(settings_path):
        with open(settings_path, "r") as f:
            settings = json.load(f)
    else:
        settings = {}

    settings["hooks"] = stashed_hooks
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")

    os.remove(stash_path)

    # Log buckle event to audit ledger
    try:
        from . import database
        database.init_db()
        database.log_audit(
            environment="operator",
            agent_id="human-operator",
            intent="seatbelt_buckle",
            command="redmtz seatbelt buckle",
            verdict="ALLOW",
            reason=f"Human operator restored governance enforcement at {datetime.datetime.utcnow().isoformat()}Z",
            policy="operator_action",
            patterns_matched="",
        )
    except Exception:
        pass

    print("\n✅ Seatbelt buckled. Claudius is governed.\n")


def _cmd_verify(args):
    """Verify the audit ledger hash chain integrity."""
    from . import database
    database.init_db()
    result = database.verify_chain()
    valid = result.get("valid", False)
    total = result.get("total_entries", 0)
    message = result.get("message", "")
    first_break = result.get("first_break")

    if total == 0:
        print("Audit ledger is empty. Nothing to verify.")
        return

    if valid:
        print(f"\n  ✅ CHAIN INTACT — {total} {'entry' if total == 1 else 'entries'} verified.\n")
    else:
        print(f"\n  ❌ CHAIN BROKEN at entry {first_break}.\n  {message}\n")
        sys.exit(1)


def _cmd_hook_install(args):
    """Install Seatbelt as an enforced PreToolUse hook for an agent platform."""
    platform = args.platform

    if platform != "claude-code":
        print(f"Error: unsupported platform '{platform}'. Supported: claude-code")
        sys.exit(1)

    # Find the redmtz hooks module path
    from . import hooks as hooks_module
    hooks_path = os.path.abspath(hooks_module.__file__)
    python_path = sys.executable

    # Determine settings file location — always ~/.claude/settings.json
    claude_dir = os.path.join(os.path.expanduser("~"), ".claude")
    settings_path = os.path.join(claude_dir, "settings.json")

    # Build the hook command
    hook_command = f"{python_path} -m redmtz.hooks"

    # Build the settings
    hook_config = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Edit|Write|WebFetch|Agent",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 10
                        }
                    ]
                }
            ]
        }
    }

    # Merge with existing settings if present
    os.makedirs(claude_dir, exist_ok=True)
    if os.path.exists(settings_path):
        with open(settings_path, "r") as f:
            existing = json.load(f)
        existing["hooks"] = hook_config["hooks"]
        hook_config = existing

    with open(settings_path, "w") as f:
        json.dump(hook_config, f, indent=2)
        f.write("\n")

    policy = os.environ.get("REDMTZ_HOOK_POLICY", "safe_defaults")

    print(
        f"[redmtz][SEATBELT] Hook installed for {platform}.\n"
        f"  Settings:  {settings_path}\n"
        f"  Command:   {hook_command}\n"
        f"  Policy:    {policy} (set REDMTZ_HOOK_POLICY to change)\n"
        f"  Governed:  Bash, Edit, Write, WebFetch, Agent\n"
        f"  Passthru:  Read, Glob, Grep, WebSearch\n"
        f"  Mode:      ENFORCED — agent cannot bypass\n"
        f"\n"
        f"  To configure policy:\n"
        f"    export REDMTZ_HOOK_POLICY=strict_prod\n"
        f"\n"
        f"  To add a whitelist:\n"
        f"    export REDMTZ_HOOK_WHITELIST=/path/to/role_devops_senior.json\n"
        f"\n"
        f"  To uninstall:\n"
        f"    redmtz hook uninstall claude-code"
    )


def _cmd_hook_uninstall(args):
    """Remove Seatbelt hook from an agent platform."""
    platform = args.platform

    if platform != "claude-code":
        print(f"Error: unsupported platform '{platform}'. Supported: claude-code")
        sys.exit(1)

    settings_path = os.path.join(os.path.expanduser("~"), ".claude", "settings.json")

    if not os.path.exists(settings_path):
        print(f"No settings found at {settings_path}. Nothing to uninstall.")
        sys.exit(0)

    with open(settings_path, "r") as f:
        settings = json.load(f)

    if "hooks" in settings:
        del settings["hooks"]

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")

    print(f"[redmtz][SEATBELT] Hook removed from {platform}. Settings updated at {settings_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="redmtz",
        description="REDMTZ Seatbelt — AI governance for any MCP-compatible agent.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # redmtz seatbelt
    seatbelt = subparsers.add_parser(
        "seatbelt",
        help="Seatbelt governance controls",
    )
    seatbelt.set_defaults(func=_cmd_seatbelt)
    seatbelt_sub = seatbelt.add_subparsers(dest="seatbelt_command", metavar="action")

    unbuckle_p = seatbelt_sub.add_parser("unbuckle", help="Suspend governance hook (human-only, logged)")
    unbuckle_p.set_defaults(func=_cmd_seatbelt_unbuckle)

    buckle_p = seatbelt_sub.add_parser("buckle", help="Restore governance hook (human-only, logged)")
    buckle_p.set_defaults(func=_cmd_seatbelt_buckle)

    # redmtz serve
    serve = subparsers.add_parser(
        "serve",
        help="Start the MCP governance server (stdio transport)",
    )
    serve.add_argument(
        "--policy",
        default="safe_defaults",
        choices=["safe_defaults", "read_only", "audit_mode", "strict_prod", "strict_whitelist"],
        help="Policy template (default: safe_defaults)",
    )
    serve.add_argument(
        "--whitelist",
        default="",
        metavar="ROLE_FILE",
        help="Path to a role whitelist JSON file (e.g. role_devops_senior.json). Required for strict_whitelist policy.",
    )
    serve.set_defaults(func=_cmd_serve)

    # redmtz version
    ver = subparsers.add_parser("version", help="Print version and exit")
    ver.set_defaults(func=_cmd_version)

    # redmtz audit
    audit = subparsers.add_parser(
        "audit",
        help="Query the audit ledger from the terminal",
    )
    audit.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent entries to show (max 100, default: 10)",
    )
    audit.add_argument(
        "--csv",
        metavar="OUTPUT_PATH",
        nargs="?",
        const=os.path.join(os.path.expanduser("~"), "redmtz_audit.csv"),
        default="",
        help="Export full ledger as a signed CSV. Defaults to ~/redmtz_audit.csv if no path given.",
    )
    audit.set_defaults(func=_cmd_audit)

    # redmtz verify
    verify = subparsers.add_parser(
        "verify",
        help="Verify audit ledger hash chain integrity",
    )
    verify.set_defaults(func=_cmd_verify)

    # redmtz hook
    hook = subparsers.add_parser("hook", help="Manage harness-level governance hooks")
    hook_sub = hook.add_subparsers(dest="hook_command", metavar="action")

    # redmtz hook install <platform>
    hook_install = hook_sub.add_parser("install", help="Install Seatbelt hook for a platform")
    hook_install.add_argument("platform", choices=["claude-code"], help="Agent platform")
    hook_install.set_defaults(func=_cmd_hook_install)

    # redmtz hook uninstall <platform>
    hook_uninstall = hook_sub.add_parser("uninstall", help="Remove Seatbelt hook from a platform")
    hook_uninstall.add_argument("platform", choices=["claude-code"], help="Agent platform")
    hook_uninstall.set_defaults(func=_cmd_hook_uninstall)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        if args.command == "hook":
            hook.print_help()
        else:
            parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
