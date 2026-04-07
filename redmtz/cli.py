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

import sys
import argparse


def _cmd_serve(args):
    from .mcp_server import mcp, _initialize
    _initialize(policy_name=args.policy, whitelist_path=args.whitelist or "")
    mcp.run(transport="stdio")


def _cmd_version(args):
    from . import __version__
    print(f"redmtz {__version__}")


def main():
    parser = argparse.ArgumentParser(
        prog="redmtz",
        description="REDMTZ Seatbelt — AI governance for any MCP-compatible agent.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

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

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
