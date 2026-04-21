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
redmtz — REDMTZ Seatbelt
AI Governance for Python Functions

The 3-line integration:

    from redmtz import govern

    @govern(rules="destructive_actions", policy="safe_defaults")
    def execute_sql(query: str):
        db.execute(query)

Intercepts function calls, checks against the destructive pattern library,
builds a cryptographically signed audit envelope, logs to the immutable
audit ledger, and either raises GovernanceBlocked or allows execution.

Founder: Robert Benitez
"""

from .decorator import GovernanceBlocked, govern
from .patterns import DestructivePattern, PatternMatcher
from .policies import get_policy, list_policies, policy_decision

__version__ = "1.4.3"
__author__  = "Robert Benitez"
__email__   = "robertbenitez@redmtz.com"

__all__ = [
    # Core public API
    "govern",
    "GovernanceBlocked",
    # Pattern inspection
    "PatternMatcher",
    "DestructivePattern",
    # Policy inspection
    "get_policy",
    "list_policies",
    "policy_decision",
    # Version
    "__version__",
]
