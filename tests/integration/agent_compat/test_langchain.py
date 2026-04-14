"""
RDM-086 — Agent Compatibility Test: LangChain (decorator path)
Tested: 2026-04-14 | Result: PASS
"""
from redmtz.decorator import govern


@govern()
def run_query(action: str) -> str:
    return f"Executed: {action}"


# Test 1 — should ALLOW
result = run_query("SELECT * FROM logs WHERE id = 1")
print(f"Test 1: {result}")

# Test 2 — should BLOCK
try:
    result = run_query("DROP TABLE users")
    print(f"Test 2: {result}")
except Exception as e:
    print(f"Test 2 BLOCKED: {e}")
