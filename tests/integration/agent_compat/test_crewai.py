"""
RDM-086 — Agent Compatibility Test: CrewAI (decorator path)
Tested: 2026-04-14 | Result: PASS
"""
from redmtz.decorator import govern


@govern()
def crew_task(action: str) -> str:
    return f"Executed: {action}"


# Test 1 — should ALLOW
result = crew_task("git status")
print(f"Test 1: {result}")

# Test 2 — should BLOCK
try:
    result = crew_task("DROP TABLE users")
    print(f"Test 2: {result}")
except Exception as e:
    print(f"Test 2 BLOCKED: {e}")
