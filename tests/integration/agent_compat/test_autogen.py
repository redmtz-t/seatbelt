"""
RDM-086 — Agent Compatibility Test: AutoGen (decorator path)
Tested: 2026-04-14 | Result: PASS
"""
from redmtz.decorator import govern


@govern()
def agent_task(action: str) -> str:
    return f"Executed: {action}"


# Test 1 — should ALLOW
result = agent_task("kubectl get pods")
print(f"Test 1: {result}")

# Test 2 — should BLOCK
try:
    result = agent_task("rm -rf /")
    print(f"Test 2: {result}")
except Exception as e:
    print(f"Test 2 BLOCKED: {e}")
