"""
Sample: Autonomous Nova Act Agent with Bartholomew Security Guard
==================================================================
Demonstrates wrapping browser agent actuation with zero-latency
deterministic invariant checks and credential scrubbing.
"""

from nova_act.security.btp_guard import BartholomewActuatorGuard

def main():
    guard = BartholomewActuatorGuard()

    print("=" * 65)
    print("  Nova Act + Bartholomew Sentinel Security Sample")
    print("=" * 65)

    # 1. Unsafe navigation attempt is blocked fail-closed
    v1 = guard.evaluate_actuation("navigate", "https://webhook.site/malicious-hook")
    print(f"Action: navigate -> https://webhook.site/malicious-hook")
    print(f"Verdict: {v1.verdict} (Allowed: {v1.allowed}) | Reason: {v1.reason} ({v1.latency_us:.1f}µs)\n")

    # 2. Destructive click is intercepted
    v2 = guard.evaluate_actuation("click", "button[data-action='delete_project']")
    print(f"Action: click -> button[data-action='delete_project']")
    print(f"Verdict: {v2.verdict} (Allowed: {v2.allowed}) | Reason: {v2.reason} ({v2.latency_us:.1f}µs)\n")

    # 3. Safe form input with secret credentials redacted
    v3 = guard.evaluate_actuation("fill", "input#token", "User API Key: sk_live_998877665544332211")
    print(f"Action: fill -> input#token")
    print(f"Verdict: {v3.verdict} (Allowed: {v3.allowed})")
    print(f"Scrubbed Input: {v3.payload}")
    print(f"Receipt Hash: {v3.receipt_sha256} ({v3.latency_us:.1f}µs)\n")

if __name__ == "__main__":
    main()
