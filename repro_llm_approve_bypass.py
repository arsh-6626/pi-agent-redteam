#!/usr/bin/env python3
"""
Minimal, LLM-free repro: OpenHands silently discards --llm-approve under --headless.

It exercises the REAL code path in
    openhands_cli/tui/textual_app.py :: main()
(lines 723-729) by stubbing only the TUI app constructor, and prints which
ConfirmationPolicy the CLI actually selects for each flag combination.

Expected (buggy) behaviour:
    --llm-approve              -> ConfirmRisky(threshold=HIGH)   [intended]
    --llm-approve --headless   -> NeverConfirm()                 [analyzer silently dropped]

No model, no network, no episode. Exit code 0 = bypass reproduced.

Usage:  python3 repro_llm_approve_bypass.py
"""
from __future__ import annotations

import sys


def policy_for(*, headless: bool, llm_approve: bool, always_approve: bool = False) -> str:
    """Run the real textual_app.main() and capture the policy it constructs."""
    from openhands_cli.tui import textual_app as ta

    captured: dict[str, object] = {}

    class _Sentinel(Exception):
        pass

    class _FakeApp:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            raise _Sentinel  # stop before the TUI loop

    orig_app = ta.OpenHandsApp
    orig_setup = ta.SettingsScreen.is_initial_setup_required
    ta.OpenHandsApp = _FakeApp                     # type: ignore[assignment]
    ta.SettingsScreen.is_initial_setup_required = staticmethod(lambda **_: False)  # type: ignore[assignment]
    try:
        ta.main(headless=headless, llm_approve=llm_approve,
                always_approve=always_approve, env_overrides_enabled=False)
    except _Sentinel:
        pass
    finally:
        ta.OpenHandsApp = orig_app                  # type: ignore[assignment]
        ta.SettingsScreen.is_initial_setup_required = orig_setup  # type: ignore[assignment]

    pol = captured.get("initial_confirmation_policy")
    name = type(pol).__name__
    if name == "ConfirmRisky":
        name += f"(threshold={getattr(pol, 'threshold', '?')})"
    return name


def main() -> int:
    print(f"openhands CLI version: ", end="")
    try:
        from importlib.metadata import version
        print(version("openhands-cli"))
    except Exception:  # noqa: BLE001
        try:
            import openhands_cli
            print(getattr(openhands_cli, "__version__", "unknown"))
        except Exception:  # noqa: BLE001
            print("unknown")

    cases = [
        ("--llm-approve (intended)", dict(headless=False, llm_approve=True)),
        ("--yolo", dict(headless=False, llm_approve=False, always_approve=True)),
        ("--llm-approve --headless", dict(headless=True, llm_approve=True)),
    ]
    rows = [(label, policy_for(**kw)) for label, kw in cases]

    print()
    width = max(len(l) for l, _ in rows) + 2
    for label, policy in rows:
        print(f"  {label.ljust(width)} -> {policy}")
    print()

    intended = dict(rows)["--llm-approve (intended)"]
    combo = dict(rows)["--llm-approve --headless"]

    if combo == "NeverConfirm" and intended.startswith("ConfirmRisky"):
        print("[VULNERABLE] --headless silently downgrades --llm-approve to NeverConfirm().")
        print("             The user-requested security analyzer is discarded with no warning,")
        print("             so no action is ever risk-gated (CWE-693 / CWE-1188).")
        return 0
    print("[ok] policy selection matches the documented intent.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
