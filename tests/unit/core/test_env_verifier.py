"""Unit tests for EnvironmentVerifier — environment-grounded vaccine verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Awaitable, Callable

from decepticon.core.env_verifier import EnvironmentVerifier
from decepticon.schemas.defense_brief import ReAttackOutcome
from decepticon.schemas.env_verification import (
    CheckPhase,
    EnvironmentSnapshot,
    PoCEvidence,
    TargetCheckResult,
    VerificationEvidence,
)
from decepticon.schemas.exploit_spec import (
    CommandOutputCheck,
    ExploitSpec,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def make_runner(
    poc_response: tuple[str, str, int] = ("PWNED root@target", "", 0),
    negative_response: tuple[str, str, int] = ("clean", "", 0),
    check_response: tuple[str, str, int] = ("matched", "", 0),
) -> Callable[[str], Awaitable[tuple[str, str, int]]]:
    """Build a deterministic mock PoCRunner that branches on command shape."""

    async def _run(command: str) -> tuple[str, str, int]:
        if "PWNED" in command or "exploit" in command.lower():
            return poc_response
        if "clean_request" in command or "noop" in command:
            return negative_response
        return check_response

    return _run


def make_spec(
    finding_ref: str = "FIND-001",
    success_patterns: list[str] | None = None,
    negative_command: str | None = None,
) -> ExploitSpec:
    return ExploitSpec(
        finding_ref=finding_ref,
        poc_command="curl -X POST exploit",
        success_patterns=success_patterns or ["PWNED"],
        negative_command=negative_command,
        target_checks=[
            CommandOutputCheck(
                command="echo matched",
                pattern="matched",
                expect_match=True,
            )
        ],
    )


# ── Test 1: Pre-defense exploit succeeds → PASSED, reward 0.0 ──────────────


async def test_pre_defense_exploit_passed(tmp_path: Path) -> None:
    runner = make_runner(poc_response=("PWNED root@target", "", 0))
    verifier = EnvironmentVerifier(tmp_path, runner)
    spec = make_spec()

    pre = await verifier.capture_state(spec, phase=CheckPhase.PRE_DEFENSE)
    # No POST snapshot pretend not yet defended; use pre as both
    evidence = await verifier.verify_blocked(spec, pre=None, post=pre)

    assert evidence.re_attack_outcome == ReAttackOutcome.PASSED
    assert "PWNED" in evidence.poc_evidence.success_signals_matched
    reward = verifier.compute_reward(evidence)
    assert reward.reward == 0.0
    assert reward.outcome == ReAttackOutcome.PASSED


# ── Test 2: Post-defense exploit fails → BLOCKED, reward 1.0 ───────────────


async def test_post_defense_exploit_blocked(tmp_path: Path) -> None:
    runner = make_runner(poc_response=("", "Permission denied", 1))
    verifier = EnvironmentVerifier(tmp_path, runner)
    spec = make_spec()

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)

    assert evidence.re_attack_outcome == ReAttackOutcome.BLOCKED
    assert evidence.poc_evidence.success_signals_matched == []
    reward = verifier.compute_reward(evidence)
    assert reward.reward == 1.0
    assert reward.outcome == ReAttackOutcome.BLOCKED


# ── Test 3: ZFP demotion → ERROR, reward 0.0 ───────────────────────────────


async def test_zfp_demotion_errors(tmp_path: Path) -> None:
    # Both PoC and negative control match success patterns — noise signal
    async def _run(command: str) -> tuple[str, str, int]:
        return ("PWNED everywhere", "", 0)

    verifier = EnvironmentVerifier(tmp_path, _run)
    spec = make_spec(negative_command="curl noop")

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)

    assert evidence.poc_evidence.zfp_demoted is True
    assert evidence.re_attack_outcome == ReAttackOutcome.ERROR
    reward = verifier.compute_reward(evidence)
    assert reward.reward == 0.0
    assert reward.zfp_demoted is True


# ── Test 4: PARTIAL outcome → reward 0.5 ───────────────────────────────────


async def test_partial_reward(tmp_path: Path) -> None:
    runner = make_runner()
    verifier = EnvironmentVerifier(tmp_path, runner)
    pre = EnvironmentSnapshot(
        finding_ref="FIND-002",
        phase=CheckPhase.PRE_DEFENSE,
        results=[
            TargetCheckResult(
                check_id="FIND-002-pre_defense-0",
                kind="command",
                phase=CheckPhase.PRE_DEFENSE,
                positive=True,
            ),
            TargetCheckResult(
                check_id="FIND-002-pre_defense-1",
                kind="command",
                phase=CheckPhase.PRE_DEFENSE,
                positive=True,
            ),
        ],
    )
    post = EnvironmentSnapshot(
        finding_ref="FIND-002",
        phase=CheckPhase.POST_DEFENSE,
        results=[
            TargetCheckResult(
                check_id="FIND-002-post_defense-0",
                kind="command",
                phase=CheckPhase.POST_DEFENSE,
                positive=False,
            ),
            TargetCheckResult(
                check_id="FIND-002-post_defense-1",
                kind="command",
                phase=CheckPhase.POST_DEFENSE,
                positive=True,
            ),
        ],
    )
    evidence = VerificationEvidence(
        finding_ref="FIND-002",
        pre_snapshot=pre,
        post_snapshot=post,
        poc_evidence=PoCEvidence(
            exit_code=0,
            success_signals_matched=["PWNED"],
            zfp_demoted=False,
            output_hash="abc123",
        ),
        re_attack_outcome=ReAttackOutcome.PARTIAL,
    )
    reward = verifier.compute_reward(evidence)
    assert reward.reward == 0.5
    assert reward.outcome == ReAttackOutcome.PARTIAL
    assert reward.blocked_checks == 1
    assert reward.total_checks == 2


# ── Test 5: persist_reward writes valid JSONL line ─────────────────────────


async def test_persist_reward_writes_jsonl(tmp_path: Path) -> None:
    runner = make_runner(poc_response=("", "Permission denied", 1))
    verifier = EnvironmentVerifier(tmp_path, runner)
    spec = make_spec()

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)
    reward = verifier.compute_reward(evidence)
    verifier.persist_reward(reward)

    rewards_path = tmp_path / "rlvr" / "rewards.jsonl"
    assert rewards_path.exists()
    lines = rewards_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["finding_ref"] == "FIND-001"
    assert parsed["reward"] == 1.0
    assert parsed["outcome"] == "blocked"

    # Append-only: second write produces a second line
    verifier.persist_reward(reward)
    lines2 = rewards_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines2) == 2
    json.loads(lines2[1])  # validates JSON


# ── Test 6: spec round-trip via load_spec ──────────────────────────────────


async def test_load_spec_roundtrip(tmp_path: Path) -> None:
    runner = make_runner()
    verifier = EnvironmentVerifier(tmp_path, runner)
    spec = make_spec("FIND-077")
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "FIND-077-exploit-spec.json").write_text(
        spec.model_dump_json(indent=2), encoding="utf-8"
    )
    loaded = verifier.load_spec("FIND-077")
    assert loaded is not None
    assert loaded.finding_ref == "FIND-077"
    assert loaded.success_patterns == ["PWNED"]


async def test_load_spec_missing_returns_none(tmp_path: Path) -> None:
    runner = make_runner()
    verifier = EnvironmentVerifier(tmp_path, runner)
    assert verifier.load_spec("FIND-NONE") is None


# ── Test 7: persist_snapshot + persist_evidence write to disk ──────────────


async def test_persistence_writes_snapshot_and_evidence(tmp_path: Path) -> None:
    runner = make_runner(poc_response=("", "blocked", 1))
    verifier = EnvironmentVerifier(tmp_path, runner)
    spec = make_spec()

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    verifier.persist_snapshot(post)
    snap_path = tmp_path / "verification" / "FIND-001-post_defense-snapshot.json"
    assert snap_path.exists()

    evidence = await verifier.verify_blocked(spec, pre=None, post=post)
    verifier.persist_evidence(evidence)
    evidence_path = tmp_path / "verification" / "FIND-001-evidence.json"
    assert evidence_path.exists()
    parsed = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert parsed["finding_ref"] == "FIND-001"


# ── Test 9: N-run consensus 2-of-3 partial when threshold strict ──────────


async def test_n_run_consensus_2_of_3_partial(tmp_path: Path) -> None:
    """spec.runs=3, min_success_rate=1.0. 1/3 succeeds → success_rate < threshold → PARTIAL."""
    call_count = {"n": 0}

    async def _run(command: str) -> tuple[str, str, int]:
        if "exploit" in command.lower() or "PWNED" in command:
            call_count["n"] += 1
            if call_count["n"] == 1:
                return ("PWNED root@target", "", 0)
            return ("", "Permission denied", 1)
        return ("matched", "", 0)

    verifier = EnvironmentVerifier(tmp_path, _run)
    spec = ExploitSpec(
        finding_ref="FIND-RUN3",
        poc_command="curl -X POST exploit",
        success_patterns=["PWNED"],
        runs=3,
        min_success_rate=1.0,
        target_checks=[
            CommandOutputCheck(command="echo matched", pattern="matched", expect_match=True)
        ],
    )

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)

    assert evidence.consensus is not None
    assert evidence.consensus.n_runs == 3
    assert evidence.consensus.n_success == 1
    assert evidence.re_attack_outcome == ReAttackOutcome.PARTIAL


# ── Test 10: 2-of-3 with relaxed threshold + env unchanged → PASSED ───────


async def test_n_run_consensus_2_of_3_blocked_when_threshold_met(tmp_path: Path) -> None:
    """spec.runs=3, min_success_rate=0.5. 2/3 succeed → PASSED (signals still match)."""
    call_count = {"n": 0}

    async def _run(command: str) -> tuple[str, str, int]:
        if "exploit" in command.lower() or "PWNED" in command:
            call_count["n"] += 1
            if call_count["n"] <= 2:
                return ("PWNED root@target", "", 0)
            return ("", "Permission denied", 1)
        return ("matched", "", 0)

    verifier = EnvironmentVerifier(tmp_path, _run)
    spec = ExploitSpec(
        finding_ref="FIND-RUN3B",
        poc_command="curl -X POST exploit",
        success_patterns=["PWNED"],
        runs=3,
        min_success_rate=0.5,
        target_checks=[
            CommandOutputCheck(command="echo matched", pattern="matched", expect_match=True)
        ],
    )

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)

    assert evidence.consensus is not None
    assert evidence.consensus.n_success == 2
    assert evidence.consensus.success_rate >= 0.5
    assert evidence.re_attack_outcome == ReAttackOutcome.PASSED


# ── Test 11: invalid baseline → ERROR ─────────────────────────────────────


async def test_baseline_invalid_gives_error(tmp_path: Path) -> None:
    """Invalid baseline (PoC fails pre-defense) → verify_blocked returns ERROR."""

    async def _run(_: str) -> tuple[str, str, int]:
        return ("", "Connection refused", 1)

    verifier = EnvironmentVerifier(tmp_path, _run)
    spec = make_spec("FIND-BASE")

    baseline = await verifier.verify_baseline(spec)
    assert baseline.valid is False

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post, baseline=baseline)
    assert evidence.baseline_valid is False
    assert evidence.re_attack_outcome == ReAttackOutcome.ERROR


# ── Test 12: impact_patterns populate evidence + reward.impact_confirmed ──


async def test_impact_patterns_populate_evidence(tmp_path: Path) -> None:
    """impact_patterns matched in PoC output → impact_signals_matched + impact_confirmed."""

    async def _run(command: str) -> tuple[str, str, int]:
        if "exploit" in command.lower() or "PWNED" in command:
            return ("PWNED uid=0 root@target", "", 0)
        return ("matched", "", 0)

    verifier = EnvironmentVerifier(tmp_path, _run)
    spec = ExploitSpec(
        finding_ref="FIND-IMP",
        poc_command="curl -X POST exploit",
        success_patterns=["PWNED"],
        impact_patterns=["uid=0"],
        target_checks=[
            CommandOutputCheck(command="echo matched", pattern="matched", expect_match=True)
        ],
    )

    post = await verifier.capture_state(spec, phase=CheckPhase.POST_DEFENSE)
    evidence = await verifier.verify_blocked(spec, pre=None, post=post)
    assert "uid=0" in evidence.impact_signals_matched
    reward = verifier.compute_reward(evidence)
    assert reward.impact_confirmed is True


# ── Test 13: duplicate detection suppresses second run ────────────────────


async def test_duplicate_detection_suppresses_second(tmp_path: Path) -> None:
    """Same fingerprint on second call → duplicate_of set, outcome ERROR."""
    runner = make_runner(poc_response=("PWNED root@target", "", 0))
    verifier = EnvironmentVerifier(tmp_path, runner)

    spec_a = ExploitSpec(
        finding_ref="FIND-DUP-A",
        poc_command="curl -X POST exploit",
        success_patterns=["PWNED"],
        target_host="10.0.0.5",
        target_checks=[
            CommandOutputCheck(command="echo matched", pattern="matched", expect_match=True)
        ],
    )
    spec_b = ExploitSpec(
        finding_ref="FIND-DUP-B",
        poc_command="curl -X POST exploit",
        success_patterns=["PWNED"],
        target_host="10.0.0.5",
        target_checks=[
            CommandOutputCheck(command="echo matched", pattern="matched", expect_match=True)
        ],
    )

    post_a = await verifier.capture_state(spec_a, phase=CheckPhase.POST_DEFENSE)
    _ = await verifier.verify_blocked(spec_a, pre=None, post=post_a)

    post_b = await verifier.capture_state(spec_b, phase=CheckPhase.POST_DEFENSE)
    evidence_b = await verifier.verify_blocked(spec_b, pre=None, post=post_b)
    assert evidence_b.duplicate_of is not None
    assert evidence_b.re_attack_outcome == ReAttackOutcome.ERROR
