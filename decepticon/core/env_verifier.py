"""Independent environment verifier — no LLM in the verification path."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from decepticon.schemas.defense_brief import ReAttackOutcome
from decepticon.schemas.env_verification import (
    CheckPhase,
    EnvironmentSnapshot,
    PoCEvidence,
    RLVRReward,
    TargetCheckResult,
    VerificationEvidence,
)
from decepticon.schemas.exploit_spec import (
    CommandOutputCheck,
    CredentialCheck,
    ExploitSpec,
    FileCheck,
    PortCheck,
    ServiceCheck,
    TargetCheck,
)
from decepticon.tools.research.poc import PoCRunner, _hash_output, _match_signals

log = logging.getLogger("decepticon.core.env_verifier")


class EnvironmentVerifier:
    """Replays ExploitSpec against the sandbox to produce grounded RLVRReward.

    No LLM is in the verification path. All reward signal comes from:
    - PoC command exit code + regex signal matching
    - Environment probe flips (pre → post defense)
    - ZFP negative control demotion
    """

    def __init__(
        self,
        workspace: Path,
        runner: PoCRunner,
        http_session: Any = None,
    ) -> None:
        self._workspace = workspace
        self._runner = runner
        self._http = http_session

    # ── Spec I/O ──────────────────────────────────────────────────────────

    def load_spec(self, finding_ref: str) -> ExploitSpec | None:
        path = self._workspace / "findings" / f"{finding_ref}-exploit-spec.json"
        if not path.exists():
            return None
        try:
            return ExploitSpec.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Could not load exploit spec for %s: %s", finding_ref, exc)
            return None

    def load_snapshot(self, finding_ref: str, phase: CheckPhase) -> EnvironmentSnapshot | None:
        path = self._workspace / "verification" / f"{finding_ref}-{phase.value}-snapshot.json"
        if not path.exists():
            return None
        try:
            return EnvironmentSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Could not load snapshot %s/%s: %s", finding_ref, phase, exc)
            return None

    # ── Environment probing ───────────────────────────────────────────────

    async def capture_state(self, spec: ExploitSpec, phase: CheckPhase) -> EnvironmentSnapshot:
        results: list[TargetCheckResult] = []
        for i, check in enumerate(spec.target_checks):
            check_id = f"{spec.finding_ref}-{phase.value}-{i}"
            result = await self._run_check(check_id, check, phase)
            results.append(result)
        return EnvironmentSnapshot(
            finding_ref=spec.finding_ref,
            phase=phase,
            results=results,
            captured_at=time.time(),
        )

    async def _run_check(
        self, check_id: str, check: TargetCheck, phase: CheckPhase
    ) -> TargetCheckResult:
        try:
            if isinstance(check, PortCheck):
                return await self._check_port(check_id, check, phase)
            elif isinstance(check, ServiceCheck):
                return await self._check_service(check_id, check, phase)
            elif isinstance(check, (CredentialCheck, CommandOutputCheck)):
                return await self._check_command(check_id, check, phase)
            elif isinstance(check, FileCheck):
                return await self._check_file(check_id, check, phase)
            else:
                return TargetCheckResult(
                    check_id=check_id,
                    kind="unknown",
                    phase=phase,
                    signal={},
                    positive=False,
                    raw_excerpt="unknown check kind",
                )
        except Exception as exc:
            log.warning("Check %s failed: %s", check_id, exc)
            return TargetCheckResult(
                check_id=check_id,
                kind=getattr(check, "kind", "unknown"),
                phase=phase,
                signal={"error": str(exc)},
                positive=False,
                raw_excerpt=str(exc)[:500],
            )

    async def _check_port(
        self, check_id: str, check: PortCheck, phase: CheckPhase
    ) -> TargetCheckResult:
        cmd = f"nmap -p {check.port} {check.host} --open -oG - 2>/dev/null | grep -c 'open'"
        stdout, stderr, _code = await self._runner(cmd)
        combined = f"{stdout}\n{stderr}"
        is_open = bool(re.search(r"[1-9]", stdout.strip()))
        return TargetCheckResult(
            check_id=check_id,
            kind="port",
            phase=phase,
            signal={"host": check.host, "port": check.port, "open": is_open},
            positive=is_open,
            raw_excerpt=combined[:500],
        )

    async def _check_service(
        self, check_id: str, check: ServiceCheck, phase: CheckPhase
    ) -> TargetCheckResult:
        cmd = f"curl -s -o /tmp/_svc_check -w '%{{http_code}}' --max-time 10 {check.url!r}"
        stdout, _stderr, _code = await self._runner(cmd)
        status_str = stdout.strip()
        try:
            status = int(status_str)
        except ValueError:
            status = 0
        status_ok = status == check.expected_status
        body_ok = True
        raw = ""
        if check.body_pattern:
            body_stdout, _, _ = await self._runner("cat /tmp/_svc_check 2>/dev/null || true")
            raw = body_stdout[:500]
            body_ok = bool(re.search(check.body_pattern, body_stdout, re.DOTALL | re.IGNORECASE))
        positive = status_ok and body_ok
        return TargetCheckResult(
            check_id=check_id,
            kind="service",
            phase=phase,
            signal={"url": check.url, "status": status, "body_match": body_ok},
            positive=positive,
            raw_excerpt=raw or status_str,
        )

    async def _check_command(
        self,
        check_id: str,
        check: CredentialCheck | CommandOutputCheck,
        phase: CheckPhase,
    ) -> TargetCheckResult:
        cmd = check.command
        pattern = check.success_pattern if isinstance(check, CredentialCheck) else check.pattern
        expect = True if isinstance(check, CredentialCheck) else check.expect_match
        stdout, stderr, code = await self._runner(cmd)
        combined = f"{stdout}\n{stderr}"
        matched = bool(re.search(pattern, combined, re.DOTALL | re.IGNORECASE))
        positive = matched if expect else not matched
        return TargetCheckResult(
            check_id=check_id,
            kind=check.kind,
            phase=phase,
            signal={"matched": matched, "expect_match": expect, "exit_code": code},
            positive=positive,
            raw_excerpt=combined[:500],
        )

    async def _check_file(
        self, check_id: str, check: FileCheck, phase: CheckPhase
    ) -> TargetCheckResult:
        stdout, _, _ = await self._runner(f"test -f {check.path!r} && echo EXISTS || echo MISSING")
        exists = "EXISTS" in stdout
        exists_ok = exists == check.must_exist
        content_ok = True
        raw = ""
        if check.content_pattern and exists:
            cat_out, _, _ = await self._runner(f"cat {check.path!r} 2>/dev/null || true")
            raw = cat_out[:500]
            content_ok = bool(re.search(check.content_pattern, cat_out, re.DOTALL | re.IGNORECASE))
        positive = exists_ok and content_ok
        return TargetCheckResult(
            check_id=check_id,
            kind="file",
            phase=phase,
            signal={
                "path": check.path,
                "exists": exists,
                "content_match": content_ok,
            },
            positive=positive,
            raw_excerpt=raw or stdout[:200],
        )

    # ── PoC re-run + verification ─────────────────────────────────────────

    async def verify_blocked(
        self,
        spec: ExploitSpec,
        pre: EnvironmentSnapshot | None,
        post: EnvironmentSnapshot,
    ) -> VerificationEvidence:
        stdout, stderr, exit_code = await self._runner(spec.poc_command)
        combined = f"{stdout}\n{stderr}"
        success_signals = _match_signals(combined, spec.success_patterns)
        zfp_demoted = False
        if spec.negative_command:
            n_out, n_err, _ = await self._runner(spec.negative_command)
            n_combined = f"{n_out}\n{n_err}"
            if _match_signals(n_combined, spec.success_patterns):
                log.warning(
                    "%s: negative control matched success patterns — ZFP demotion",
                    spec.finding_ref,
                )
                success_signals = []
                zfp_demoted = True

        poc_evidence = PoCEvidence(
            exit_code=exit_code,
            success_signals_matched=success_signals,
            zfp_demoted=zfp_demoted,
            output_hash=_hash_output(stdout, stderr, exit_code),
            stdout_excerpt=stdout[:1600],
            stderr_excerpt=stderr[:800],
        )

        outcome = self._determine_outcome(poc_evidence, pre, post)
        return VerificationEvidence(
            finding_ref=spec.finding_ref,
            pre_snapshot=pre,
            post_snapshot=post,
            poc_evidence=poc_evidence,
            re_attack_outcome=outcome,
            verified_at=time.time(),
        )

    def _determine_outcome(
        self,
        poc: PoCEvidence,
        pre: EnvironmentSnapshot | None,
        post: EnvironmentSnapshot,
    ) -> ReAttackOutcome:
        if poc.zfp_demoted:
            return ReAttackOutcome.ERROR
        if not poc.success_signals_matched:
            return ReAttackOutcome.BLOCKED
        # Signals still matched — check if any environment checks flipped
        if pre is None:
            return ReAttackOutcome.PASSED
        post_positives = [r.positive for r in post.results]
        pre_positives = [r.positive for r in pre.results]
        flipped = sum(1 for p, q in zip(pre_positives, post_positives) if p and not q)
        if 0 < flipped < len(pre_positives):
            return ReAttackOutcome.PARTIAL
        if flipped == len(pre_positives) and len(pre_positives) > 0:
            return ReAttackOutcome.BLOCKED
        return ReAttackOutcome.PASSED

    # ── Reward computation ────────────────────────────────────────────────

    def compute_reward(self, evidence: VerificationEvidence) -> RLVRReward:
        reward_map = {
            ReAttackOutcome.BLOCKED: 1.0,
            ReAttackOutcome.PARTIAL: 0.5,
            ReAttackOutcome.PASSED: 0.0,
            ReAttackOutcome.ERROR: 0.0,
        }
        pre = evidence.pre_snapshot
        post = evidence.post_snapshot
        total = len(post.results)
        blocked_checks = 0
        if pre is not None:
            for p, q in zip(pre.results, post.results):
                if p.positive and not q.positive:
                    blocked_checks += 1
        return RLVRReward(
            finding_ref=evidence.finding_ref,
            reward=reward_map[evidence.re_attack_outcome],
            outcome=evidence.re_attack_outcome,
            blocked_checks=blocked_checks,
            total_checks=total,
            poc_signals_matched=len(evidence.poc_evidence.success_signals_matched),
            zfp_demoted=evidence.poc_evidence.zfp_demoted,
            computed_at=time.time(),
        )

    # ── Persistence ───────────────────────────────────────────────────────

    def persist_snapshot(self, snapshot: EnvironmentSnapshot) -> None:
        out_dir = self._workspace / "verification"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{snapshot.finding_ref}-{snapshot.phase.value}-snapshot.json"
        path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        log.debug("Snapshot written: %s", path)

    def persist_evidence(self, evidence: VerificationEvidence) -> None:
        out_dir = self._workspace / "verification"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{evidence.finding_ref}-evidence.json"
        path.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
        log.debug("Evidence written: %s", path)

    def persist_reward(self, reward: RLVRReward) -> None:
        rlvr_dir = self._workspace / "rlvr"
        rlvr_dir.mkdir(parents=True, exist_ok=True)
        rewards_path = rlvr_dir / "rewards.jsonl"
        with rewards_path.open("a", encoding="utf-8") as f:
            f.write(reward.model_dump_json() + "\n")
        log.info(
            "RLVR reward written: finding=%s outcome=%s reward=%.1f",
            reward.finding_ref,
            reward.outcome,
            reward.reward,
        )
