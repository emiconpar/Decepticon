"""Independent environment verifier — no LLM in the verification path."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import time
from pathlib import Path
from typing import Any

from decepticon.schemas.defense_brief import ReAttackOutcome
from decepticon.schemas.env_verification import (
    BaselineEvidence,
    CheckPhase,
    CVSSEstimate,
    EnvironmentSnapshot,
    PoCConsensus,
    PoCEvidence,
    PoCRunResult,
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


# CVSS 3.1 metric weights
_CVSS_AV: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC: dict[str, float] = {"L": 0.77, "H": 0.44}
_CVSS_PR_U: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_PR_C: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS_UI: dict[str, float] = {"N": 0.85, "R": 0.62}
_CVSS_CIA: dict[str, float] = {"N": 0.0, "L": 0.22, "H": 0.56}


def _cvss_roundup(value: float) -> float:
    """Round up to nearest 0.1 per CVSS 3.1 spec."""
    int_val = int(round(value * 100000))
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (math.floor(int_val / 10000.0) + 1) / 10.0


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

    # ── PoC consensus ─────────────────────────────────────────────────────

    async def _run_poc_once(self, spec: ExploitSpec, run_index: int) -> PoCRunResult:
        stdout, stderr, exit_code = await self._runner(spec.poc_command)
        combined = f"{stdout}\n{stderr}"
        signals = _match_signals(combined, spec.success_patterns)
        return PoCRunResult(
            run_index=run_index,
            exit_code=exit_code,
            signals_matched=signals,
            output_hash=_hash_output(stdout, stderr, exit_code),
            stdout_excerpt=stdout[:1600],
            stderr_excerpt=stderr[:800],
            succeeded=len(signals) > 0,
        )

    async def _run_poc_consensus(self, spec: ExploitSpec) -> PoCConsensus:
        run_results: list[PoCRunResult] = []
        for i in range(spec.runs):
            result = await self._run_poc_once(spec, i)
            run_results.append(result)

        n_success = sum(1 for r in run_results if r.succeeded)
        success_rate = n_success / spec.runs

        successful_signal_sets = [set(r.signals_matched) for r in run_results if r.succeeded]
        agreed_signals: list[str] = []
        if successful_signal_sets:
            agreed_signals = list(set.intersection(*successful_signal_sets))

        zfp_demoted = False
        if spec.negative_command and agreed_signals:
            n_out, n_err, _ = await self._runner(spec.negative_command)
            n_combined = f"{n_out}\n{n_err}"
            if _match_signals(n_combined, spec.success_patterns):
                log.warning("%s: ZFP demotion — negative control matched", spec.finding_ref)
                zfp_demoted = True
                agreed_signals = []

        return PoCConsensus(
            n_runs=spec.runs,
            n_success=n_success,
            success_rate=success_rate,
            agreed_signals=agreed_signals,
            zfp_demoted=zfp_demoted,
            run_results=run_results,
        )

    async def verify_baseline(self, spec: ExploitSpec) -> BaselineEvidence:
        consensus = await self._run_poc_consensus(spec)
        valid = (
            not consensus.zfp_demoted
            and consensus.success_rate >= spec.min_success_rate
            and len(consensus.agreed_signals) > 0
        )
        if not valid:
            log.warning(
                "%s: baseline PoC invalid (rate=%.2f zfp=%s signals=%s)",
                spec.finding_ref,
                consensus.success_rate,
                consensus.zfp_demoted,
                consensus.agreed_signals,
            )
        return BaselineEvidence(
            finding_ref=spec.finding_ref,
            valid=valid,
            consensus=consensus,
        )

    # ── Impact + inconclusive + CVSS ──────────────────────────────────────

    def _match_impact_patterns(self, spec: ExploitSpec, combined: str) -> list[str]:
        if not spec.impact_patterns:
            return []
        return _match_signals(combined, spec.impact_patterns)

    def _check_inconclusive(
        self, pre: EnvironmentSnapshot | None, post: EnvironmentSnapshot
    ) -> bool:
        if pre is None or len(pre.results) < 2:
            return False
        host_port_map: dict[str, bool] = {}
        host_service_map: dict[str, bool] = {}

        for result in post.results:
            sig = result.signal
            if result.kind == "port":
                key = f"{sig.get('host')}:{sig.get('port')}"
                host_port_map[key] = result.positive
            elif result.kind == "service":
                url = str(sig.get("url", ""))
                host = url.split("/")[2] if "/" in url else url
                host_service_map[host] = result.positive

        for url_host, svc_positive in host_service_map.items():
            for port_key, port_positive in host_port_map.items():
                if port_key.startswith(url_host) and svc_positive != port_positive:
                    return True
        return False

    def _estimate_cvss(
        self,
        spec: ExploitSpec,
        consensus: PoCConsensus,
        pre: EnvironmentSnapshot | None,
        post: EnvironmentSnapshot,
    ) -> CVSSEstimate:
        # Default: network attack vector if any port/service check, else local
        attack_vector = "L"
        for check in spec.target_checks:
            if isinstance(check, (PortCheck, ServiceCheck)):
                attack_vector = "N"
                break

        attack_complexity = "L"
        privileges_required = "N"
        user_interaction = "N"
        scope = "U"

        # Credentials needed → privs required low
        for check in spec.target_checks:
            if isinstance(check, CredentialCheck):
                privileges_required = "L"
                break

        confidentiality = "N"
        integrity = "N"
        availability = "N"

        # Inspect impact patterns to derive CIA
        impact_blob = " ".join(spec.impact_patterns)
        if re.search(r"uid=0|root:|SYSTEM", impact_blob, re.IGNORECASE):
            confidentiality = "H"
            integrity = "H"
            scope = "C"
        if re.search(r"email|password|secret|key|token", impact_blob, re.IGNORECASE):
            confidentiality = "H"
        if re.search(r"RCE|exec|shell|cmd", impact_blob, re.IGNORECASE):
            integrity = "H"
            availability = "H"

        # No impact patterns → low impact
        if not spec.impact_patterns:
            confidentiality = "L" if consensus.agreed_signals else "N"

        c = _CVSS_CIA[confidentiality]
        i_val = _CVSS_CIA[integrity]
        a = _CVSS_CIA[availability]
        isc_base = 1 - (1 - c) * (1 - i_val) * (1 - a)
        if scope == "U":
            impact_sub = 6.42 * isc_base
            pr_weight = _CVSS_PR_U[privileges_required]
        else:
            impact_sub = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
            pr_weight = _CVSS_PR_C[privileges_required]

        exploitability = (
            8.22
            * _CVSS_AV[attack_vector]
            * _CVSS_AC[attack_complexity]
            * pr_weight
            * _CVSS_UI[user_interaction]
        )

        if impact_sub <= 0:
            base_score = 0.0
        else:
            if scope == "U":
                base_score = _cvss_roundup(min(10.0, impact_sub + exploitability))
            else:
                base_score = _cvss_roundup(min(10.0, 1.08 * (impact_sub + exploitability)))

        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}"
            f"/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        return CVSSEstimate(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
            base_score=base_score,
            vector_string=vector,
        )

    # ── Dedup ─────────────────────────────────────────────────────────────

    def _compute_fingerprint(self, spec: ExploitSpec) -> str:
        parts = [
            spec.poc_command.strip(),
            ",".join(sorted(spec.success_patterns)),
            spec.target_host or "",
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def _dedup_path(self) -> Path:
        return self._workspace / "rlvr" / "dedup.jsonl"

    def is_duplicate(self, spec: ExploitSpec) -> bool:
        path = self._dedup_path()
        if not path.exists():
            return False
        fp = self._compute_fingerprint(spec)
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("fingerprint") == fp and entry.get("finding_ref") != spec.finding_ref:
                    return True
        except OSError:
            return False
        return False

    def _get_duplicate_ref(self, spec: ExploitSpec) -> str | None:
        path = self._dedup_path()
        if not path.exists():
            return None
        fp = self._compute_fingerprint(spec)
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("fingerprint") == fp and entry.get("finding_ref") != spec.finding_ref:
                    ref = entry.get("finding_ref")
                    return str(ref) if ref is not None else None
        except OSError:
            return None
        return None

    def _register_fingerprint(self, spec: ExploitSpec) -> None:
        path = self._dedup_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "fingerprint": self._compute_fingerprint(spec),
            "finding_ref": spec.finding_ref,
            "registered_at": time.time(),
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    # ── Verification entrypoint ───────────────────────────────────────────

    async def verify_blocked(
        self,
        spec: ExploitSpec,
        pre: EnvironmentSnapshot | None,
        post: EnvironmentSnapshot,
        baseline: BaselineEvidence | None = None,
    ) -> VerificationEvidence:
        # 1. Check duplicate
        is_dup = self.is_duplicate(spec)
        dup_ref: str | None = None
        if is_dup:
            dup_ref = self._get_duplicate_ref(spec)
            log.info("%s: duplicate of %s — skipping PoC re-run", spec.finding_ref, dup_ref)
        else:
            self._register_fingerprint(spec)

        # 2. Baseline validity gate
        baseline_valid = True
        if baseline is not None:
            baseline_valid = baseline.valid

        # 3. N-run consensus PoC
        consensus = await self._run_poc_consensus(spec)

        # 4. Match impact patterns over all run output
        all_run_output = "\n".join(
            r.stdout_excerpt + r.stderr_excerpt for r in consensus.run_results
        )
        impact_signals = self._match_impact_patterns(spec, all_run_output)

        # 5. Inconclusive check
        inconclusive = self._check_inconclusive(pre, post)

        # 6. CVSS estimate
        cvss = self._estimate_cvss(spec, consensus, pre, post)

        # 7. Build legacy PoCEvidence (backward compat)
        best_run = max(consensus.run_results, key=lambda r: len(r.signals_matched), default=None)
        legacy_poc = PoCEvidence(
            exit_code=best_run.exit_code if best_run else -1,
            success_signals_matched=consensus.agreed_signals,
            zfp_demoted=consensus.zfp_demoted,
            output_hash=best_run.output_hash if best_run else "",
            stdout_excerpt=best_run.stdout_excerpt if best_run else "",
            stderr_excerpt=best_run.stderr_excerpt if best_run else "",
        )

        # 8. Determine outcome
        outcome = self._determine_outcome_v2(
            consensus=consensus,
            baseline_valid=baseline_valid,
            inconclusive=inconclusive,
            pre=pre,
            post=post,
            is_duplicate=is_dup,
            success_rate_threshold=spec.min_success_rate,
        )

        return VerificationEvidence(
            finding_ref=spec.finding_ref,
            pre_snapshot=pre,
            post_snapshot=post,
            poc_evidence=legacy_poc,
            re_attack_outcome=outcome,
            verified_at=time.time(),
            baseline_evidence=baseline,
            consensus=consensus,
            impact_signals_matched=impact_signals,
            cvss_estimate=cvss,
            duplicate_of=dup_ref,
            baseline_valid=baseline_valid,
            inconclusive=inconclusive,
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

    def _determine_outcome_v2(
        self,
        consensus: PoCConsensus,
        baseline_valid: bool,
        inconclusive: bool,
        pre: EnvironmentSnapshot | None,
        post: EnvironmentSnapshot,
        is_duplicate: bool,
        success_rate_threshold: float,
    ) -> ReAttackOutcome:
        if not baseline_valid:
            return ReAttackOutcome.ERROR
        if consensus.zfp_demoted:
            return ReAttackOutcome.ERROR
        if inconclusive:
            return ReAttackOutcome.ERROR
        if is_duplicate:
            return ReAttackOutcome.ERROR

        if consensus.success_rate < success_rate_threshold and consensus.n_success > 0:
            return ReAttackOutcome.PARTIAL

        if not consensus.agreed_signals:
            return ReAttackOutcome.BLOCKED

        if pre is None:
            return ReAttackOutcome.PASSED

        post_positives = [r.positive for r in post.results]
        pre_positives = [r.positive for r in pre.results]
        if not pre_positives:
            return ReAttackOutcome.PASSED

        flipped = sum(1 for p, q in zip(pre_positives, post_positives) if p and not q)
        if flipped == len(pre_positives):
            return ReAttackOutcome.BLOCKED
        if 0 < flipped < len(pre_positives):
            return ReAttackOutcome.PARTIAL
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

        base_reward = reward_map[evidence.re_attack_outcome]

        consensus = evidence.consensus
        n_runs = 1
        success_rate = 1.0
        impact_confirmed = bool(evidence.impact_signals_matched)

        if consensus is not None:
            n_runs = consensus.n_runs
            success_rate = consensus.success_rate

        # Confidence: success_rate * (1.0 if no impact_patterns OR impact confirmed else 0.7)
        # We can only know if spec had impact_patterns by checking impact_signals_matched
        # plus the absence — but absence is ambiguous. Use evidence-only signal: if any
        # impact signal matched, fully confident; otherwise neutral 1.0 multiplier.
        confidence = success_rate * (
            1.0 if impact_confirmed or not evidence.impact_signals_matched else 0.7
        )

        return RLVRReward(
            finding_ref=evidence.finding_ref,
            reward=base_reward,
            outcome=evidence.re_attack_outcome,
            blocked_checks=blocked_checks,
            total_checks=total,
            poc_signals_matched=len(evidence.poc_evidence.success_signals_matched),
            zfp_demoted=evidence.poc_evidence.zfp_demoted,
            computed_at=time.time(),
            confidence=confidence,
            cvss_score=evidence.cvss_estimate.base_score if evidence.cvss_estimate else None,
            is_duplicate=evidence.duplicate_of is not None,
            impact_confirmed=impact_confirmed,
            baseline_valid=evidence.baseline_valid,
            success_rate=success_rate,
            n_runs=n_runs,
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

    def persist_baseline(self, baseline: BaselineEvidence) -> None:
        out_dir = self._workspace / "verification"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{baseline.finding_ref}-baseline.json"
        path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
        log.debug("Baseline written: %s", path)

    def load_baseline(self, finding_ref: str) -> BaselineEvidence | None:
        path = self._workspace / "verification" / f"{finding_ref}-baseline.json"
        if not path.exists():
            return None
        try:
            return BaselineEvidence.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Could not load baseline %s: %s", finding_ref, exc)
            return None

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
