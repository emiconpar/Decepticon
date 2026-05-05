"""Environment-grounded verification schemas replacing LLM-judged VerificationResult."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from decepticon.schemas.defense_brief import ReAttackOutcome


class CheckPhase(StrEnum):
    PRE_DEFENSE = "pre_defense"
    POST_DEFENSE = "post_defense"


class TargetCheckResult(BaseModel):
    check_id: str
    kind: str
    phase: CheckPhase
    signal: dict[str, Any] = Field(default_factory=dict)
    positive: bool
    raw_excerpt: str = ""


class EnvironmentSnapshot(BaseModel):
    finding_ref: str
    phase: CheckPhase
    results: list[TargetCheckResult] = Field(default_factory=list)
    captured_at: float = Field(default_factory=time.time)


class PoCEvidence(BaseModel):
    exit_code: int
    success_signals_matched: list[str]
    zfp_demoted: bool
    output_hash: str
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""


class PoCRunResult(BaseModel):
    run_index: int
    exit_code: int
    signals_matched: list[str]
    output_hash: str
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    succeeded: bool


class PoCConsensus(BaseModel):
    n_runs: int
    n_success: int
    success_rate: float
    agreed_signals: list[str]
    zfp_demoted: bool
    run_results: list[PoCRunResult]


class BaselineEvidence(BaseModel):
    finding_ref: str
    valid: bool
    consensus: PoCConsensus
    captured_at: float = Field(default_factory=time.time)


class CVSSEstimate(BaseModel):
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"
    base_score: float = 0.0
    vector_string: str = ""


class VerificationEvidence(BaseModel):
    finding_ref: str
    pre_snapshot: EnvironmentSnapshot | None
    post_snapshot: EnvironmentSnapshot
    poc_evidence: PoCEvidence
    re_attack_outcome: ReAttackOutcome
    verified_at: float = Field(default_factory=time.time)
    baseline_evidence: BaselineEvidence | None = None
    consensus: PoCConsensus | None = None
    impact_signals_matched: list[str] = Field(default_factory=list)
    cvss_estimate: CVSSEstimate | None = None
    duplicate_of: str | None = None
    baseline_valid: bool = True
    inconclusive: bool = False


class RLVRReward(BaseModel):
    finding_ref: str
    reward: float  # 0.0, 0.5, or 1.0
    outcome: ReAttackOutcome
    blocked_checks: int = 0
    total_checks: int = 0
    poc_signals_matched: int = 0
    zfp_demoted: bool = False
    computed_at: float = Field(default_factory=time.time)
    confidence: float = 1.0
    cvss_score: float | None = None
    is_duplicate: bool = False
    impact_confirmed: bool = False
    baseline_valid: bool = True
    success_rate: float = 1.0
    n_runs: int = 1
