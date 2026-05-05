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


class VerificationEvidence(BaseModel):
    finding_ref: str
    pre_snapshot: EnvironmentSnapshot | None
    post_snapshot: EnvironmentSnapshot
    poc_evidence: PoCEvidence
    re_attack_outcome: ReAttackOutcome
    verified_at: float = Field(default_factory=time.time)


class RLVRReward(BaseModel):
    finding_ref: str
    reward: float  # 0.0, 0.5, or 1.0
    outcome: ReAttackOutcome
    blocked_checks: int = 0
    total_checks: int = 0
    poc_signals_matched: int = 0
    zfp_demoted: bool = False
    computed_at: float = Field(default_factory=time.time)
