"""Decepticon middleware — custom AgentMiddleware implementations."""

from decepticon.middleware.engagement import EngagementContextMiddleware
from decepticon.middleware.filesystem import FilesystemMiddleware
from decepticon.middleware.intelligence import (
    AutoContextMiddleware,
    BashIntelMiddleware,
    FindingGuardMiddleware,
    RoEGuardMiddleware,
    SmartRetryMiddleware,
    build_resume_briefing,
)
from decepticon.middleware.notifications import (
    SandboxNotificationMiddleware,
)
from decepticon.middleware.opplan import OPPLANMiddleware
from decepticon.middleware.skills import SkillsMiddleware

__all__ = [
    "AutoContextMiddleware",
    "BashIntelMiddleware",
    "EngagementContextMiddleware",
    "FilesystemMiddleware",
    "FindingGuardMiddleware",
    "OPPLANMiddleware",
    "RoEGuardMiddleware",
    "SandboxNotificationMiddleware",
    "SkillsMiddleware",
    "SmartRetryMiddleware",
    "build_resume_briefing",
]
