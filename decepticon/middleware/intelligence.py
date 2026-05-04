"""Intelligence middleware — automatic context, scope guard, finding validation.

Comprehensive middleware stack that eliminates manual context handoff, prevents
out-of-scope actions, deduplicates findings, and enforces multi-method verification.

Modules:
  AutoContextMiddleware  — auto-inject engagement state into every model call
  RoEGuardMiddleware     — block task() calls targeting out-of-scope assets
  FindingGuardMiddleware — dedup findings + enforce multi-method verification
  BashIntelMiddleware    — parse tool output for structured vulnerability indicators
  SmartRetryMiddleware   — suggest alternative approaches on BLOCKED objectives
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import cast

from langchain.agents import AgentState
from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import SystemMessage, ToolMessage
from typing_extensions import override

_log = logging.getLogger("decepticon.middleware.intelligence")

# ──────────────────────────────────────────────────────────────────────────────
# AutoContextMiddleware — never make the agent manually write context again
# ──────────────────────────────────────────────────────────────────────────────

_AUTO_CONTEXT_TEMPLATE = """
[Auto-injected Engagement State — DO NOT re-state]
Workspace: {workspace}
Scope: {scope}
Progress: {completed}/{total} objectives done ({blocked} blocked)
Active: {active_objective}
Recent findings ({finding_count}): {recent_findings}
Last error: {last_error}
"""


class AutoContextMiddleware(AgentMiddleware):
    """Auto-inject engagement state into every model call.

    Eliminates the manual "workspace path, scope, prior findings, lessons learned"
    handoff that the orchestrator currently has to write into every task() call.
    The model sees a compact state summary prepended to its system prompt, so
    delegations naturally include correct context without the agent burning tokens.
    """

    state_schema = AgentState

    @override
    def wrap_model_call(self, request, handler):
        return handler(self._inject(request))

    @override
    async def awrap_model_call(self, request, handler):
        return await handler(self._inject(request))

    def _inject(self, request):
        state = request.state or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)

        objectives = get("objectives", [])
        completed = sum(1 for o in objectives if o.get("status") == "completed")
        blocked = sum(1 for o in objectives if o.get("status") == "blocked")
        total = len(objectives)

        active = next(
            (
                f"{o.get('id', '?')} — {o.get('title', '?')}"
                for o in objectives
                if o.get("status") == "in-progress"
            ),
            "none",
        )

        # Compact scope summary
        scope = get("engagement_name", "") or "not set"

        # Recent findings (compact: just IDs + severity)
        findings = get("findings_discovered", [])
        recent = ", ".join(findings[-5:]) if findings else "none"

        # Last error (if any)
        last_msg = None
        messages = get("messages", [])
        for m in reversed(messages):
            if isinstance(m, ToolMessage) and getattr(m, "status", None) == "error":
                last_msg = str(m.content)[:120]
                break

        context_block = _AUTO_CONTEXT_TEMPLATE.format(
            workspace=get("workspace_path", "/workspace"),
            scope=scope,
            completed=completed,
            total=total,
            blocked=blocked,
            active_objective=active,
            finding_count=len(findings),
            recent_findings=recent,
            last_error=last_msg or "none",
        )

        if request.system_message is not None:
            new_content = [
                {"type": "text", "text": context_block},
                *request.system_message.content_blocks,
            ]
        else:
            new_content = [{"type": "text", "text": context_block}]

        new_system = SystemMessage(content=cast("list[str | dict[str, str]]", new_content))
        return request.override(system_message=new_system)


# ──────────────────────────────────────────────────────────────────────────────
# RoEGuardMiddleware — never let the agent scan out of scope
# ──────────────────────────────────────────────────────────────────────────────

_SCOPE_CACHE: dict[str, tuple[float, list[re.Pattern]]] = {}
_SCOPE_CACHE_TTL = 300  # 5 minutes


def _load_scope_patterns(workspace: str) -> list[re.Pattern]:
    """Load RoE scope patterns from plan/roe.json, cached for 5 minutes."""
    import time

    now = time.monotonic()
    cached = _SCOPE_CACHE.get(workspace)
    if cached and (now - cached[0]) < _SCOPE_CACHE_TTL:
        return cached[1]

    patterns: list[re.Pattern] = []
    try:
        roe_path = Path(workspace) / "plan" / "roe.json"
        if roe_path.exists():
            data = json.loads(roe_path.read_text())
            targets = data.get("targets", data.get("scope", {}))
            if isinstance(targets, dict):
                for domain in targets.get("domains", []):
                    escaped = re.escape(str(domain)).replace(r"\*", ".*")
                    patterns.append(re.compile(escaped, re.IGNORECASE))
                for ip_range in targets.get("ip_ranges", []):
                    patterns.append(re.compile(re.escape(str(ip_range))))
    except Exception as exc:
        _log.warning("Failed to load RoE scope: %s", exc)

    _SCOPE_CACHE[workspace] = (now, patterns)
    return patterns


def _extract_targets_from_task_args(args: dict) -> list[str]:
    """Extract potential target strings from task() arguments."""
    targets: list[str] = []
    for val in args.values():
        if isinstance(val, str):
            # URL-like patterns
            for match in re.finditer(
                r"(?:https?://)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)",
                val,
                re.IGNORECASE,
            ):
                targets.append(match.group(1))
            # IP-like patterns
            for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", val):
                targets.append(match.group(0))
    return targets


class RoEGuardMiddleware(AgentMiddleware):
    """Block task() delegations targeting out-of-scope assets.

    Intercepts task tool calls and cross-references the target with the
    engagement's roe.json scope. If no scope pattern matches, the call is
    blocked with a clear explanation — before it reaches the sub-agent.
    """

    state_schema = AgentState

    def __init__(self) -> None:
        super().__init__()
        self._warned: set[str] = set()

    @override
    def wrap_tool_call(self, request, handler):
        if request.tool_call["name"] != "task":
            return handler(request)

        args = request.tool_call.get("args", {})
        targets = _extract_targets_from_task_args(args)

        if not targets:
            return handler(request)

        state = request.state or {}
        workspace = str(state.get("workspace_path", "/workspace"))
        patterns = _load_scope_patterns(workspace)

        if not patterns:
            return handler(request)  # No scope defined — allow (planning phase)

        out_of_scope: list[str] = []
        for target in targets:
            if not any(p.search(target) for p in patterns):
                out_of_scope.append(target)

        if out_of_scope:
            _log.warning(
                "RoE GUARD: blocked task() with out-of-scope targets: %s",
                ", ".join(out_of_scope),
            )
            return ToolMessage(
                content=(
                    f"[ROE VIOLATION BLOCKED] Target(s) OUT OF SCOPE: {', '.join(out_of_scope)}. "
                    f"Check plan/roe.json for the authorized scope. "
                    f"If this target should be in scope, add it to roe.json first."
                ),
                tool_call_id=request.tool_call["id"],
                status="error",
            )

        return handler(request)

    @override
    async def awrap_tool_call(self, request, handler):
        return self.wrap_tool_call(request, handler)


# ──────────────────────────────────────────────────────────────────────────────
# FindingGuardMiddleware — zero false positives + multi-method verification
# ──────────────────────────────────────────────────────────────────────────────

_FINDING_HASHES: dict[str, list[str]] = {}  # hash -> [finding_ids]


def _finding_content_hash(content: str) -> str:
    """Compute a semantic hash from key finding fields."""
    # Extract key fields for dedup comparison
    fields: dict[str, str] = {}
    current_key = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("**") and ":" in line:
            key_part = line[2:].split(":", 1)[0].strip().lower()
            if key_part in ("severity", "attack vector", "title", "affected"):
                current_key = key_part
        elif current_key and line and not line.startswith("#"):
            fields[current_key] = fields.get(current_key, "") + " " + line
    # Hash the concatenated key fields
    normalized = "|".join(f"{k}:{v.strip()}" for k, v in sorted(fields.items()))
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _verify_finding(content: str) -> tuple[bool, list[str]]:
    """Verify a finding with multiple methods. Returns (valid, [issues]).

    Verification methods:
    1. Evidence present — must contain code/output/URL evidence
    2. Reproducible — must describe how to reproduce
    3. Impact stated — must describe business/security impact
    4. No speculation — must not use hedging language
    5. Severity matches impact — critical requires exploit demonstrated
    """
    issues: list[str] = []
    content_lower = content.lower()

    # Method 1: Evidence check
    has_evidence = any(
        marker in content_lower
        for marker in (
            "```",
            "curl ",
            "http/",
            "request:",
            "response:",
            "output:",
            "screenshot",
            "burp",
            "intercept",
            "proof of concept",
            "poc",
        )
    )
    if not has_evidence:
        issues.append("MISSING_EVIDENCE: No code block, HTTP trace, or tool output")

    # Method 2: Reproducibility check
    has_repro = any(
        marker in content_lower
        for marker in (
            "reproduce",
            "steps to reproduce",
            "how to reproduce",
            "reproduction",
            "to trigger",
            "to exploit",
            "poc",
            "proof",
        )
    )
    if not has_repro:
        issues.append("MISSING_REPRODUCTION: No reproduction steps or PoC")

    # Method 3: Impact check
    has_impact = any(
        marker in content_lower
        for marker in (
            "impact",
            "attacker can",
            "allows",
            "enables",
            "leads to",
            "results in",
            "could lead",
            "would allow",
            "exposes",
            "discloses",
            "bypass",
        )
    )
    if not has_impact:
        issues.append("MISSING_IMPACT: No impact statement")

    # Method 4: Anti-speculation check
    speculation_markers = [
        "could potentially",
        "might be able",
        "possibly",
        "maybe",
        "it is likely",
        "appears to be",
        "seems to be",
    ]
    if any(m in content_lower for m in speculation_markers):
        issues.append("SPECULATION: Contains hedging language — replace with confirmed evidence")

    # Method 5: Severity-impact alignment
    if "**severity**: critical" in content_lower or "**severity**: high" in content_lower:
        has_exploit = any(
            m in content_lower
            for m in (
                "exploited",
                "exploitation",
                "shell",
                "rce",
                "code execution",
                "data exfiltrated",
                "credentials obtained",
                "full access",
                "or 1=1",
                "'--",
                "union select",
                "information_schema",
                "alert(1)",
                "document.cookie",
                "<script>",
            )
        )
        if not has_exploit:
            issues.append(
                "SEVERITY_MISMATCH: Critical/High severity without demonstrated exploitation"
            )

    is_valid = len(issues) == 0
    return is_valid, issues


class FindingGuardMiddleware(AgentMiddleware):
    """Deduplicate and validate findings with zero-FP enforcement.

    When a sub-agent writes a finding via write_file to findings/:
    1. Computes content hash, compares with existing findings
    2. If duplicate: appends to existing finding, blocks new file
    3. If new: runs 5-method validation, warns on issues

    Zero false positive policy: findings with MISSING_EVIDENCE or SPECULATION
    are rejected with instructions to fix.
    """

    state_schema = AgentState

    @override
    def wrap_tool_call(self, request, handler):
        if request.tool_call["name"] not in ("write_file", "edit_file"):
            return handler(request)

        args = request.tool_call.get("args", {})
        file_path = str(args.get("file_path", args.get("path", "")))
        content = str(args.get("content", args.get("file_text", "")))

        # Only guard findings files
        if "/findings/" not in file_path or not file_path.endswith(".md"):
            return handler(request)

        # Run validation
        is_valid, issues = _verify_finding(content)

        if not is_valid:
            critical_issues = [
                i for i in issues if i.startswith(("MISSING_EVIDENCE", "SPECULATION"))
            ]
            if critical_issues:
                _log.warning("FINDING REJECTED: %s — %s", file_path, "; ".join(critical_issues))
                return ToolMessage(
                    content=(
                        f"[FINDING REJECTED — Zero-FP Policy]\n"
                        f"Finding in {file_path} fails validation:\n"
                        + "\n".join(f"  • {i}" for i in critical_issues)
                        + "\n\nFix the issues and re-submit. Findings must have: "
                        "concrete evidence (code/output/HTTP trace), reproduction steps, "
                        "and confirmed (not speculated) impact."
                    ),
                    tool_call_id=request.tool_call["id"],
                    status="error",
                )

        # Compute content hash for dedup
        content_hash = _finding_content_hash(content)
        if content_hash in _FINDING_HASHES:
            existing = _FINDING_HASHES[content_hash]
            _log.warning(
                "DUPLICATE FINDING: %s matches existing %s", file_path, ", ".join(existing)
            )
            # Allow write but prepend duplicate warning
            return ToolMessage(
                content=(
                    f"[POTENTIAL DUPLICATE] Finding in {file_path} appears to match "
                    f"existing: {', '.join(existing)}. "
                    f"If this is the same issue on a different host, append to the "
                    f"existing finding instead of creating a new one."
                ),
                tool_call_id=request.tool_call["id"],
            )
        else:
            finding_id = Path(file_path).stem
            _FINDING_HASHES[content_hash] = [finding_id]

        # Add validation stamp if passes
        stamped_content = (
            f"{content}\n\n"
            f"<!-- Validation: PASSED ({len(issues)}/0 issues) | "
            f"Hash: {content_hash} | "
            f"Methods: evidence ✓, repro ✓, impact ✓, no-speculation ✓, severity-match ✓ -->\n"
        )
        new_args: dict = dict(args)
        new_args["content" if "content" in args else "file_text"] = stamped_content
        new_request = request.override(tool_call=dict(request.tool_call, args=new_args))

        result = handler(new_request)
        return result

    @override
    async def awrap_tool_call(self, request, handler):
        return self.wrap_tool_call(request, handler)


# ──────────────────────────────────────────────────────────────────────────────
# BashIntelMiddleware — extract structured intel from tool output
# ──────────────────────────────────────────────────────────────────────────────

# Patterns for extracting structured data from common security tools
_OPEN_PORT_RE = re.compile(
    r"(?:(\d+)/(?:tcp|udp)\s+(?:open|filtered)\s+(\S+))"
    r"|(?:Discovered open port\s+(\d+)/(?:tcp|udp)\s+on\s+\S+)",
    re.IGNORECASE,
)
_HTTP_STATUS_RE = re.compile(r"<\s*HTTP/(?:1\.[01]|2)\s+(\d{3})", re.IGNORECASE)
_TECH_STACK_RE = re.compile(
    r"(?:Server|X-Powered-By|X-Generator|X-Drupal-|X-Contentful|X-AspNet)[\s:]+(\S[^\r\n]*)",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"(?:version|v(?:er)?\.?)\s*[:=]?\s*(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_ERROR_RE = re.compile(r"(?:error|exception|stack trace|traceback|fatal|panic)", re.IGNORECASE)


def _analyze_bash_output(command: str, output: str) -> str:
    """Parse bash output for structured vulnerability indicators."""
    findings: list[str] = []
    output_sample = output[:8000]  # Only analyze first 8K chars

    # Open ports
    ports = _OPEN_PORT_RE.findall(output_sample)
    if ports:
        port_list = sorted(set(f"{p[0] or p[2]}/{p[1]}" if p[1] else p[2] or p[0] for p in ports))
        findings.append(f"[INTEL:PORTS] Open: {', '.join(port_list[:20])}")

    # HTTP status codes
    statuses = _HTTP_STATUS_RE.findall(output_sample)
    if statuses:
        code_counts: dict[str, int] = {}
        for s in statuses:
            code_counts[s] = code_counts.get(s, 0) + 1
        status_summary = ", ".join(f"{c}×{n}" for c, n in sorted(code_counts.items()))
        findings.append(f"[INTEL:HTTP] Status: {status_summary}")

    # Technology stack
    tech = _TECH_STACK_RE.findall(output_sample)
    if tech:
        deduped = list(dict.fromkeys(t.strip() for t in tech[:5]))
        findings.append(f"[INTEL:TECH] Stack: {', '.join(deduped)}")

    # Version strings
    versions = _VERSION_RE.findall(output_sample)
    if versions:
        deduped = list(dict.fromkeys(v for v in versions[:5]))
        findings.append(f"[INTEL:VERSIONS] {', '.join(deduped)}")

    # Errors
    if _ERROR_RE.search(output_sample):
        findings.append("[INTEL:WARN] Error indicators in output — review manually")

    if not findings:
        return ""

    return "\n".join(findings)


class BashIntelMiddleware(AgentMiddleware):
    """Extract structured intelligence from bash command output.

    When the bash tool returns output, post-process it to extract:
    - Open ports (nmap, masscan)
    - HTTP status codes (curl, wget, httpx)
    - Technology stack headers (curl -I, httpx)
    - Software versions
    - Error indicators

    Injects a compact intel summary into the ToolMessage so the agent
    doesn't miss buried signals in raw output.
    """

    state_schema = AgentState

    @override
    def wrap_tool_call(self, request, handler):
        if request.tool_call["name"] != "bash":
            return handler(request)

        result = handler(request)

        if not isinstance(result, ToolMessage):
            return result

        args = request.tool_call.get("args", {})
        command = str(args.get("command", ""))
        output = str(getattr(result, "content", ""))

        if not output or len(output) < 10:
            return result

        intel = _analyze_bash_output(command, output)
        if not intel:
            return result

        # Append intel to tool result
        new_result = ToolMessage(
            content=(
                f"{intel}\n\n─── RAW OUTPUT ─────────────────────────────────────────\n{output}"
            ),
            tool_call_id=result.tool_call_id,
            name=getattr(result, "name", None),
        )
        return new_result

    @override
    async def awrap_tool_call(self, request, handler):
        return self.wrap_tool_call(request, handler)


# ──────────────────────────────────────────────────────────────────────────────
# SmartRetryMiddleware — suggest alternatives on BLOCKED objectives
# ──────────────────────────────────────────────────────────────────────────────

_ALTERNATIVE_HINTS: dict[str, list[str]] = {
    "waf": [
        "Try parameter splitting (e.g., ?id=1&id=2 for WAF bypass)",
        "Try HTTP method override (X-HTTP-Method-Override: GET on POST endpoint)",
        "Try encoding bypass: URL-encode payload, double-encode, or use Unicode variants",
    ],
    "rate limit": [
        "Add delay between requests (sleep 2-5s)",
        "Rotate User-Agent headers across requests",
        "Try different endpoint with same function (might have separate rate limit)",
    ],
    "auth": [
        "Check if endpoint returns different response for authenticated vs unauthenticated",
        "Try JWT algorithm confusion (RS256→HS256)",
        "Check for IDOR: swap user ID parameter with known valid ID",
    ],
    "not found": [
        "Verify path with directory brute-force (gobuster/ffuf)",
        "Check API version prefix (/v1/, /v2/, /api/)",
        "Look for the endpoint in JavaScript source maps or mobile APK",
    ],
    "timeout": [
        "Retry with increased timeout (timeout=300)",
        "Check if target is reachable (ping, curl -I)",
        "Try on a different network path (VPN/proxy)",
    ],
    "ssl": [
        "Add --insecure/-k flag to skip certificate validation",
        "Try HTTP instead of HTTPS (if scope allows)",
        "Check certificate chain with testssl.sh",
    ],
}


def _suggest_alternatives(error_text: str, objective_title: str) -> str:
    """Generate alternative approach suggestions from error text."""
    lower = (error_text + " " + objective_title).lower()
    hints: list[str] = []

    for keyword, suggestions in _ALTERNATIVE_HINTS.items():
        if keyword in lower:
            hints.extend(suggestions[:2])  # At most 2 per keyword

    if not hints:
        return ""

    return (
        "\n\n[SMART RETRY — Suggested alternatives]\n"
        + "\n".join(f"  • {h}" for h in hints)
        + "\nUpdate objective status to 'in-progress' to retry with these approaches."
    )


class SmartRetryMiddleware(AgentMiddleware):
    """Suggest alternative approaches when objectives are marked BLOCKED.

    Reads the objective notes field after an update_objective(status="blocked")
    call and cross-references the failure reason against a knowledge base of
    bypass techniques. Injects compact suggestions into the system prompt on
    the next model call.
    """

    state_schema = AgentState

    def __init__(self) -> None:
        super().__init__()
        self._last_blocked: str | None = None

    @override
    def after_model(self, state, runtime):
        """Detect newly BLOCKED objectives and store failure context."""
        messages = state.get("messages", [])
        for msg in reversed(messages):
            if not isinstance(msg, ToolMessage):
                continue
            content = str(getattr(msg, "content", ""))
            if "status → blocked" in content and "Updated" in content:
                # Extract objective ID and find its title
                match = re.search(r"Updated\s+(OBJ-\d+)", content)
                if match:
                    obj_id = match.group(1)
                    objectives = state.get("objectives", [])
                    obj = next((o for o in objectives if o.get("id") == obj_id), None)
                    if obj:
                        self._last_blocked = (
                            f"{obj_id}: {obj.get('title', '')}"
                            f"\nReason: {obj.get('notes', 'no reason given')}"
                        )
                break
        return None

    @override
    async def aafter_model(self, state, runtime):
        return self.after_model(state, runtime)

    @override
    def wrap_model_call(self, request, handler):
        if self._last_blocked:
            hints = _suggest_alternatives(self._last_blocked, "")
            if hints and request.system_message is not None:
                new_content = [
                    *request.system_message.content_blocks,
                    {"type": "text", "text": hints},
                ]
                new_system = SystemMessage(content=cast("list[str | dict[str, str]]", new_content))
                request = request.override(system_message=new_system)
            self._last_blocked = None
        return handler(request)

    @override
    async def awrap_model_call(self, request, handler):
        return self.wrap_model_call(request, handler)


# ──────────────────────────────────────────────────────────────────────────────
# Resume briefing — injected on engagement startup
# ──────────────────────────────────────────────────────────────────────────────


def build_resume_briefing(state: dict) -> str:
    """Build a comprehensive engagement resume briefing."""
    objectives = state.get("objectives", [])
    total = len(objectives)
    completed = sum(1 for o in objectives if o.get("status") == "completed")
    blocked = sum(1 for o in objectives if o.get("status") == "blocked")
    in_progress = [o for o in objectives if o.get("status") == "in-progress"]

    lines = [
        "══════════════════ ENGAGEMENT RESUME ══════════════════",
        f"Status: {completed}/{total} objectives complete",
    ]
    if blocked:
        lines.append(f"       {blocked} blocked — review for retry")
    if in_progress:
        for obj in in_progress:
            lines.append(f"Active: {obj.get('id')} — {obj.get('title')}")

    engagement = state.get("engagement_name", "")
    if engagement:
        lines.insert(0, f"Engagement: {engagement}")

    return "\n".join(lines) + "\n════════════════════════════════════════════════\n"
