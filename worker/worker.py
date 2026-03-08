#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "claude-agent-sdk>=0.1.48",
#     "anyio>=4.0.0",
# ]
# ///
"""
OSS Watchdog Worker

Watches the job queue and processes pending security analyses using Claude Agent SDK.
Uses the SDK's built-in tools (Bash, Read, Glob, Grep) plus a custom write_report tool.

Usage:
    uv run worker.py              # Process all pending jobs
    uv run worker.py --watch      # Watch mode, poll every 30s
    uv run worker.py --job <id>   # Process specific job
"""

import asyncio
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    tool,
)
from claude_agent_sdk.types import HookContext, HookInput, HookJSONOutput

# Paths
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent
SITE_DIR = ROOT_DIR / "site"
QUEUE_FILE = SITE_DIR / "data" / "queue" / "jobs.json"
REPORTS_DIR = SITE_DIR / "data" / "reports"
REPORTS_INDEX = REPORTS_DIR / "index.json"
PROMPT_FILE = SCRIPT_DIR / "PROMPT.md"
CLONE_BASE = Path("/tmp/oss-watchdog-analysis")

# Model to use
MODEL = "claude-sonnet-4-20250514"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_queue():
    return load_json(QUEUE_FILE) or {"jobs": []}


def save_queue(q):
    save_json(QUEUE_FILE, q)


def load_reports_index():
    return load_json(REPORTS_INDEX) or {"reports": []}


def save_reports_index(idx):
    save_json(REPORTS_INDEX, idx)


def get_pending_jobs():
    q = load_queue()
    return [j for j in q["jobs"] if j.get("status") == "pending"]


def update_job_status(job_id, status, error=None):
    q = load_queue()
    for job in q["jobs"]:
        if job["id"] == job_id:
            job["status"] = status
            if error:
                job["error"] = error
            break
    q["lastUpdated"] = now()
    save_queue(q)


def remove_job(job_id):
    q = load_queue()
    q["jobs"] = [j for j in q["jobs"] if j["id"] != job_id]
    q["lastUpdated"] = now()
    save_queue(q)


def add_report_to_index(report):
    """Add report summary to reports index."""
    idx = load_reports_index()
    idx["reports"] = [r for r in idx["reports"] if r["id"] != report["id"]]
    idx["reports"].insert(
        0,
        {
            "id": report["id"],
            "owner": report["owner"],
            "repo": report["repo"],
            "commit": report.get("commit", "unknown"),
            "analyzed": report["analyzed"],
            "ecosystem": report.get("primaryEcosystem", "unknown"),
            "risk": report["risk"],
            "verdict": report["verdict"],
            "keyFinding": report["keyFinding"],
        },
    )
    idx["lastUpdated"] = now()
    save_reports_index(idx)


# ─────────────────────────────────────────────────────────────────────────────
# Custom write_report tool (as in-process MCP server)
# ─────────────────────────────────────────────────────────────────────────────


def create_report_tool(job: dict):
    """Create a write_report tool configured for the current job."""

    @tool(
        "write_report",
        "Write the final JSON security report. Call this when analysis is complete.",
        {
            "verdict": str,
            "risk": str,
            "keyFinding": str,
            "commit": str,
            "stars": int,
            "forks": int,
            "primaryEcosystem": str,
            "overview": str,
            "legitimacyIndicators": dict,
            "securityAnalysis": dict,
            "trustSignals": dict,
            "installationSafety": dict,
            "recommendations": list,
            "notes": str,
        },
    )
    async def write_report(args: dict[str, Any]) -> dict[str, Any]:
        """Write the final security report JSON."""
        report = {
            "id": job["id"],
            "url": job["url"],
            "owner": job["owner"],
            "repo": job["repo"],
            "analyzed": today(),
            "sopVersion": "1.4",
            **args,
        }

        # Validate required fields
        required = ["verdict", "risk", "keyFinding"]
        missing = [f for f in required if f not in report or not report[f]]
        if missing:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"ERROR: Report missing required fields: {missing}",
                    }
                ],
                "is_error": True,
            }

        # Write report
        report_path = REPORTS_DIR / f"{job['id']}.json"
        save_json(report_path, report)

        return {
            "content": [
                {"type": "text", "text": f"SUCCESS: Report written to {report_path}"}
            ]
        }

    return write_report


# ─────────────────────────────────────────────────────────────────────────────
# Security hooks
# ─────────────────────────────────────────────────────────────────────────────


async def block_dangerous_commands(
    input_data: HookInput, tool_use_id: str | None, context: HookContext
) -> HookJSONOutput:
    """Block dangerous shell commands for security."""
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    if tool_name != "Bash":
        return {}

    command = tool_input.get("command", "")

    # Patterns to block
    dangerous_patterns = [
        "rm -rf /",
        "sudo ",
        "> /etc",
        "chmod 777",
        "curl | bash",
        "curl | sh",
        "wget | bash",
        "wget | sh",
        "mkfs",
        "dd if=",
        ":(){:|:&};:",  # fork bomb
    ]

    for pattern in dangerous_patterns:
        if pattern in command:
            return {
                "reason": f"Blocked dangerous command pattern: {pattern}",
                "systemMessage": "Command blocked for security",
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Security policy blocks dangerous commands: {pattern}",
                },
            }

    return {}


async def restrict_file_access(
    input_data: HookInput, tool_use_id: str | None, context: HookContext
) -> HookJSONOutput:
    """Restrict file access to clone directory only."""
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Tools that access files
    if tool_name not in ["Read", "Write", "Edit", "MultiEdit"]:
        return {}

    file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
    if not file_path:
        return {}

    # Resolve and check path
    try:
        resolved = Path(file_path).resolve()
        allowed_paths = [CLONE_BASE, REPORTS_DIR]

        if not any(str(resolved).startswith(str(p)) for p in allowed_paths):
            return {
                "reason": f"File access restricted to analysis directories",
                "systemMessage": f"Cannot access files outside {CLONE_BASE}",
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"File access restricted to {CLONE_BASE} and {REPORTS_DIR}",
                },
            }
    except Exception:
        pass

    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Analysis runner
# ─────────────────────────────────────────────────────────────────────────────


def build_system_prompt(job: dict) -> str:
    """Build the system prompt for Claude."""
    sop = PROMPT_FILE.read_text()

    return f"""{sop}

## Current Job

- **Job ID**: {job["id"]}
- **URL**: {job["url"]}
- **Owner**: {job["owner"]}
- **Repo**: {job["repo"]}
- **Clone to**: {CLONE_BASE / job["id"]}
- **Options**: {json.dumps(job.get("options", {}))}
- **Today's Date**: {today()}

Begin by cloning the repository to {CLONE_BASE / job["id"]}, then systematically analyze it following the SOP.
When complete, call the write_report tool with all required fields."""


async def run_analysis(job: dict) -> bool:
    """Run the security analysis using Claude Agent SDK."""
    job_id = job["id"]
    print(f"\n{'=' * 60}")
    print(f"Processing: {job['owner']}/{job['repo']}")
    print(f"Job ID: {job_id}")
    print(f"{'=' * 60}\n")

    update_job_status(job_id, "processing")

    # Ensure clone base exists
    CLONE_BASE.mkdir(parents=True, exist_ok=True)

    # Create the write_report tool for this job
    write_report_tool = create_report_tool(job)

    # Create MCP server with the report tool
    report_server = create_sdk_mcp_server(
        name="watchdog",
        version="1.0.0",
        tools=[write_report_tool],
    )

    # Configure Claude with built-in tools + our custom tool
    options = ClaudeAgentOptions(
        model=MODEL,
        system_prompt=build_system_prompt(job),
        cwd=str(CLONE_BASE),
        # Use built-in Claude Code tools
        tools=["Bash", "Read", "Glob", "Grep"],
        # Add our custom MCP server
        mcp_servers={"watchdog": report_server},
        # Allow all tools we need
        allowed_tools=[
            "Bash",
            "Read",
            "Glob",
            "Grep",
            "mcp__watchdog__write_report",
        ],
        # Security hooks
        hooks={
            "PreToolUse": [
                HookMatcher(matcher="Bash", hooks=[block_dangerous_commands]),
                HookMatcher(
                    matcher="Read|Write|Edit|MultiEdit", hooks=[restrict_file_access]
                ),
            ],
        },
        # Auto-accept tool use (we control via hooks)
        permission_mode="acceptEdits",
        max_turns=100,
    )

    report_written = False

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(
                "Analyze this repository for security risks. Clone it first, then follow the SOP. "
                "When done, call write_report with the complete analysis."
            )

            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text = (
                                block.text[:200] + "..."
                                if len(block.text) > 200
                                else block.text
                            )
                            print(f"  Claude: {text}")
                        elif isinstance(block, ToolUseBlock):
                            print(f"  Tool: {block.name}")
                            if block.name == "mcp__watchdog__write_report":
                                print("    -> Writing report...")
                        elif isinstance(block, ToolResultBlock):
                            if block.content and "SUCCESS" in str(block.content):
                                report_written = True

                elif isinstance(message, ResultMessage):
                    print(f"\n  Completed in {message.duration_ms}ms")
                    if message.total_cost_usd:
                        print(f"  Cost: ${message.total_cost_usd:.4f}")

        # Verify report was created
        report_path = REPORTS_DIR / f"{job_id}.json"
        if not report_path.exists():
            raise Exception("Report was not written")

        report = load_json(report_path)
        if not report:
            raise Exception("Report is invalid JSON")

        # Add to index
        add_report_to_index(report)

        # Remove from queue
        remove_job(job_id)

        print(f"\n[SUCCESS] Report generated: {report_path}")
        print(f"  Verdict: {report.get('verdict')}")
        print(f"  Risk: {report.get('risk')}")
        print(f"  Key Finding: {report.get('keyFinding')}")

        return True

    except Exception as e:
        update_job_status(job_id, "failed", str(e))
        print(f"\n[FAILED] {job_id}: {e}")
        return False

    finally:
        # Cleanup clone dir
        clone_dir = CLONE_BASE / job_id
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


def process_all_pending():
    """Process all pending jobs."""
    jobs = get_pending_jobs()
    if not jobs:
        print("No pending jobs in queue")
        return
    print(f"Found {len(jobs)} pending job(s)")
    for job in jobs:
        asyncio.run(run_analysis(job))


def process_job_by_id(job_id: str):
    """Process a specific job by ID."""
    q = load_queue()
    job = next((j for j in q["jobs"] if j["id"] == job_id), None)
    if not job:
        print(f"Job not found: {job_id}")
        return False
    return asyncio.run(run_analysis(job))


def watch_mode(interval: int = 30):
    """Watch mode - poll for new jobs periodically."""
    import time

    print(f"Watching for jobs (polling every {interval}s)...")
    print("Press Ctrl+C to stop\n")
    try:
        while True:
            jobs = get_pending_jobs()
            if jobs:
                for job in jobs:
                    asyncio.run(run_analysis(job))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping worker...")


def main():
    args = sys.argv[1:]

    if "--watch" in args:
        watch_mode()
    elif "--job" in args:
        idx = args.index("--job")
        if idx + 1 < len(args):
            process_job_by_id(args[idx + 1])
        else:
            print("Error: --job requires a job ID")
            sys.exit(1)
    else:
        process_all_pending()


if __name__ == "__main__":
    main()
