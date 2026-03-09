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

Runs deep security analysis using Claude Agent SDK.
Claude writes a markdown report AND calls write_metadata for structured sidebar data.

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

# Model - use the smartest available
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
            "ecosystem": report.get("ecosystem", "unknown"),
            "risk": report["risk"],
            "verdict": report["verdict"],
            "keyFinding": report["keyFinding"],
        },
    )
    idx["lastUpdated"] = now()
    save_reports_index(idx)


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
        ":(){:|:&};:",
    ]

    for pattern in dangerous_patterns:
        if pattern in command:
            return {
                "reason": f"Blocked dangerous command pattern: {pattern}",
                "systemMessage": "Command blocked for security",
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Security policy blocks: {pattern}",
                },
            }

    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Metadata tool (MCP server for structured data capture)
# ─────────────────────────────────────────────────────────────────────────────


def create_metadata_tool(job: dict, captured_metadata: dict):
    """Create a write_metadata tool that captures structured data."""

    @tool(
        "write_metadata",
        "Record structured metadata for the security report. Call this AFTER writing the markdown report.",
        {
            "verdict": str,  # "approve", "conditional", or "reject"
            "risk": str,  # "low", "medium", or "high"
            "keyFinding": str,  # One-line summary of most important finding
            "commit": str,  # Git commit SHA analyzed
            "ecosystem": str,  # Primary ecosystem (e.g., "Node.js/NPM", "Python/PyPI")
            "stars": int,  # GitHub stars count
            "forks": int,  # GitHub forks count
            "contributors": int,  # Number of contributors
            "openIssues": int,  # Number of open issues
            "created": str,  # Repository creation date (YYYY-MM-DD)
            "license": str,  # License name (e.g., "MIT", "Apache-2.0")
            "hasSecurityMd": bool,  # Whether SECURITY.md exists
        },
    )
    async def write_metadata(args: dict[str, Any]) -> dict[str, Any]:
        """Capture structured metadata for the report."""
        # Validate required fields
        required = ["verdict", "risk", "keyFinding", "commit"]
        missing = [f for f in required if f not in args or not args[f]]
        if missing:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"ERROR: Missing required fields: {missing}",
                    }
                ],
                "isError": True,
            }

        # Normalize verdict and risk
        verdict = args.get("verdict", "conditional").lower()
        if verdict not in ("approve", "conditional", "reject"):
            verdict = "conditional"

        risk = args.get("risk", "medium").lower()
        if risk not in ("low", "medium", "high"):
            risk = "medium"

        # Store in captured_metadata dict (passed by reference)
        captured_metadata["verdict"] = verdict
        captured_metadata["risk"] = risk
        captured_metadata["keyFinding"] = args.get("keyFinding", "")[:500]
        captured_metadata["commit"] = args.get("commit", "unknown")
        captured_metadata["ecosystem"] = args.get("ecosystem", "unknown")
        captured_metadata["stats"] = {
            "stars": f"{args.get('stars', 0):,}",
            "forks": f"{args.get('forks', 0):,}",
            "contributors": str(args.get("contributors", 0)),
            "openIssues": args.get("openIssues", 0),
            "created": args.get("created", "unknown"),
            "license": args.get("license", "unknown"),
            "hasSecurityMd": args.get("hasSecurityMd", False),
        }

        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Metadata recorded: verdict={verdict}, risk={risk}",
                }
            ]
        }

    return write_metadata


# ─────────────────────────────────────────────────────────────────────────────
# Analysis prompt
# ─────────────────────────────────────────────────────────────────────────────


ANALYSIS_PROMPT = """# Security Analysis Task

You are conducting an **adversarial security analysis** of an open source repository.
Your goal is to determine if this code is safe to run on a privileged corporate machine.

## Repository
- **URL**: {url}
- **Owner**: {owner}
- **Repo**: {repo}
- **Clone to**: {clone_path}

## Your Mission

1. **Analyze** the repository thoroughly
2. **Write** a detailed markdown report to `{report_path}`
3. **Call** the `write_metadata` tool with structured data for the sidebar

## Analysis Requirements

### Step 1: Clone and Reconnaissance
```bash
git clone --depth 50 {url} {clone_path}
cd {clone_path}
git rev-parse HEAD  # Get commit SHA
```

### Step 2: Fetch GitHub Stats
```bash
curl -s "https://api.github.com/repos/{owner}/{repo}" | jq '{{stars: .stargazers_count, forks: .forks_count, open_issues: .open_issues_count, created: .created_at, license: .license.spdx_id}}'
```
Also check:
- Number of contributors: `curl -s "https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100" | jq length`
- SECURITY.md presence: `ls -la SECURITY.md 2>/dev/null`

### Step 3: Deep Code Analysis

For each area, **show specific evidence**:

**Network & Communications**
- Find ALL URLs, domains, IP addresses in the code
- Trace data flow: where does data go?
- Check for undocumented "phone home" behaviors

**Code Execution Risks**
- Find eval(), Function(), exec(), spawn(), fork()
- Understand WHY they're used - legitimate or suspicious?
- Check for obfuscation, packed code

**Dependencies**
- Run security scanner (npm audit, pip-audit, cargo audit)
- Check for typosquatting, unpinned versions
- Analyze what each dependency does

**Supply Chain**
- Check lifecycle scripts (postinstall, prepare)
- Analyze install-time behavior

**Binary & Asset Analysis**
- Any committed binaries? Can you verify their source?

**Trust Signals**
- Commit patterns, contributor analysis
- Signs of account compromise?

### Step 4: Write Your Report

Save a markdown file to `{report_path}` with this structure:

```markdown
# Security Analysis: {owner}/{repo}

**Commit**: `<sha>`
**Analyzed**: {date}
**Ecosystem**: <detected>

## Executive Summary

<One paragraph summary of findings and recommendation>

**Verdict**: APPROVE | CONDITIONAL | REJECT
**Risk Level**: LOW | MEDIUM | HIGH

## Detailed Findings

### 1. <Finding Title>
<Deep analysis with code snippets and evidence>

### 2. <Finding Title>
...

## Evidence Appendix

<Specific file:line references, command outputs>

## Recommendation

<What should the user do?>
```

### Step 5: Call write_metadata

After writing the markdown report, call the `write_metadata` tool with:
- verdict: "approve", "conditional", or "reject"
- risk: "low", "medium", or "high"  
- keyFinding: One sentence summary
- commit: The SHA you analyzed
- ecosystem: Primary ecosystem (e.g., "Node.js/NPM")
- stars: GitHub stars (integer)
- forks: GitHub forks (integer)
- contributors: Number of contributors (integer)
- openIssues: Open issue count (integer)
- created: Repo creation date (YYYY-MM-DD format)
- license: License identifier (e.g., "MIT")
- hasSecurityMd: true/false

## Guidelines

- **Be thorough.** Take time to understand the code.
- **Show evidence.** No vague statements like "no issues found."
- **Think adversarially.** How would a malicious actor hide something here?
- **Include code snippets** with file paths and line numbers.

Begin your analysis now.
"""


async def run_analysis(job: dict) -> bool:
    """Run deep security analysis using Claude Agent SDK."""
    job_id = job["id"]
    print(f"\n{'=' * 60}")
    print(f"Processing: {job['owner']}/{job['repo']}")
    print(f"Job ID: {job_id}")
    print(f"{'=' * 60}\n")

    update_job_status(job_id, "processing")

    # Ensure directories exist
    CLONE_BASE.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    clone_path = CLONE_BASE / job_id
    report_path = REPORTS_DIR / f"{job_id}.md"

    # Dict to capture metadata from tool call (passed by reference)
    captured_metadata: dict[str, Any] = {}

    # Create the metadata tool
    metadata_tool = create_metadata_tool(job, captured_metadata)

    # Create MCP server with the metadata tool
    metadata_server = create_sdk_mcp_server(
        name="watchdog",
        version="1.0.0",
        tools=[metadata_tool],
    )

    # Build the analysis prompt
    prompt = ANALYSIS_PROMPT.format(
        url=job["url"],
        owner=job["owner"],
        repo=job["repo"],
        clone_path=clone_path,
        report_path=report_path,
        date=today(),
    )

    # Configure Claude with built-in tools + our metadata tool
    options = ClaudeAgentOptions(
        model=MODEL,
        system_prompt="You are an expert security researcher conducting adversarial analysis of open source code. Be thorough, specific, and show your work.",
        cwd=str(CLONE_BASE),
        tools=["Bash", "Read", "Write", "Glob", "Grep"],
        mcp_servers={"watchdog": metadata_server},
        allowed_tools=[
            "Bash",
            "Read",
            "Write",
            "Glob",
            "Grep",
            "mcp__watchdog__write_metadata",
        ],
        hooks={
            "PreToolUse": [
                HookMatcher(matcher="Bash", hooks=[block_dangerous_commands]),
            ],
        },
        permission_mode="acceptEdits",
        max_turns=200,
    )

    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)

            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text = block.text
                            if len(text) > 300:
                                text = text[:300] + "..."
                            print(f"  {text}")
                        elif isinstance(block, ToolUseBlock):
                            print(f"  [Tool] {block.name}")

                elif isinstance(message, ResultMessage):
                    print(f"\n  Completed in {message.duration_ms}ms")
                    if message.total_cost_usd:
                        print(f"  Cost: ${message.total_cost_usd:.4f}")

        # Read the markdown report
        if not report_path.exists():
            raise Exception(f"Report not written to {report_path}")

        markdown_content = report_path.read_text()

        # Use captured metadata from tool call, with fallbacks
        metadata = (
            captured_metadata
            if captured_metadata
            else {
                "verdict": "conditional",
                "risk": "medium",
                "keyFinding": "Analysis completed - metadata not captured",
                "commit": "unknown",
                "ecosystem": "unknown",
                "stats": {
                    "stars": "—",
                    "forks": "—",
                    "contributors": "—",
                    "openIssues": 0,
                    "created": "—",
                    "license": "unknown",
                    "hasSecurityMd": False,
                },
            }
        )

        # Build the final report object
        report = {
            "id": job_id,
            "url": job["url"],
            "owner": job["owner"],
            "repo": job["repo"],
            "analyzed": today(),
            "format": "markdown",
            "content": markdown_content,
            **metadata,
        }

        # Save as JSON (with markdown content embedded)
        json_path = REPORTS_DIR / f"{job_id}.json"
        save_json(json_path, report)

        # Add to index
        add_report_to_index(report)

        # Remove from queue
        remove_job(job_id)

        print(f"\n[SUCCESS] Report generated: {report_path}")
        print(f"  Verdict: {report.get('verdict')}")
        print(f"  Risk: {report.get('risk')}")
        print(f"  Key Finding: {report.get('keyFinding', 'N/A')[:80]}...")

        return True

    except Exception as e:
        update_job_status(job_id, "failed", str(e))
        print(f"\n[FAILED] {job_id}: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        # Cleanup clone dir
        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)


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
