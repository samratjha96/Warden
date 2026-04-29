---
name: ask-warden
description: Use Warden to submit repositories for adversarial security review, poll job status, fetch completed reports, search prior reports, and summarize Warden verdicts without flooding the terminal.
---

# Ask Warden

Use this skill when a user asks whether a repository is safe to use, wants a Warden security review, wants to query Warden reports, or provides a Warden API URL/job ID/report ID.

Warden is a repository review service. It queues an adversarial analysis job and returns a markdown-backed security report with a verdict, risk level, key finding, approval conditions, and evidence.

## API Base

Default local base URL:

```text
http://localhost:12000
```

If the user gives another Warden URL, use that instead. Do not guess credentials or private network access. If Warden is unreachable, report that directly.

## Submit A Repository

Submit GitHub or GitLab repository URLs:

```bash
curl -s "$WARDEN_URL/api/submit" \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/owner/repo",
    "ecosystem": "auto",
    "severity": "low",
    "depth": "shallow"
  }' \
  -o warden-submit.json
```

Read `warden-submit.json` and capture:

- `jobId`
- `statusUrl`
- `reportUrl`
- `dispatchCode`
- `queuedForLater`
- `workerError`

If `dispatchCode` is `worker_trigger_failed` or `queuedForLater` is true, the job may still be queued. Poll status before assuming failure.

## Poll Job Status

Poll with the stable `jobId`:

```bash
curl -s "$WARDEN_URL/api/jobs/<job-id>" -o warden-job.json
```

Expected statuses:

- `pending`: queued, not started
- `processing`: worker is analyzing
- `failed`: analysis failed; read `error`
- `succeeded`: report exists and can be fetched from `links.report`

Polling guidance:

- Poll every 10-30 seconds unless the user asks otherwise.
- Stop after a reasonable timeout and say the job is still running.
- Do not start duplicate submissions for the same repository just because a job is pending.

## Fetch A Report

Reports include full markdown content and can be long. Always write report responses to a file first:

```bash
curl -s "$WARDEN_URL/api/reports/<report-id>" -o warden-report.json
```

Do not dump full report JSON or markdown into the terminal. Inspect targeted fields instead:

```bash
jq '.report | {id, owner, repo, verdict, risk, keyFinding, approvalConditions}' warden-report.json
```

If `jq` is unavailable, use another JSON reader or a short script. Keep terminal output bounded.

## Search Reports

Search by repository and write the result to a file:

```bash
curl -s "$WARDEN_URL/api/reports?repository=owner/repo" -o warden-report-search.json
```

Provider-specific form:

```bash
curl -s "$WARDEN_URL/api/reports?provider=github&owner=owner&repo=repo" -o warden-report-search.json
```

Search results are summaries. Fetch a specific report by `id` only when the user needs the full report or evidence.

## Understand The Report

When summarizing Warden output, lead with:

- Repository: `owner/repo`
- Verdict: `approve`, `conditional`, or `reject`
- Risk: `low`, `medium`, or `high`
- Key finding
- Approval conditions, if any
- Most important evidence from the markdown report

Interpretation:

- `approve`: acceptable based on Warden's review, subject to normal engineering judgment.
- `conditional`: do not treat as approved until the listed conditions are satisfied.
- `reject`: do not recommend adoption unless the user explicitly accepts the risk and explains why.

Be precise. If Warden did not inspect something, say so. Do not turn a Warden report into a guarantee of safety.

## Agent Conduct

- Keep Warden artifacts in named files such as `warden-submit.json`, `warden-job.json`, `warden-report-search.json`, and `warden-report.json`.
- Avoid spamming the terminal with full report contents.
- Quote only short report excerpts. Prefer concise summaries with report field names.
- If a report is missing, check job status with the same ID before resubmitting.
- If the user asks for a final recommendation, base it on verdict, risk, approval conditions, and evidence. Call out unresolved risk plainly.
