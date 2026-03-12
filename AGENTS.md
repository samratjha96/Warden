# Warden

## Architecture
- `server.py` — serves `site/`, handles API (submit, queue, reports)
- `worker/worker.py` — pulls from `site/data/queue/jobs.json`, writes to `site/data/reports/`

## Run

```bash
python server.py > /tmp/warden-server.log 2>&1 &  # default port 12000
uv run worker/worker.py          # drain all jobs
uv run worker/worker.py --job <id>  # single job
```

Restart server after any `server.py` changes. Worker changes take effect on next spawn. Static asset changes only need a hard refresh.

## Logs

```bash
tail -n 120 "${TMPDIR:-/tmp}/warden-worker.log"
tail -n 120 "${TMPDIR:-/tmp}/warden-worker-batch.log"
ps -ax | rg "server.py|worker.py"
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Queue looks stale | Hard refresh; confirm server restarted |
| `Unexpected non-JSON response` | Server is stale — restart it |
| Regen/delete returns 404 | Restart server |
| Queue grows, no analysis | Run worker manually |

## Key Files
`server.py` · `worker/worker.py` · `worker/PROMPT.md` · `site/js/app.js` · `site/data/queue/jobs.json` · `site/data/reports/index.json`
