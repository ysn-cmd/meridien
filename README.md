# Meridien

A plugin-based automated security scanning and reporting platform. Meridien runs
reconnaissance, dynamic (DAST) and static (SAST) scans through a single
orchestration core, normalizes every tool's output into one common schema, and
turns the results into deduplicated, diff-aware reports — available on the CLI, as
PDF/HTML, through a REST API, and in a React dashboard. It can also run on a
schedule and email you when new findings appear.

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)
![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen)

## Architecture

![Architecture](docs/architecture.png)

Every scanner is a **plugin** that returns the same `Finding` schema, so the core,
processing, storage and reporting layers never need to know which tool produced a
result. Adding a new tool means adding a plugin — the rest of the pipeline is
untouched.

## Features

- **Three scan types, one contract** — recon (`nmap`), DAST (`nuclei`) and SAST
  (`semgrep`), each normalized into a common `Finding` schema.
- **Deduplication** — identical findings are collapsed with an occurrence count.
- **Diff** — each scan is compared against the previous scan of the same target
  *with the same plugin set*, surfacing newly introduced and resolved findings.
- **CVE & CWE enrichment** — findings are tagged with their CVE (specific
  vulnerability) or CWE (weakness class) where available.
- **Reporting** — self-contained HTML and PDF reports (via Puppeteer), with
  severity summaries, badges and a "Changes" section.
- **REST API + React dashboard** — browse scans and findings interactively.
- **Scheduling & alerting** — periodic scans via `node-cron`; email alerts (SMTP)
  on new medium/high/critical findings, opt-in per job.
- **Scope enforcement** — a 4-tier allowlist/denylist gate with path-boundary and
  argument-injection protection, so only authorized targets are ever scanned.

## Requirements

- **Node.js >= 18**
- External scanners on `PATH` (or pointed to via env): [`nmap`](https://nmap.org),
  [`nuclei`](https://github.com/projectdiscovery/nuclei),
  [`semgrep`](https://semgrep.dev) (`SEMGREP_PATH` override supported)
- **System Chromium** for PDF reports (`CHROME_PATH` override supported)

## Installation

```bash
git clone https://github.com/ysn-cmd/meridien.git
cd meridien
npm install
npm --prefix frontend install     # dashboard dependencies

cp scope.example.yaml scope.yaml           # define your authorized targets
cp schedule.example.yaml schedule.yaml     # (optional) scheduled scans
cp .env.example .env                        # (optional) SMTP for alerts
```

## Usage

### Scan (CLI)

```bash
npm run scan -- --target scanme.nmap.org --plugins nmap,nuclei --report
```

Common flags:

| Flag | Description |
|------|-------------|
| `--target, -t` | Target to scan (must be allowed by `scope.yaml`) |
| `--plugins, -p` | Comma-separated plugins: `nmap,nuclei,semgrep` |
| `--report, -r` | Generate HTML + PDF report |
| `--alert` | Email on new findings above the severity threshold |
| `--min-severity` | Alert threshold: `medium` (default), `high`, `critical` |

### API + dashboard

```bash
npm run serve        # REST API + built dashboard on http://127.0.0.1:3000
npm run dashboard    # frontend dev server (http://localhost:5173, proxies /api)
```

Endpoints: `GET /api/scans`, `GET /api/scans/:id`.

### Scheduled scans & alerts

```bash
npm run schedule                       # run on the cron schedule in schedule.yaml
node src/scheduler/index.js --once     # run every job once (for testing)
```

## Configuration

- **`scope.yaml`** — allowlist/denylist of authorized targets (required).
- **`schedule.yaml`** — scheduled jobs (`target`, `plugins`, `cron`, `alert`) and
  the global alert threshold.
- **`.env`** — SMTP settings for email alerts. If left empty, an
  [Ethereal](https://ethereal.email) test account is used and a preview URL is
  printed (no real email is sent).

Real config files are gitignored; the committed `*.example` files show the format.

## Project structure

```
meridien/
├── bin/            CLI entry point
├── src/
│   ├── core/       orchestration, Finding schema, scope, diff, cve/cwe
│   ├── plugins/    recon (nmap), DAST (nuclei), SAST (semgrep) + registry
│   ├── reporting/  HTML/PDF report generation
│   ├── store/      SQLite persistence
│   ├── api/        Express API + static dashboard
│   ├── alerting/   email notifier + alert check
│   └── scheduler/  node-cron scheduler
├── frontend/       React + Vite dashboard
├── docs/           architecture diagram
└── test/           unit tests
```

## Testing

```bash
npm test
```

20 unit tests (Node's built-in runner, zero dependencies) cover the schema,
deduplication, diff, CVE/CWE extraction, and scope enforcement — including the
path-boundary and argument-injection protections.

## Responsible use

Meridien is intended for authorized security testing only. Scan targets you own
or have explicit written permission to test. The scope allowlist is a safeguard,
not a substitute for authorization. The authors accept no liability for misuse.

## License

[MIT](LICENSE) (c) ysn-cmd
