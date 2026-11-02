# Project Solomon

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Tests](https://img.shields.io/badge/tests-89%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

Windows-first Python framework for **authorized penetration testing, read-only local security audits and evidence-based vulnerability reporting**. No AI, commercial APIs, subscriptions, telemetry or paid services.

> 🇧🇷 [Leia em português](README.pt-BR.md)

> [!IMPORTANT]
> Solomon is meant for systems you own or are explicitly authorized to test. Every network operation is checked against a declared scope, and nothing leaves the machine until an engagement is marked as authorized.

## Highlights

- **Scope enforcement by design**: domains, wildcards, exact URLs, IPs and CIDRs, with exclusions, time windows, allowed ports and allowed operations. Out-of-scope or unauthorized targets are blocked before any socket is opened.
- **Safe networking**: shared rate, concurrency and request-budget limits; verified HTTPS; every redirect re-checked against scope; resolved IPs checked against exclusions and private ranges (DNS-rebinding aware).
- **Evidence-based findings**: each finding carries evidence, confidence, impact, rationale, reproduction steps, remediation, limitations, references and SHA-256 hashes. Tampered evidence is rejected on re-analysis.
- **Conservative rules**: an open port, an announced version or an inconclusive response is never reported as a vulnerability.
- **Local diagnostics (read-only)**: CPU, memory, storage, processes, interfaces, sockets, services, routes and firewall profiles on Windows, with Ubuntu providers.
- **Reports**: self-contained HTML (no external resources), Markdown for bug bounty write-ups and JSON for offline re-analysis.
- **CLI and TUI** (Textual), with offline planning and per-module commands for DNS, HTTP, TLS, ports and CORS.

## Quick start (Windows)

Requires Python 3.12+ and PowerShell. No WSL, Docker, Nmap or admin rights needed.

```powershell
git clone https://github.com/Reinaldo-Porfirio/project-solomon.git
cd project-solomon
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1
.\solomon.cmd status
.\solomon.cmd          # opens the TUI
```

`-ExecutionPolicy Bypass` applies only to that process. The installer does not change system policy, firewall, services or permissions. Opening the app does **not** start any remote test.

Other platforms (manual install):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
solomon status
```

## See it working without touching third parties

```powershell
.\solomon.cmd demo
```

The demo starts a temporary server on **127.0.0.1**, creates a scope restricted to it, collects HTTP, technology, one port and two CORS probes, writes JSON/HTML/Markdown reports to `reports/local-demo/SESS-*/` and shuts the server down. All data is fictitious.

Sample output (the CLI and reports are currently in Portuguese):

```
[MEDIUM] WEB-CORS-001-79C2A84A1267: Duas origens arbitrárias refletidas com credenciais permitidas
[LOW] WEB-COOKIE-002-11F636B3C0A0: Cookie de sessão sessionid sem HttpOnly
  Confiança: 99% | Prioridade: 8/100
  Correção: Aplique HttpOnly aos cookies de sessão que não precisam ser acessados por JavaScript.
[INFORMATIONAL] WEB-COOKIE-003-0829774B45D6: SameSite não declarado no cookie sessionid
[INFORMATIONAL] WEB-FRAME-001-D9E8E206767C: Restrição de enquadramento não observada
[INFORMATIONAL] WEB-HEADERS-001-8FC9C311CE41: Defesas adicionais ausentes na resposta HTML
```

That is: two arbitrary origins reflected with credentials allowed (a CORS candidate that still needs impact confirmation), a session cookie without `HttpOnly`, and three informational observations.

## Testing an authorized target

```powershell
.\solomon.cmd pentest init --engagement engagements\program.json --name "My program" --include "https://authorized-target.invalid/" --authorize --authorization-reference "Program policy or written authorization"
.\solomon.cmd pentest plan "https://authorized-target.invalid/" --engagement engagements\program.json --modules HTTP,TLS,TECHNOLOGY
.\solomon.cmd pentest scan "https://authorized-target.invalid/" --engagement engagements\program.json --modules HTTP,TLS,TECHNOLOGY --output reports\program
```

Without `--authorize`, every operation is reported as `BLOCKED_NOT_AUTHORIZED` and no network activity happens. CORS, port and active service identification also require `active_testing=true` in the engagement policy. `plan`, `scope check`, `analyze` and `report` never touch the network.

## Local audit and reports

```powershell
.\solomon.cmd diagnostics
.\solomon.cmd audit --output reports\audit
.\solomon.cmd analyze --input "reports\SESS-ID\report.json" --output reports\reanalyzed
.\solomon.cmd report  --input "reports\SESS-ID\report.json" --output reports\exported
```

## Architecture

```
src/solomon/
  core/          domain models, scope, evidence, findings, scoring
  platform/      OS detection and read-only providers (Windows, Ubuntu)
  diagnostics/   local collectors (CPU, memory, storage, network, services, firewall...)
  analysis/      deterministic rules, correlation and health score
  pentest/       engagement, scope matcher, target guard, transports (DNS/HTTP/TLS/TCP),
                 recon and discovery modules
  reporting.py   JSON / HTML / Markdown exporters
  tui/           Textual interface
```

All pentest network traffic goes through the transport layer, which enforces the guard, resolved-IP checks, timeouts, budget and secret redaction. Scanners never open sockets directly. See [docs/architecture.md](docs/architecture.md) and [docs/security-model.md](docs/security-model.md).

## Development

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-windows.ps1 -Dev
.\.venv\Scripts\python.exe -m pytest -q                  # 88 unit tests, mocked network
.\.venv\Scripts\python.exe -m pytest -q -m integration   # loopback-only lab
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy src --ignore-missing-imports
```

## Current limitations

Version 0.2.0 is a working base for assessment and documentation. Not implemented yet: SQLi/XSS/SSRF exploitation, business logic and authenticated testing, mass discovery, automatic CVE/CVSS, PDF export and hardening (the `harden`, `verify` and `rollback` commands explicitly report as unavailable). Real execution was validated on Windows 11; Linux providers exist but still need validation on a physical host. The 0–100 score reflects only the rules and evidence available and does not certify a target as secure.

## Documentation (Portuguese)

[Windows](docs/windows.md) · [Pentest & bug bounty](docs/pentest.md) · [Rules](docs/rules.md) · [Report template](docs/bug-bounty-template.md) · [Architecture](docs/architecture.md) · [Security model](docs/security-model.md) · [Threat model](docs/threat-model.md) · [Validation](docs/validation.md) · [Roadmap](docs/project-review.md) · [Development](docs/development.md) · [Security policy](SECURITY.md)

## License

[MIT](LICENSE). You are responsible for using this tool only against systems you are authorized to test.
