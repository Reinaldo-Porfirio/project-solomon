"""Windows-friendly CLI with real engagement files and offline report exports."""

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .analysis.engine import AnalysisEngine
from .config import ConfigManager
from .core.exceptions import ConfigurationError
from .diagnostics.engine import DiagnosticsEngine
from .logging import setup_logging
from .pentest.engagement import load_engagement, new_engagement, save_engagement
from .pentest.engine import DEFAULT_MODULES, PentestDiscoveryEngine, build_plan
from .pentest.guard import TargetGuard
from .pentest.models import OperationType, TargetDecision
from .pentest.security import PentestRuleEngine, security_health
from .platform.factory import get_platform_detector
from .reporting import load_report, report_evidence, save_reports, serializable


def parse_ports(value: str) -> list[int]:
    try:
        ports = sorted({int(port.strip()) for port in value.split(",")})
        if not ports or len(ports) > 100 or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError
        return ports
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Use até 100 portas entre 1 e 65535, separadas por vírgula."
        ) from exc


def _export(result, output: str) -> None:
    for kind, path in save_reports(result, Path(output)).items():
        print(f"Relatório {kind.upper()}: {path.resolve()}")


def _summary(result) -> None:
    print(f"Solomon — {result['kind']} / {result['session_status']}")
    print(f"Alvo: {result['target']}")
    for module, status in result["status"].items():
        print(f"  {module:<15} {status}")
    print(f"Evidências: {len(result['evidence'])} | Achados: {len(result['findings'])}")
    health = result["security_health"]
    print(
        "Nota das verificações coletadas: "
        + (f"{health}/100" if health is not None else "não calculada (sem cobertura suficiente)")
    )
    for finding in result["findings"]:
        print(f"[{finding.severity.value}] {finding.finding_id}: {finding.title}")
        print(
            f"  Confiança: {round(finding.confidence * 100)}% | Prioridade: {finding.priority}/100"
        )
        print(f"  Justificativa: {finding.reasoning}")
        print(f"  Correção: {finding.recommendation}")
    for check in result.get("checks", []):
        if check["status"] not in ("SUCCESS", "SKIPPED"):
            print(f"  {check['module']}: {check['status']} — {check['reason']}")


def cmd_pentest_init(args) -> int:
    engagement = new_engagement(
        args.name,
        args.include,
        args.exclude,
        args.authorize,
        args.authorization_reference,
        args.active_testing,
    )
    save_engagement(engagement, Path(args.engagement))
    print(f"Engagement salvo: {Path(args.engagement).resolve()}")
    print(f"Autorização: {engagement.authorization_status.value}")
    print("Nenhuma atividade de rede realizada.")
    return 0


def cmd_pentest_plan(args) -> int:
    engagement = load_engagement(Path(args.engagement))
    modules = (
        [value.upper() for value in args.modules.split(",")] if args.modules else DEFAULT_MODULES
    )
    print(
        json.dumps(
            build_plan(engagement, args.target, modules, args.ports), ensure_ascii=False, indent=2
        )
    )
    return 0


def cmd_pentest_scope_check(args) -> int:
    engagement = load_engagement(Path(args.engagement))
    result = TargetGuard.check(engagement, args.target, OperationType[args.operation], args.port)
    print(json.dumps(serializable(result), ensure_ascii=False, indent=2))
    return 0 if result.decision == TargetDecision.ALLOWED else 2


def cmd_pentest_run(args) -> int:
    engagement = load_engagement(Path(args.engagement))
    if args.pentest_cmd in ("discover", "scan"):
        modules = (
            [value.strip().upper() for value in args.modules.split(",")]
            if args.modules
            else list(DEFAULT_MODULES)
        )
    else:
        modules = [args.pentest_cmd.upper()]
    if args.cors and "CORS" not in modules:
        modules.append("CORS")
    plan = build_plan(engagement, args.target, modules, args.ports)
    if args.plan:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    if not any(item["decision"] == "ALLOWED" for item in plan["operations"]):
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        print("Execução bloqueada: nenhuma operação autorizada.", file=sys.stderr)
        return 2
    result = PentestDiscoveryEngine(engagement).run(args.target, modules, args.ports)
    _summary(result)
    _export(result, args.output)
    return 0 if result["session_status"] == "COMPLETED" else 2


def cmd_pentest_status(args) -> int:
    if args.session:
        report = load_report(Path(args.session))
        print(
            json.dumps(
                {
                    key: report.get(key)
                    for key in (
                        "session_id",
                        "session_status",
                        "target",
                        "started_at",
                        "ended_at",
                        "status",
                        "requests_used",
                        "security_health",
                    )
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.engagement:
        engagement = load_engagement(Path(args.engagement))
        print(f"{engagement.name}: {engagement.authorization_status.value}")
        print(f"Referência de autorização: {engagement.authorization_reference}")
    else:
        raise ValueError("Informe --engagement ou --session.")
    return 0


def cmd_local(args) -> int:
    detector = get_platform_detector()
    capabilities = detector.detect()
    started = datetime.now(UTC).isoformat()
    print(f"Coletando evidências locais em {capabilities.platform}...")
    results = DiagnosticsEngine(detector).run()
    evidence = [ev for result in results.values() for ev in result.evidence]
    analysis = AnalysisEngine(capabilities.platform).run(evidence)
    complete = all(result.status.value == "SUCCESS" for result in results.values())
    report = {
        "schema_version": 1,
        "kind": args.command,
        "session_id": f"LOCAL-{uuid.uuid4().hex[:12].upper()}",
        "session_status": "COMPLETED" if complete else "PARTIAL",
        "target": capabilities.platform,
        "platform": capabilities.platform,
        "started_at": started,
        "ended_at": datetime.now(UTC).isoformat(),
        "status": {name: result.status.value for name, result in results.items()},
        "checks": [
            {
                "module": name,
                "target": "local",
                "status": result.status.value,
                "reason": result.message or "",
            }
            for name, result in results.items()
        ],
        "evidence": evidence,
        "findings": analysis.findings if args.command == "audit" else [],
        "security_health": analysis.health.overall
        if args.command == "audit" and evidence
        else None,
        "limitations": [
            "Somente leitura; nenhuma configuração do Windows é modificada.",
            "A nota considera somente as regras implementadas e as evidências disponíveis.",
            "Coletores indisponíveis ou sem privilégios deixam lacunas na cobertura.",
        ],
    }
    _summary(report)
    _export(report, args.output)
    return 0


def cmd_status(args) -> int:
    caps = get_platform_detector().detect()
    print(f"Solomon v{__version__}")
    print(f"Sistema: {caps.platform} | Privilégio: {caps.privilege_level.value}")
    for capability, available in caps.capabilities.items():
        print(f"  {'[OK]' if available else '[  ]'} {capability}")
    return 0


def cmd_demo(args) -> int:
    from .lab import run_demo

    result = run_demo(Path(args.output))
    _summary(result)
    _export(result, args.output)
    return 0 if result["session_status"] == "COMPLETED" else 2


def cmd_analyze(args) -> int:
    report = load_report(Path(args.input))
    evidence = report_evidence(report)
    if report.get("kind") == "pentest":
        findings = PentestRuleEngine().analyze(evidence)
    else:
        findings = (
            AnalysisEngine(report.get("platform", report.get("target", ""))).run(evidence).findings
        )
    from .analysis.health import HealthEngine

    report["findings"] = findings
    report["security_health"] = (
        security_health(evidence, findings)
        if report.get("kind") == "pentest"
        else HealthEngine().calculate(findings).overall
        if evidence
        else None
    )
    _summary(report)
    _export(report, args.output)
    return 0


def cmd_report(args) -> int:
    report = load_report(Path(args.input))
    _export(report, args.output)
    return 0


def cmd_unavailable(args) -> int:
    print("Hardening, verificação e rollback ainda não foram implementados.", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solomon", description="Solomon — pentest autorizado e auditoria local"
    )
    parser.add_argument("--version", action="version", version=f"Solomon {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    for command in ("diagnostics", "audit"):
        sub = subparsers.add_parser(command, help="Diagnóstico/auditoria local somente leitura")
        sub.add_argument("--output", default="reports", help="Diretório dos relatórios")
        sub.set_defaults(func=cmd_local)
    status = subparsers.add_parser("status", help="Plataforma e capacidades")
    status.set_defaults(func=cmd_status)
    version = subparsers.add_parser("version", help="Versão")
    version.set_defaults(func=lambda args: print(f"Solomon {__version__}") or 0)
    tui = subparsers.add_parser("tui", help="Interface interativa")
    tui.set_defaults(func=cmd_tui)
    demo = subparsers.add_parser("demo", help="Laboratório automático em loopback, gratuito")
    demo.add_argument("--output", default="reports/local-demo")
    demo.set_defaults(func=cmd_demo)

    pentest = subparsers.add_parser("pentest", help="Avaliação de alvos explicitamente autorizados")
    commands = pentest.add_subparsers(dest="pentest_cmd", required=True)
    init = commands.add_parser("init", help="Criar um arquivo de engagement")
    init.add_argument("--engagement", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--include", action="append", required=True)
    init.add_argument("--exclude", action="append", default=[])
    init.add_argument(
        "--authorize", action="store_true", help="Declarar autorização para esses ativos"
    )
    init.add_argument("--authorization-reference", default="")
    init.add_argument(
        "--active-testing", action="store_true", help="Habilitar portas/serviços/CORS"
    )
    init.set_defaults(func=cmd_pentest_init)
    plan = commands.add_parser("plan", help="Planejamento offline")
    plan.add_argument("target")
    plan.add_argument("--engagement", required=True)
    plan.add_argument("--modules", default="")
    plan.add_argument("--ports", type=parse_ports)
    plan.set_defaults(func=cmd_pentest_plan)
    status = commands.add_parser("status", help="Estado do engagement ou sessão salva")
    status.add_argument("--engagement")
    status.add_argument("--session")
    status.set_defaults(func=cmd_pentest_status)
    for command in ("scan", "discover", "dns", "http", "tls", "ports", "cors"):
        sub = commands.add_parser(command, help=f"Coletar {command} com escopo e gerar relatórios")
        sub.add_argument("target")
        sub.add_argument("--engagement", required=True)
        sub.add_argument("--plan", action="store_true")
        sub.add_argument("--ports", type=parse_ports)
        sub.add_argument("--modules", default="")
        sub.add_argument(
            "--cors", action="store_true", help="Duas sondagens CORS, exige active_testing"
        )
        sub.add_argument("--output", default="reports")
        sub.set_defaults(func=cmd_pentest_run)
    scope = commands.add_parser("scope", help="Validação de escopo sem rede")
    scope_subs = scope.add_subparsers(dest="scope_cmd", required=True)
    check = scope_subs.add_parser("check")
    check.add_argument("target")
    check.add_argument("--engagement", required=True)
    check.add_argument(
        "--operation", choices=[op.name for op in OperationType], default="HTTP_REQUEST"
    )
    check.add_argument("--port", type=int)
    check.set_defaults(func=cmd_pentest_scope_check)
    for command, handler in (("analyze", cmd_analyze), ("report", cmd_report)):
        sub = subparsers.add_parser(command, help="Processar relatório salvo sem rede")
        sub.add_argument("--input", required=True)
        sub.add_argument("--output", default="reports")
        sub.set_defaults(func=handler)
    for command in ("harden", "verify", "rollback"):
        sub = subparsers.add_parser(command, help="Planejado; indisponível nesta versão")
        sub.set_defaults(func=cmd_unavailable)
    return parser


def cmd_tui(args) -> int:
    from .tui.app import SolomonConsole

    SolomonConsole().run()
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging()
    config = ConfigManager()
    try:
        config.load()
        return cmd_tui(args) if args.command is None else args.func(args)
    except (OSError, ValueError, TypeError, ConfigurationError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Execução interrompida pelo usuário.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
