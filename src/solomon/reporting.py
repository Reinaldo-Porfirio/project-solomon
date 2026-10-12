"""Portable, offline reports with escaped HTML and evidence integrity hashes."""

import hashlib
import html
import json
import re
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from solomon import __version__
from solomon.core.evidence import Evidence
from solomon.pentest.transport.base import Redactor


def serializable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: serializable(getattr(value, field.name))
            for field in fields(value)
            if not field.name.startswith("_")
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serializable(item) for item in value]
    return value


def _digest(evidence: dict[str, Any]) -> str:
    payload = {key: value for key, value in evidence.items() if key != "sha256"}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def prepare_report(result: dict[str, Any]) -> dict[str, Any]:
    serialized = serializable(result)
    report = Redactor.redact_data(serialized)
    # Report identifiers and authorization metadata are not authentication secrets.
    report["session_id"] = serialized.get("session_id", "report")
    if isinstance(serialized.get("engagement"), dict):
        for key in ("authorization_status", "authorization_reference"):
            report["engagement"][key] = Redactor.redact_data(serialized["engagement"].get(key, ""))
    report.setdefault("schema_version", 1)
    report.setdefault("solomon_version", __version__)
    for evidence in report.get("evidence", []):
        evidence["sha256"] = _digest(evidence)
    # Linked copies use the same sanitized evidence/hash as the evidence index.
    index = {item["evidence_id"]: item for item in report.get("evidence", [])}
    for finding in report.get("findings", []):
        finding["evidence"] = [
            index[key] for key in finding.get("evidence_ids", []) if key in index
        ]
    return report


def load_report(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("Relatório inválido ou versão não suportada.")
    evidence = report.get("evidence", [])
    if not isinstance(evidence, list) or not isinstance(report.get("findings", []), list):
        raise ValueError("Estrutura de relatório inválida.")
    ids: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict) or not item.get("sha256") or item["sha256"] != _digest(item):
            raise ValueError(
                "Hash de evidência ausente ou inválido; arquivo possivelmente alterado."
            )
        if item["evidence_id"] in ids:
            raise ValueError("IDs de evidência duplicados.")
        ids.add(item["evidence_id"])
    for finding in report.get("findings", []):
        if any(key not in ids for key in finding.get("evidence_ids", [])):
            raise ValueError("Achado referencia evidência inexistente.")
    return report


def report_evidence(report: dict[str, Any]) -> list[Evidence]:
    names = {field.name for field in fields(Evidence)}
    return [
        Evidence(**{key: value for key, value in item.items() if key in names})
        for item in report.get("evidence", [])
    ]


def _text(value: Any) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value))


def _escape(value: Any) -> str:
    return html.escape(_text(value), quote=True)


def _health_label(report: dict[str, Any]) -> str:
    value = report.get("security_health")
    return f"{value} / 100" if value is not None else "Não calculada: cobertura insuficiente"


def render_markdown(report: dict[str, Any]) -> str:
    def safe(value: Any) -> str:
        return _text(value).replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        "# Solomon — Relatório técnico",
        "",
        f"- Sessão: {safe(report.get('session_id', ''))}",
        f"- Versão Solomon: {safe(report.get('solomon_version', ''))}",
        f"- Tipo: {safe(report.get('kind', ''))}",
        f"- Estado: {safe(report.get('session_status', ''))}",
        f"- Alvo: {safe(report.get('target', ''))}",
        f"- Início (UTC): {safe(report.get('started_at', ''))}",
        f"- Fim (UTC): {safe(report.get('ended_at', ''))}",
        f"- Nota das verificações coletadas: {_health_label(report)}",
        f"- Requisições/operações contabilizadas: {report.get('requests_used', 0)}",
        "",
        "## Escopo e autorização",
        "",
    ]
    engagement = report.get("engagement", {})
    lines.extend(
        [
            f"- Programa: {safe(engagement.get('name', 'auditoria local'))}",
            f"- Referência de autorização: "
            f"{safe(engagement.get('authorization_reference', 'local'))}",
            f"- Incluídos: {safe(engagement.get('scope', {}).get('included', []))}",
            f"- Excluídos: {safe(engagement.get('scope', {}).get('excluded', []))}",
            "",
            "## Cobertura e limitações",
            "",
        ]
    )
    for module, status in report.get("status", {}).items():
        lines.append(f"- {safe(module)}: {safe(status)}")
    for check in report.get("checks", []):
        if check.get("status") != "SUCCESS":
            lines.append(
                f"- {safe(check.get('module'))} / {safe(check.get('target'))}: "
                f"{safe(check.get('status'))} — {safe(check.get('reason', ''))}"
            )
    lines.extend(f"- {safe(item)}" for item in report.get("limitations", []))
    lines.extend(["", "## Achados", ""])
    index = {item["evidence_id"]: item for item in report.get("evidence", [])}
    if not report.get("findings"):
        lines.extend(
            [
                "Nenhum achado gerado pelas regras aplicadas. "
                "Isso não comprova ausência de vulnerabilidades.",
                "",
            ]
        )
    for finding in report.get("findings", []):
        lines.extend(
            [
                f"### {safe(finding['finding_id'])} — {safe(finding['title'])}",
                "",
                f"- Gravidade: {safe(finding['severity'])}",
                f"- Classificação: {safe(finding.get('classification', 'configuration'))}",
                f"- Confiança: {round(finding['confidence'] * 100)}%",
                f"- Prioridade: {finding.get('priority', 0)} / 100 (não é CVSS)",
                f"- Ativo: {safe(finding['asset'])}",
                f"- CWE: {safe(finding.get('cwe') or 'não atribuído')}",
                "",
            ]
        )
        for title, key in (
            ("Descrição", "description"),
            ("Justificativa", "reasoning"),
            ("Impacto", "impact"),
            ("Correção", "recommendation"),
            ("Verificação", "verification"),
            ("Limites do achado", "limitations"),
        ):
            lines.extend([f"**{title}**", "", safe(finding.get(key) or "Não documentado."), ""])
        risk = finding.get("risk_score")
        if risk:
            lines.extend(["**Cálculo determinístico**", "", safe(risk.get("reasoning")), ""])
        lines.extend(["**Passos de reprodução**", ""])
        lines.extend(
            f"{number}. {safe(step)}"
            for number, step in enumerate(finding.get("reproduction_steps", []), 1)
        )
        lines.extend(["", "**Evidências**", ""])
        for key in finding.get("evidence_ids", []):
            item = index[key]
            payload = json.dumps(item, ensure_ascii=False, indent=2)
            fence = "`" * max(
                3, max((len(m.group()) + 1 for m in re.finditer(r"`+", payload)), default=3)
            )
            lines.extend([f"{fence}json", payload, fence, ""])
        lines.extend(["**Referências**", ""])
        lines.extend(f"- {safe(reference)}" for reference in finding.get("references", []))
        lines.append("")
    lines.extend(
        [
            "## Integridade",
            "",
            "Cada evidência JSON inclui SHA-256 do conteúdo sanitizado. "
            "O hash detecta alterações acidentais; não é uma assinatura nem prova de origem.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(report: dict[str, Any]) -> str:
    counts: dict[str, int] = {}
    for finding in report.get("findings", []):
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    findings = []
    for finding in report.get("findings", []):
        sections = []
        for title, key in (
            ("Descrição", "description"),
            ("Justificativa técnica", "reasoning"),
            ("Impacto", "impact"),
            ("Correção recomendada", "recommendation"),
            ("Verificação", "verification"),
            ("Limitações", "limitations"),
        ):
            sections.append(
                f"<h3>{title}</h3><p>{_escape(finding.get(key) or 'Não documentado.')}</p>"
            )
        steps = "".join(
            f"<li>{_escape(step)}</li>" for step in finding.get("reproduction_steps", [])
        )
        linked = json.dumps(finding.get("evidence", []), ensure_ascii=False, indent=2)
        refs = "".join(f"<li>{_escape(ref)}</li>" for ref in finding.get("references", []))
        risk = finding.get("risk_score") or {}
        findings.append(
            f"<article><span class='badge'>{_escape(finding['severity'])}</span>"
            f"<h2>{_escape(finding['title'])}</h2>"
            f"<p class='muted'>{_escape(finding['finding_id'])} · "
            f"{_escape(finding.get('classification'))} · "
            f"Confiança {round(finding['confidence'] * 100)}% · "
            f"Prioridade {_escape(finding.get('priority', 0))}/100</p>"
            f"<p>Ativo: {_escape(finding['asset'])} · "
            f"CWE: {_escape(finding.get('cwe') or 'não atribuído')}</p>"
            + "".join(sections)
            + f"<h3>Reprodução</h3><ol>{steps}</ol>"
            + f"<h3>Fórmula de risco (não é CVSS)</h3><p>{_escape(risk.get('reasoning', ''))}</p>"
            + "<details><summary>Evidências rastreáveis</summary>"
            + f"<pre>{_escape(linked)}</pre></details>"
            + f"<h3>Referências</h3><ul>{refs}</ul></article>"
        )
    checks = "".join(
        f"<tr><td>{_escape(item.get('module'))}</td><td>{_escape(item.get('target'))}</td>"
        f"<td>{_escape(item.get('status'))}</td><td>{_escape(item.get('reason', ''))}</td></tr>"
        for item in report.get("checks", [])
    )
    limitations = "".join(f"<li>{_escape(item)}</li>" for item in report.get("limitations", []))
    scope = json.dumps(report.get("engagement", {}), ensure_ascii=False, indent=2)
    overview = _escape(json.dumps(counts, ensure_ascii=False))
    all_evidence = _escape(json.dumps(report.get("evidence", []), ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Solomon — Relatório técnico</title><style>
body{{font:16px/1.6 Segoe UI,Arial,sans-serif;background:#101827;color:#e6edf7;margin:0}}
main{{max-width:1100px;margin:auto;padding:36px 24px}}h1{{font-size:32px;color:#70e0c3}}
h2{{font-size:22px}}h3{{font-size:17px;color:#70e0c3;margin-bottom:6px}}
article,section{{background:#1a2639;border:1px solid #33445f;border-radius:12px;padding:24px;
margin:20px 0}}.muted{{color:#b1bed2}}
.badge{{background:#33445f;border-radius:6px;padding:4px 10px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;padding:16px;font-size:13px}}
table{{width:100%;border-collapse:collapse}}
td,th{{padding:9px;text-align:left;border-bottom:1px solid
#33445f;overflow-wrap:anywhere}}p,li{{overflow-wrap:anywhere}}
@media print{{body{{background:white;color:#111}}
section,article{{background:white;border-color:#bbb}}
h1,h3{{color:#174c40}}pre{{background:#eee}}article{{break-inside:avoid}}}}
</style></head><body><main><h1>SOLOMON</h1><p>Relatório técnico de segurança</p>
<section><h2>Resumo da avaliação</h2>
<p>Versão Solomon: {_escape(report.get("solomon_version", ""))}</p>
<p>Sessão: {_escape(report.get("session_id"))} · {_escape(report.get("session_status"))}</p>
<p>Alvo: {_escape(report.get("target"))}</p>
<p>Início UTC: {_escape(report.get("started_at"))}<br>Fim UTC: {_escape(report.get("ended_at"))}</p>
<p>Nota das verificações coletadas: {_escape(_health_label(report))}<br>
Operações contabilizadas: {_escape(report.get("requests_used", 0))}</p>
<p>Achados: {overview}</p><p class="muted">A nota não certifica a segurança geral do alvo.
Observações e candidatos precisam de validação contextual para bug bounty.</p></section>
<section><h2>Escopo e autorização</h2><pre>{_escape(scope)}</pre></section>
<section><h2>Cobertura e limitações</h2><ul>{limitations}</ul>
<table><thead><tr><th>Módulo</th><th>Alvo</th><th>Estado</th><th>Detalhe</th></tr></thead>
<tbody>{checks}</tbody></table></section>
{
        "".join(findings)
        or "<section>Nenhum achado gerado. Isso não comprova ausência de "
        "vulnerabilidades.</section>"
    }
<section><h2>Índice de evidências</h2><details><summary>Dados sanitizados e hashes SHA-256</summary>
<pre>{
        all_evidence
    }</pre></details><p>Hashes detectam alterações; não são assinaturas nem prova de origem.
Nenhum recurso externo é carregado por este relatório.</p></section>
</main></body></html>
"""


def save_reports(result: dict[str, Any], output: Path) -> dict[str, Path]:
    report = prepare_report(result)
    session = str(report.get("session_id", "report"))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", session):
        raise ValueError("ID de sessão inválido para exportação.")
    directory = output / session
    directory.mkdir(parents=True, exist_ok=True)
    paths = {kind: directory / f"report.{kind}" for kind in ("json", "html", "md")}
    payloads = {
        "json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        "html": render_html(report),
        "md": render_markdown(report),
    }
    for kind, path in paths.items():
        path.write_text(payloads[kind], encoding="utf-8")
    return paths
