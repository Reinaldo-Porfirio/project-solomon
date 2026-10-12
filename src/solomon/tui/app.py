"""Interactive console. Opening the app never starts remote network tests."""

import json
from pathlib import Path
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

from solomon.analysis.engine import AnalysisEngine
from solomon.core.findings import Finding
from solomon.diagnostics.engine import DiagnosticsEngine
from solomon.pentest.engagement import load_engagement
from solomon.pentest.engine import PentestDiscoveryEngine, build_plan
from solomon.platform.factory import get_platform_detector
from solomon.reporting import save_reports


class SolomonConsole(App):
    TITLE = "Solomon — Segurança baseada em evidências"
    SUB_TITLE = "Windows | Pentest autorizado | Sem serviços pagos"
    CSS = """
    Screen { background: $surface; }
    #overview { padding: 1 2; }
    TabPane { padding: 1 2; }
    Input { margin-bottom: 1; }
    DataTable { height: 12; margin-bottom: 1; }
    #finding-detail { padding: 1 2; border: solid $primary; }
    #pentest-state { margin: 1 0; padding: 1; border: solid $primary; }
    #local-state { margin-bottom: 1; }
    Button { margin-right: 1; }
    """
    BINDINGS = [("q", "quit", "Sair"), ("r", "refresh_local", "Atualizar máquina")]

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.findings: dict[str, Finding] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent():
            with TabPane("Máquina", id="machine"):
                yield Static("Coleta local somente leitura.", id="local-state", markup=False)
                yield DataTable(id="diagnostics")
                yield Button("Atualizar diagnóstico", id="refresh-local")
            with TabPane("Auditoria", id="audit"):
                yield Static("Aguardando evidências locais.", id="health", markup=False)
                yield DataTable(id="local-findings")
                yield Static(
                    "Selecione um achado para ler os detalhes.", id="local-detail", markup=False
                )
            with TabPane("Pentest", id="pentest"):
                with VerticalScroll():
                    yield Static(
                        "Defina o arquivo de escopo e o alvo. Validar o plano não usa rede.\n"
                        "Crie o escopo pela CLI: solomon pentest init --help",
                        markup=False,
                    )
                    yield Label("Arquivo de escopo/autorização (JSON)")
                    yield Input(placeholder="Ex.: engagements/lab.json", id="engagement")
                    yield Label("Alvo exato: URL, domínio ou IP")
                    yield Input(placeholder="Ex.: http://127.0.0.1:8000/", id="target")
                    yield Label("Módulos (separados por vírgula)")
                    yield Input(value="HTTP,TLS,TECHNOLOGY", id="modules")
                    yield Checkbox("Testar CORS (requer active_testing no escopo)", id="cors")
                    yield Label("Pasta de relatórios")
                    yield Input(value="reports", id="output")
                    with Horizontal():
                        yield Button("Validar plano", id="plan")
                        yield Button("Executar coleta", id="scan", variant="primary")
                    yield Static(
                        "Nenhuma coleta remota iniciada.", id="pentest-state", markup=False
                    )
                    yield DataTable(id="remote-findings")
                    yield Static("Selecione um achado.", id="finding-detail", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#diagnostics", DataTable).add_columns(
            "Módulo", "Estado", "Evidências", "Detalhe"
        )
        for table_id in ("#local-findings", "#remote-findings"):
            table = self.query_one(table_id, DataTable)
            table.cursor_type = "row"
            table.add_columns("Gravidade", "ID", "Título", "Prioridade", "Confiança")
        self.collect_local()

    def action_refresh_local(self) -> None:
        self.collect_local()

    @work(thread=True, exclusive=True, group="local")
    def collect_local(self) -> None:
        try:
            detector = get_platform_detector()
            caps = detector.detect()
            results = DiagnosticsEngine(detector).run()
            evidence = [ev for result in results.values() for ev in result.evidence]
            analysis = AnalysisEngine(caps.platform).run(evidence)
            self.call_from_thread(self.show_local, caps, results, analysis)
        except Exception as exc:
            self.call_from_thread(
                self.query_one("#local-state", Static).update, f"Falha na coleta: {exc}"
            )

    def show_local(self, caps, results, analysis) -> None:
        self.query_one("#local-state", Static).update(
            f"{caps.platform}\nPrivilégio: {caps.privilege_level.value}\n"
            "Coleta somente leitura. Use a CLI audit para exportar o relatório completo."
        )
        table = self.query_one("#diagnostics", DataTable)
        table.clear()
        for name, result in results.items():
            table.add_row(
                name, result.status.value, str(len(result.evidence)), result.message or ""
            )
        self.query_one("#health", Static).update(
            f"Nota das verificações coletadas: {analysis.health.overall}/100. "
            "Coletores incompletos podem deixar lacunas."
        )
        self.fill_findings("#local-findings", analysis.findings)

    def fill_findings(self, table_id: str, findings: list[Finding]) -> None:
        table = self.query_one(table_id, DataTable)
        table.clear()
        for finding in findings:
            self.findings[finding.finding_id] = finding
            table.add_row(
                finding.severity.value,
                finding.finding_id,
                finding.title,
                str(finding.priority),
                f"{round(finding.confidence * 100)}%",
                key=finding.finding_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        finding = self.findings.get(str(event.row_key.value))
        if not finding:
            return
        detail = (
            f"{finding.title}\n{finding.finding_id} | {finding.severity.value}\n"
            f"Ativo: {finding.asset}\nClassificação: {finding.classification}\n\n"
            f"{finding.description}\n\nJustificativa: {finding.reasoning}\n\n"
            f"Impacto: {finding.impact}\n\nCorreção: {finding.recommendation}\n\n"
            f"Limitações: {finding.limitations}\n\n"
            f"Evidências: {', '.join(finding.evidence_ids)}"
        )
        target = "#local-detail" if event.data_table.id == "local-findings" else "#finding-detail"
        self.query_one(target, Static).update(detail)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh-local":
            self.collect_local()
        elif event.button.id in ("plan", "scan"):
            try:
                engagement = load_engagement(Path(self.query_one("#engagement", Input).value))
                target = self.query_one("#target", Input).value.strip()
                modules = [
                    value.strip().upper()
                    for value in self.query_one("#modules", Input).value.split(",")
                    if value.strip()
                ]
                if not modules:
                    raise ValueError("Escolha pelo menos um módulo.")
                if self.query_one("#cors", Checkbox).value and "CORS" not in modules:
                    modules.append("CORS")
                plan = build_plan(engagement, target, modules)
                if event.button.id == "plan":
                    self.query_one("#pentest-state", Static).update(
                        json.dumps(plan, ensure_ascii=False, indent=2)
                    )
                else:
                    if not any(item["decision"] == "ALLOWED" for item in plan["operations"]):
                        raise ValueError("Nenhuma operação autorizada. Revise o plano e o escopo.")
                    self.query_one("#scan", Button).disabled = True
                    self.query_one("#pentest-state", Static).update("Coleta em execução...")
                    self.run_remote(
                        engagement, target, modules, Path(self.query_one("#output", Input).value)
                    )
            except (OSError, ValueError) as exc:
                self.query_one("#pentest-state", Static).update(f"Erro: {exc}")

    @work(thread=True, exclusive=True, group="remote")
    def run_remote(self, engagement, target: str, modules: list[str], output: Path) -> None:
        try:
            result = PentestDiscoveryEngine(engagement).run(target, modules)
            paths = save_reports(result, output)
            self.call_from_thread(self.show_remote, result, paths)
        except Exception as exc:
            self.call_from_thread(self.query_one("#pentest-state", Static).update, f"Erro: {exc}")
        finally:
            self.call_from_thread(setattr, self.query_one("#scan", Button), "disabled", False)

    def show_remote(self, result, paths) -> None:
        self.fill_findings("#remote-findings", result["findings"])
        message = (
            f"{result['session_status']} | Evidências: {len(result['evidence'])} | "
            f"Achados: {len(result['findings'])}\n"
        )
        message += "\n".join(f"{module}: {status}" for module, status in result["status"].items())
        message += "\n\n" + "\n".join(
            f"{kind.upper()}: {path.resolve()}" for kind, path in paths.items()
        )
        self.query_one("#pentest-state", Static).update(message)


if __name__ == "__main__":
    SolomonConsole().run()
