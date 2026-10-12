"""Free local demonstration. The server binds only to IPv4 loopback."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from solomon.pentest.engagement import new_engagement, save_engagement
from solomon.pentest.engine import PentestDiscoveryEngine


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:
        content = (
            "<!doctype html><html lang='pt-BR'><meta charset='utf-8'>"
            "<title>Solomon Lab</title><h1>Laboratório local Solomon</h1>"
            "<p>Resposta fictícia para testar coleta e documentação de falhas.</p></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Set-Cookie", "sessionid=demo-value; Path=/")
        self.send_header("Set-Cookie", "analytics=demo-analytics; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_demo(output: Path) -> dict[str, Any]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    server.daemon_threads = True
    port = server.server_port
    target = f"http://127.0.0.1:{port}/"
    engagement = new_engagement(
        "Laboratório local Solomon",
        ["127.0.0.1"],
        [],
        True,
        "Servidor de demonstração iniciado pelo Solomon em loopback",
        True,
    )
    if engagement.scope is None:
        raise ValueError("Escopo de laboratório ausente.")
    engagement.scope.policy.allowed_ports = [port]
    engagement.scope.policy.max_requests = 12
    engagement.scope.policy.requests_per_second = 10
    output.mkdir(parents=True, exist_ok=True)
    save_engagement(engagement, output / f"{engagement.engagement_id}.json")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return PentestDiscoveryEngine(engagement).run(
            target, ["HTTP", "TECHNOLOGY", "PORTS", "CORS"], [port]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
