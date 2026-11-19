#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO"), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger(__name__)

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "https://grafana.antonio-code.duckdns.org")
ARGOCD_URL = os.environ.get("ARGOCD_URL", "https://argocd.antonio-code.duckdns.org")
DEDUP_TTL = int(os.environ.get("DEDUP_TTL_SECONDS", "120"))
# The apiserver batches events (400 by default); 10 MiB is far above that and stops memory abuse.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(10 * 1024 * 1024)))

INTERACTIVE_SUBRESOURCES = {
    "exec": ("HIGH", "Shell direto no container"),
    "attach": ("HIGH", "Terminal interativo"),
    "portforward": ("MEDIUM", "Port-forward ativo"),
    "proxy": ("MEDIUM", "Proxy para servico"),
}

SENSITIVE_WRITE_RESOURCES = {
    "clusterrolebindings": ("HIGH", "ClusterRoleBinding modificado"),
    "rolebindings": ("MEDIUM", "RoleBinding modificado"),
    "clusterroles": ("HIGH", "ClusterRole modificado"),
    "roles": ("MEDIUM", "Role modificado"),
    "serviceaccounts": ("MEDIUM", "ServiceAccount modificado"),
    "networkpolicies": ("MEDIUM", "NetworkPolicy modificada"),
    "nodes": ("HIGH", "Node modificado diretamente"),
}

SENSITIVE_READ_RESOURCES = {"secrets", "configmaps"}
SENSITIVE_NAMESPACES = {"kube-system", "monitoring", "argocd", "databases"}
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
NOISY_RESOURCES = {"events", "pods/status", "endpoints", "endpointslices"}
IGNORED_PREFIXES = ("system:serviceaccount:", "system:node:")
IGNORED_USERNAMES = {
    "system:apiserver",
    "system:kube-scheduler",
    "system:kube-controller-manager",
    "system:anonymous",
}

_dedup: dict[str, float] = {}


def ignore_user(user: dict) -> bool:
    username = user.get("username", "")
    return username in IGNORED_USERNAMES or any(
        username.startswith(prefix) for prefix in IGNORED_PREFIXES
    )


def is_duplicate(key: str) -> bool:
    now = time.monotonic()
    for cached_key in list(_dedup):
        if now - _dedup[cached_key] > DEDUP_TTL * 2:
            del _dedup[cached_key]

    if key in _dedup and now - _dedup[key] < DEDUP_TTL:
        return True

    _dedup[key] = now
    return False


def fmt_ts(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime(
            "%d/%m %H:%M:%S UTC"
        )
    except ValueError:
        return value or "-"


def classify(event: dict) -> tuple[str, str] | None:
    verb = event.get("verb", "")
    obj = event.get("objectRef", {})
    resource = obj.get("resource", "")
    subresource = obj.get("subresource", "")
    namespace = obj.get("namespace", "")

    if subresource in INTERACTIVE_SUBRESOURCES:
        return INTERACTIVE_SUBRESOURCES[subresource]

    if verb in WRITE_VERBS and resource in SENSITIVE_WRITE_RESOURCES:
        return SENSITIVE_WRITE_RESOURCES[resource]

    if (
        verb in {"get", "list"}
        and resource in SENSITIVE_READ_RESOURCES
        and namespace in SENSITIVE_NAMESPACES
    ):
        return ("HIGH", f"{resource} lido em namespace sensivel")

    resource_full = f"{resource}/{subresource}" if subresource else resource
    if verb in WRITE_VERBS and namespace in SENSITIVE_NAMESPACES and resource_full not in NOISY_RESOURCES:
        return ("MEDIUM", f"Escrita em namespace sensivel: {resource_full}")

    return None


def process_event(event: dict) -> bool:
    obj = event.get("objectRef", {})
    subresource = obj.get("subresource", "")
    stage = event.get("stage", "")

    if subresource in INTERACTIVE_SUBRESOURCES:
        if stage != "RequestReceived":
            return False
    elif stage != "ResponseComplete":
        return False

    if ignore_user(event.get("user", {})):
        return False

    classification = classify(event)
    if classification is None:
        return False

    severity, description = classification
    username = event.get("user", {}).get("username", "unknown")
    verb = event.get("verb", "")
    resource = obj.get("resource", "")
    namespace = obj.get("namespace", "")
    name = obj.get("name", "")
    source_ips = event.get("sourceIPs", [])
    resource_full = f"{resource}/{subresource}" if subresource else resource
    key = hashlib.md5(
        f"{username}:{verb}:{resource_full}:{namespace}:{name}".encode()
    ).hexdigest()

    if is_duplicate(key):
        return False

    source_ip = source_ips[0] if source_ips else "desconhecido"
    text = (
        f"[{severity}] KUBERNETES AUDIT ALERT\n"
        f"Usuario: {username}\n"
        f"Operacao: {description}\n"
        f"Acao: {verb} -> {resource_full}\n"
        f"Namespace: {namespace or 'cluster-wide'}\n"
        f"Recurso: {name or '-'}\n"
        f"IP origem: {source_ip}\n"
        f"Quando: {fmt_ts(event.get('requestReceivedTimestamp', ''))}\n"
        f"Grafana: {GRAFANA_URL}\n"
        f"ArgoCD: {ARGOCD_URL}"
    )
    if not send_telegram(text):
        # Not delivered: forget the key so the next identical event can alert again
        _dedup.pop(key, None)
        return False
    return True


def send_telegram(text: str) -> bool:
    """Returns True only when Telegram accepted the message."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        LOG.warning("Telegram env missing; notification skipped")
        return False

    payload = json.dumps(
        {"chat_id": TELEGRAM_CHAT, "text": text, "disable_web_page_preview": True}
    ).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            LOG.debug("Telegram response: %s", response.status)
            return True
    except urllib.error.HTTPError as exc:
        LOG.error("Telegram HTTP error: %s", exc.code)
    except OSError as exc:
        LOG.error("Telegram error: %s", exc)
    return False


class AuditHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        LOG.debug(fmt, *args)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.respond(200, {"status": "healthy"})
            return
        self.respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/audit":
            self.respond(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0:
            self.respond(400, {"error": "invalid content-length"})
            return
        if length > MAX_BODY_BYTES:
            self.respond(413, {"error": "payload too large"})
            return

        try:
            payload = json.loads(self.rfile.read(length))
        except ValueError:  # JSONDecodeError and UnicodeDecodeError
            self.respond(400, {"error": "invalid json"})
            return

        items = payload.get("items", []) if isinstance(payload, dict) else None
        if not isinstance(items, list):
            self.respond(400, {"error": "expected an EventList object with an items list"})
            return

        notified = 0
        for item in items:
            try:
                notified += int(process_event(item))
            except Exception:
                LOG.exception("failed to process audit event")

        self.respond(200, {"status": "ok", "items": len(items), "notified": notified})

    def respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), AuditHandler)
    LOG.info("audit-notifier listening on %d", port)
    server.serve_forever()


if __name__ == "__main__":
    main()
