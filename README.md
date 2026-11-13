# audit-notifier

Kubernetes audit webhook that turns risky cluster actions into deduplicated Telegram alerts.

`kubectl exec` into a pod, a RoleBinding edit, a Secret read in `kube-system` — all of it lands in the audit log and nobody reads it. This service subscribes to that stream through the native [audit webhook](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) backend, classifies each event by severity, throws away the noise and the repeats, and pushes what is left to a Telegram chat.

It is one Python file (189 lines), with no runtime dependencies beyond the standard library, a 12-line Dockerfile and four CI workflows.

## What it does

| Signal | Severity | Alert text |
|---|---|---|
| `pods/exec` | HIGH | Shell direto no container |
| `pods/attach` | HIGH | Terminal interativo |
| `pods/portforward` | MEDIUM | Port-forward ativo |
| `pods/proxy` | MEDIUM | Proxy para servico |
| `clusterrolebindings` write | HIGH | ClusterRoleBinding modificado |
| `clusterroles` write | HIGH | ClusterRole modificado |
| `nodes` write | HIGH | Node modificado diretamente |
| `rolebindings` / `roles` write | MEDIUM | RoleBinding / Role modificado |
| `serviceaccounts` write | MEDIUM | ServiceAccount modificado |
| `networkpolicies` write | MEDIUM | NetworkPolicy modificada |
| `secrets` or `configmaps` read | HIGH | `<resource>` lido em namespace sensivel |
| any other write in a sensitive namespace | MEDIUM | Escrita em namespace sensivel: `<resource>` |

"Write" means `create`, `update`, `patch`, `delete` or `deletecollection`. Sensitive namespaces are `kube-system`, `monitoring`, `argocd` and `databases`. The last rule is a catch-all and deliberately skips the noisy resources `events`, `pods/status`, `endpoints` and `endpointslices`.

The classification order matters: interactive subresources win over everything, then sensitive writes, then reads of Secrets/ConfigMaps, then the catch-all. A first match returns, so one event produces at most one alert.

## Noise control

Two filters run before anything is sent.

**Ignored identities.** The service drops events from `system:apiserver`, `system:kube-scheduler`, `system:kube-controller-manager`, `system:anonymous`, and from any username starting with `system:serviceaccount:` or `system:node:`. Its own workflows and controllers will not page you.

**Deduplication.** The key is an MD5 of `username:verb:resource/subresource:namespace:name`, so the same person repeating the same action on the same object collapses into one alert. A key is remembered for `DEDUP_TTL_SECONDS` (default `120`), and entries older than twice the TTL are pruned on every check.

Two consequences worth knowing up front: the cache lives in process memory, so a restart forgets everything, and two replicas deduplicate independently — each one will send its own alert.

## Stage handling

The webhook can deliver the same audit event at several stages. The handler keeps:

- interactive subresources (`exec`, `attach`, `portforward`, `proxy`) only at `RequestReceived` — the alert fires when the shell opens, not when it closes;
- everything else only at `ResponseComplete` — so failed or forbidden attempts do not spam the chat.

Events arriving at any other stage are dropped silently.

## Quick start

The repo targets Python 3.12: the Dockerfile uses `python:3.12-alpine` and `build.yml` sets up 3.12.

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHAT_ID="-1001234567890"
python3 src/audit_notifier.py
# 2026-11-12 12:00:00,000 INFO audit-notifier listening on 8080
```

The service starts an HTTP server on `0.0.0.0:$PORT` (default `8080`) and waits. A request to `/health` is enough to confirm it is up:

```bash
curl -s localhost:8080/health
# {"status": "healthy"}
```

### Docker

```bash
docker build -t audit-notifier .
docker run --rm -p 8080:8080 \
  -e TELEGRAM_BOT_TOKEN="123456:ABC..." \
  -e TELEGRAM_CHAT_ID="-1001234567890" \
  audit-notifier
```

The image copies only `src/audit_notifier.py`, creates an unprivileged `appuser` (uid 1000), sets `PORT=8080`, exposes it and runs the script. No `pip install`, no build stage, no shell in the entrypoint.

`build.yml` publishes the image to GHCR on every push to `main`/`master`, tagged `latest` and with the commit SHA:

```
ghcr.io/juninmd/audit-notifier:latest
ghcr.io/juninmd/audit-notifier:<git-sha>
```

`docker.yml` runs in parallel through the shared `reusable-docker-build.yml` workflow from `juninmd/base-actions` and pushes the same image name. If you pull from GHCR and the package is private, authenticate first with `docker login ghcr.io` using a token that has `read:packages`.

## Endpoints

Paths are matched exactly — `/audit/` or `/audit?x=1` return `404`.

### `GET /health`

Always `200`, no body parsing, no dependency checks:

```json
{"status": "healthy"}
```

### `POST /audit`

The body is the standard `EventList` the kube-apiserver posts, and only `items` is read:

```json
{
  "kind": "EventList",
  "apiVersion": "audit.k8s.io/v1",
  "items": [
    {
      "stage": "RequestReceived",
      "verb": "create",
      "user": {"username": "junin"},
      "objectRef": {
        "resource": "pods",
        "subresource": "exec",
        "namespace": "apps",
        "name": "api-7d9f8c6b5-x2k4m"
      },
      "sourceIPs": ["10.0.4.18"],
      "requestReceivedTimestamp": "2026-11-12T12:04:31.512Z"
    }
  ]
}
```

Response:

```json
{"status": "ok", "items": 1, "notified": 1}
```

| Status | When |
|---|---|
| `200` | body parsed; `items` may be `0` and `notified` may be `0` |
| `400` | body is not valid JSON (`{"error": "invalid json"}`) |
| `404` | any other path (`{"error": "not found"}`) |

A malformed event inside `items` is logged and skipped; it does not fail the batch. Telegram failures are logged as well and do **not** change the `200` — a failed send is not retried.

## Example alert

For the event above, the Telegram message is:

```text
[HIGH] KUBERNETES AUDIT ALERT
Usuario: junin
Operacao: Shell direto no container
Acao: create -> pods/exec
Namespace: apps
Recurso: api-7d9f8c6b5-x2k4m
IP origem: 10.0.4.18
Quando: 12/11 12:04:31 UTC
Grafana: https://grafana.antonio-code.duckdns.org
ArgoCD: https://argocd.antonio-code.duckdns.org
```

Namespace `cluster-wide` and resource `-` are the fallbacks when the event has no namespace or no object name. `IP origem` becomes `desconhecido` when `sourceIPs` is empty. Messages are sent with `disable_web_page_preview` and no `parse_mode` — plain text, so no Markdown escaping to get wrong.

## Configuration

All configuration is environment variables, read once at import time.

| Variable | Default | Purpose |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | empty | Bot token; without it, alerts are logged as `Telegram env missing; notification skipped` |
| `TELEGRAM_CHAT_ID` | empty | Target chat/channel id |
| `GRAFANA_URL` | `https://grafana.antonio-code.duckdns.org` | Link printed in every alert |
| `ARGOCD_URL` | `https://argocd.antonio-code.duckdns.org` | Link printed in every alert |
| `DEDUP_TTL_SECONDS` | `120` | How long a repeated event stays suppressed |
| `PORT` | `8080` | Listen port |
| `LOG_LEVEL` | `INFO` | Standard `logging` level name |

`TELEGRAM_CHAT_ID` is a single id, not a list. To fan out to several chats, run several instances or point the bot at a group.

## Wiring it to the API server

The webhook config file is a kubeconfig whose `server` points at this service. Example:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: audit-notifier
    cluster:
      server: http://audit-notifier.audit.svc:8080/audit
contexts:
  - name: audit-notifier
    context:
      cluster: audit-notifier
      user: audit-notifier
current-context: audit-notifier
users:
  - name: audit-notifier
    user: {}
```

Then start the API server with `--audit-webhook-config-file` pointing at that file, plus `--audit-policy-file` describing which resources and stages you want collected. The policy has to include both `RequestReceived` and `ResponseComplete` for the rules above to fire — a policy that only emits `Metadata` at one stage will produce alerts for some rules and silence for others.

Practical notes for the deployment: the `server` above is plain HTTP, so keep the service on a cluster-internal address; `/audit` has no authentication, no token check and no IP allowlist. Exposing it to the internet means anyone can post fake alerts to your chat.

## Tests

```bash
python -m unittest discover -s tests
```

`tests/test_audit_notifier.py` imports the module by path (no packaging step) and covers the pieces that are easy to get wrong: service accounts are ignored, `exec` classifies as HIGH, `pods/status` in a sensitive namespace is treated as noise, a plain pod `delete` in `kube-system` still alerts, and the same event twice produces exactly one `send_telegram` call.

`build.yml` runs that same command before building the image, so a push that breaks classification fails before anything is published to GHCR.

## CI and workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `build.yml` | push to `main`/`master`, manual | `python -m unittest discover -s tests`, then build and push `ghcr.io/juninmd/audit-notifier` (`latest` + SHA) |
| `docker.yml` | push to `main`, manual | Reusable `reusable-docker-build.yml` from `juninmd/base-actions` |
| `validate.yml` | PR and push to `main` | Reusable `reusable-validate.yml` from `juninmd/base-actions` |
| `security.yml` | push to `main`, weekly, manual | Reusable `reusable-security-scan.yml` from `juninmd/base-actions` |

Both `build.yml` and `docker.yml` publish to the same image name on a push to `main`, from two separate builds. `build.yml` writes `latest` and the commit SHA itself; the tags written by the reusable workflow in `docker.yml` are defined in `juninmd/base-actions`, not here.

## Design notes

```text
src/audit_notifier.py    # HTTP server, classifier, dedup, Telegram client
tests/                   # unittest suite, imports the module by path
Dockerfile               # python:3.12-alpine, non-root, no dependencies
.github/workflows/       # build (test + GHCR), docker, validate, security
```

- **No dependencies.** `http.server`, `urllib.request`, `hashlib`, `json`, `logging`. That is the whole stack. No `requirements.txt`, no virtualenv, no supply chain to audit.
- **One file.** Classification tables are module-level dicts; adding a resource means adding a line to `SENSITIVE_WRITE_RESOURCES`.
- **Single-threaded by design.** `HTTPServer`, not `ThreadingHTTPServer`: one audit batch is handled at a time, and each alert blocks on a Telegram call with a 10 s timeout.

## Limitations

- **The request blocks on Telegram.** With a batch of several alerts and a slow bot API, the webhook response can take seconds. The API server's webhook timeout and `failurePolicy` decide what happens then — audit events may be dropped, and this service does not notice or retry.
- **No queue, no persistence.** Restart it and in-flight alerts and the dedup cache are gone. Nothing is written to disk; there is no history beyond what Telegram keeps.
- **Dedup is per process and per key.** Same user running `exec` on two different pods is two alerts (the pod name is part of the key), which is intentional. The same user reconnecting to the same pod within the TTL is one alert, which may hide a second session.
- **Classification is a fixed allowlist.** Resources outside the tables are only caught by the sensitive-namespace catch-all, and an `exec` in a non-sensitive namespace is still HIGH — the rules do not consider namespace for interactive access.
- **No authentication on `/audit`.** Any workload that can reach the port can forge an alert.
- **Telegram only.** No Slack, no webhook fan-out, no per-severity routing — a HIGH and a MEDIUM land in the same chat with the same formatting.
- **Severity is a label, not a metric.** Nothing is exported for Prometheus, and `/health` does not check Telegram connectivity.

## License

No license file is present in this repository.
