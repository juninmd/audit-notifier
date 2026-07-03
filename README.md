# audit-notifier

Kubernetes audit webhook that turns risky cluster actions into Telegram alerts.

Daily use:
- alerts on `kubectl exec`, `attach`, `port-forward`, and `proxy`;
- alerts on RBAC/service account/network policy writes;
- alerts on reads of Secrets and ConfigMaps in sensitive namespaces;
- deduplicates repeated events to keep Telegram readable.

## Runtime

Environment:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `GRAFANA_URL`
- `ARGOCD_URL`
- `DEDUP_TTL_SECONDS`
- `PORT`

Endpoints:
- `GET /health`
- `POST /audit`

The app has no runtime dependencies beyond Python stdlib.
