# AGENTS.md

audit-notifier: a Kubernetes audit webhook that turns risky cluster actions into deduplicated Telegram alerts. It is one Python file with only the standard library.

## Stack

- Python 3.12 (CI and Docker), standard library only. Do not add runtime dependencies
- Docker: `python:3.12-alpine`, runs as a non-root user (uid 1000)

## Commands

- Test: `python -m unittest discover -s tests` (the CI command)
- Run locally: `PORT=8080 python src/audit_notifier.py`
- Docker build: `docker build -t audit-notifier .`

## Structure

- `src/audit_notifier.py`: the whole service (classification, dedup, Telegram delivery, HTTP handler)
- `tests/`: `test_audit_notifier.py` (unit) and `test_http.py` (HTTP behavior)
- `Dockerfile`: copies only `src/audit_notifier.py`. Adding a file means updating the Dockerfile
- `docs/readme/`: README images
- `.github/workflows/`: `build.yml` (tests and image build), `docker.yml`, `validate.yml`, `security.yml` (reusable from `juninmd/base-actions`)

## Conventions

- Keep the single-file design unless the owner asks otherwise.
- Classification order matters: interactive subresources first, then sensitive writes, then Secret/ConfigMap reads, then the catch-all. Keep a first match returning.
- Every new rule needs a unit test in `tests/`.

## Gotchas

- Secrets come from the environment: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Never print or log them.
- Other variables: `GRAFANA_URL`, `ARGOCD_URL`, `DEDUP_TTL_SECONDS` (default 120), `MAX_BODY_BYTES`, `LOG_LEVEL`, `PORT` (default 8080).
- The service ignores events from system identities (`system:apiserver`, `system:kube-*`, `system:serviceaccount:*`, `system:node:*`). Changing that list changes what pages people.
- Do not commit `.env`.

<!-- base-actions-main-policy -->
## GitHub Actions — padrão obrigatório (@main)

- Referencie as actions internas sempre pelo branch, nunca por SHA:
  - `uses: juninmd/base-actions/<action>@main`
  - `uses: juninmd/base-actions/.github/workflows/<arquivo>.yml@main`
- Não fixe `@<sha>` em `juninmd/base-actions`: a atualização é centralizada no
  `main` e passa a valer no próximo run.
- PRs cujos checks não iniciam por billing/spending limit são mesclados pelo bot central
  `juninmd/base-actions/.github/workflows/auto-merge-billing-blocked.yml`.
  Para impedir o merge automático de um PR, aplique a label `do-not-merge`.
