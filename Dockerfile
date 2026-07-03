FROM python:3.12-alpine

WORKDIR /app
COPY src/audit_notifier.py /app/audit_notifier.py

ENV PORT=8080
EXPOSE 8080

CMD ["python", "/app/audit_notifier.py"]
