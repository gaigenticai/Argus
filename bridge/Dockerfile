# Argus inference bridge — minimal python image.
#
# Used only when the operator picks the "Claude Code bridge" LLM option
# AND the host is Linux (so a Linux-arch ``claude`` binary can be
# mounted). On macOS this image isn't built; ``scripts/bridge_host.sh``
# runs ``bridge.py`` host-native instead. See bridge/bridge.py for the
# rationale.

FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY bridge.py /app/bridge.py

# CLAUDE_CLI_PATH must be set by docker-compose / the operator so the
# worker knows where to find the mounted claude binary. We deliberately
# do NOT bundle a copy of the CLI in the image — Anthropic's installer
# is per-user and licence-bound.
ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/bridge.py"]
