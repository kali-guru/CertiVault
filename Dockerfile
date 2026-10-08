FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CERTIVAULT_INSTANCE=/data \
    HOME=/tmp

WORKDIR /app
COPY requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt \
    && groupadd --gid 10001 certivault \
    && useradd --uid 10001 --gid certivault --no-create-home certivault \
    && mkdir /data \
    && chown certivault:certivault /data \
    && chmod 700 /data

COPY app ./app
COPY migrations ./migrations
COPY deployment ./deployment
COPY run.py ./
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-m", "deployment.healthcheck"]
ENTRYPOINT ["python", "-m", "deployment.entrypoint"]
CMD ["gunicorn", "--config", "deployment/gunicorn.conf.py", "run:app"]
