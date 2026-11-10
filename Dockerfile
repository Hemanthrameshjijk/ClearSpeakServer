FROM python:3.11-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY licsrv ./licsrv
RUN useradd -r -u 10001 licsrv && mkdir /data && chown licsrv /data
USER licsrv
ENV LICSRV_SIGNING_KEY_FILE=/data/signing.key
EXPOSE 8000
# TLS is terminated by the reverse proxy in front of this container.
CMD ["uvicorn", "licsrv.wsgi:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
