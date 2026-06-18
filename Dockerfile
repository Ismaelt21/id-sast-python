FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY api ./api
COPY cli ./cli
COPY config ./config
COPY core ./core
COPY database ./database
COPY engine ./engine
COPY reports ./reports
COPY service ./service
RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["id-sast-python-api"]
