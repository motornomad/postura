# Contributing to POSTURA

## Development setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]" --no-cache-dir
```

## Running tests

```bash
# All offline tests (no Neo4j/Redis needed)
PYTHONPATH=. .venv/bin/pytest tests/ -v

# Specific suites
PYTHONPATH=. .venv/bin/pytest tests/test_ingest/ tests/test_reasoning/ tests/test_evaluation/ -v

# With Neo4j running (Docker):
docker compose up -d neo4j
PYTHONPATH=. .venv/bin/pytest tests/test_graph/ -v
```

## Code style

```bash
.venv/bin/ruff check src/ evaluation/ --fix
.venv/bin/mypy src/postura --ignore-missing-imports
```

## Project structure

```
src/postura/
  api/          FastAPI app and routes
  delivery/     GitHub integration and posture history
  graph/        Neo4j builder, updater, queries
  ingest/       AST parser, SAST runner, endpoint extractor
  knowledge/    CWE/CVE/OWASP knowledge base
  models/       Pydantic data models
  reasoning/    LangGraph agent, tools, severity scoring
  tasks/        Celery tasks
  webhook/      GitHub webhook receiver and event router
evaluation/     Offline evaluation scripts and ground truth
tests/          Unit and integration tests
```

## Key invariants

- `parse_file()` returns a **4-tuple**: `(nodes, edges, events, imported_packages)`
- tree-sitter uses **byte offsets** — slice `source_bytes`, not decoded str
- Python 3.11: no backslashes inside f-string `{}` expressions
- All Neo4j writes use `run_write()` from `graph/connection.py`
- All LLM calls use `POSTURA_ANTHROPIC_API_KEY` (never hardcode)

## Adding a new evaluation metric

1. Add the metric to `evaluation/ground_truth.py` if it requires GT data
2. Implement in `evaluation/baseline_static.py` (static) or `evaluation/postura_eval.py` (POSTURA)
3. Add the column to `evaluation/report.py`
4. Write tests in `tests/test_evaluation/`

## Reporting bugs

Open an issue with:
- POSTURA version / git SHA
- Python version
- Neo4j version
- Minimal reproduction steps
- Expected vs actual behavior
