PY ?= python

.PHONY: help install test test-postgres eval seed-sql agent up down logs lint

help:
	@echo "install        install the package + dev deps (editable)"
	@echo "test           run the offline test suite (no docker)"
	@echo "test-postgres  run the full suite incl. Postgres RLS isolation (needs DSNs)"
	@echo "eval           run the reliability eval -> eval/report.md + chart"
	@echo "seed-sql       regenerate db/03_seed.sql from the Python seed"
	@echo "agent REQ=cr-002   run the agent in-process for one request"
	@echo "up / down      docker compose up --build / down -v"
	@echo "logs           tail compose logs"

install:
	$(PY) -m pip install -e ".[dev,eval]"

test:
	$(PY) -m pytest -q

test-postgres:
	$(PY) -m pytest -q -m "postgres or not postgres"

eval:
	$(PY) -m eval.run_eval --n 120 --seed 1234

seed-sql:
	$(PY) db/generate_seed_sql.py

REQ ?= cr-002
agent:
	$(PY) -m change_gate.agent.main $(REQ)

up:
	docker compose up --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=100
