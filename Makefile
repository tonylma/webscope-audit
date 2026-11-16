.PHONY: help install test backend-test frontend-build security compose-up compose-down clean

help:
	@echo "install         Install backend and frontend dependencies"
	@echo "test            Run backend tests"
	@echo "backend-test    Run pytest with coverage"
	@echo "frontend-build  Type-check and build the React frontend"
	@echo "security        Run Bandit and pip-audit"
	@echo "compose-up      Start the full Docker Compose stack"
	@echo "compose-down    Stop the stack"
	@echo "clean           Remove local caches and build outputs"

install:
	python -m pip install -r backend/requirements.txt
	cd frontend && npm install

test: backend-test frontend-build

backend-test:
	PYTHONPATH=backend pytest -q --cov=app --cov-report=term-missing

frontend-build:
	cd frontend && npm run build

security:
	bandit -r backend/app --severity-level high --confidence-level high
	pip-audit -r backend/requirements.txt
	cd frontend && npm audit --audit-level=high

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .coverage backend/.pytest_cache frontend/dist frontend/node_modules
