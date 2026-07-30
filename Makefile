.PHONY: install install-dev lint format test clean docker-build docker-run pre-commit

# Install production dependencies
install:
	pip install -e .

# Install dev dependencies
install-dev: install
	pip install -r requirements-dev.txt

# Lint with Ruff
lint:
	ruff check src/ tests/

# Format with Black
format:
	black src/ tests/

# Run tests
test:
	python -m pytest tests/ -v --tb=short --cov=src/netscan

# Run tests with coverage report
test-cov:
	python -m pytest tests/ -v --tb=short --cov=src/netscan --cov-report=html:coverage_html --cov-report=term-missing

# Clean up cache and build artifacts
clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache
	rm -rf coverage_html htmlcov
	rm -rf *.egg-info dist build
	rm -rf logs/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

# Pre-commit hooks
pre-commit:
	pre-commit install

pre-commit-run:
	pre-commit run --all-files

# Docker
docker-build:
	docker build -t netscan .

docker-run:
	docker run --rm -it netscan $(TARGET)

# Run a scan directly
scan:
	python -m netscan -t $(TARGET) -p $(PORTS)
