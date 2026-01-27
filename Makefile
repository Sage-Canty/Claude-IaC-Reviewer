.PHONY: help install lint test review-bad review-good

help:
	@echo "Usage: make <target>"
	@echo "  install      Install dependencies"
	@echo "  lint         Run flake8 and black check"
	@echo "  test         Run unit tests"
	@echo "  review-bad   Review insecure example (needs ANTHROPIC_API_KEY)"
	@echo "  review-good  Review secure example"

install:
	pip install -r requirements.txt -r requirements-dev.txt

lint:
	flake8 src/ tests/ --max-line-length=100
	black --check src/ tests/

test:
	pytest tests/ -v

review-bad:
	python -m src.cli review --path examples/bad

review-good:
	python -m src.cli review --path examples/good
