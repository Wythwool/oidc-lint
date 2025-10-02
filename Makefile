PY?=python3
install:
	$(PY) -m pip install .
lint:
	$(PY) -m pip install ruff && ruff check oidc_lint
