default: test

test: pre-commit

pre-commit:
	pre-commit run --all-files

install:
	pip install .

install-dev:
	pip install -e .

uninstall:
	pip uninstall -y ldapsearchad

publish:
	python3 setup.py check sdist upload
