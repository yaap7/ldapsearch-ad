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

clean:
	rm -fr dist/ ldapsearchad.egg-info/

build: clean
	python -m build
	twine check dist/*

publish-test: build
	twine upload -r testpypi dist/*

publish: build
	twine upload --skip-existing dist/*
