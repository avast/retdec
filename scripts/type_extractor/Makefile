#
# Makefile for the type extractor.
#

.PHONY: clean lint tests tests-coverage

help:
	@echo "Use \`make <target>', where <target> is one of"
	@echo "  clean          -> clean all the generated files"
	@echo "  lint           -> check code style with flake8"
	@echo "  tests          -> run tests"
	@echo "  tests-coverage -> obtain test coverage"

clean:
	@rm -rf coverage
	@find . -name '__pycache__' -exec rm -rf {} +
	@find . -name '*.py[co]' -exec rm -f {} +

lint:
	@flake8 \
		--max-line-length=100 \
		type_extractor tests *.py

tests:
	@nosetests tests

tests-coverage:
	@nosetests tests --with-coverage \
		--cover-package type_extractor \
		--cover-erase \
		--cover-html \
		--cover-html-dir coverage
