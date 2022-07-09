# Makefile

.PHONY: help format test coverage doc clean

help:
	@echo "Make targets:"
	@echo "  format    reformat code"
	@echo "  test      run unit tests and example tests"
	@echo "  coverage  run coverage on unit tests *"
	@echo "  doc       generate Dart documentation *"
	@echo "  clean     delete generated files"
	@echo
	@echo '* "coverage-open" and "doc-open" to run and then open the HTML'

# ssh-keygen -t rsa -b 2048 -f rsa2048
# ssh-keygen -t rsa -b 4096 -f rsa4096
# ssh-keygen  -e -m rfc4716 -f rsa2048.pub > rsa2048.rfc4716
# ssh-keygen  -e -m pkcs8 -f rsa2048.pub > rsa2048.pkcs8
# ssh-keygen  -e -m pem -f rsa2048.pub > rsa2048.pem

#----------------------------------------------------------------
# Development

format:
	@dart format lib test examples

#----------------------------------------------------------------
# Testing

test: unit-tests example-test

unit-tests:
	@dart run test

example-test:
	@example/tests-run.sh all

# Coverage tests require "lcov"

coverage:
	@if which genhtml >/dev/null; then \
	  dart run coverage:test_with_coverage && \
	  genhtml coverage/lcov.info -o coverage/html || \
	  exit 1 ; \
	else \
	  echo 'coverage: genhtml not found: please install "lcov"' ; \
	  echo '          on macOS install "lcov" with "brew install lcov"' ; \
	  exit 2 ; \
	fi

coverage-open: coverage
	open coverage/html/index.html

#----------------------------------------------------------------
# Documentation

doc:
	@dart doc --output-dir "doc" `pwd`

doc-open: doc
	open doc/index.html

#----------------------------------------------------------------

clean:
	@rm -rf "example/output" coverage doc
