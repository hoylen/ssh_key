# Makefile for ssh_key

.PHONY: help format test coverage doc clean

help:
	@echo "Make targets:"
	@echo "  format    format Dart code"
	@echo "  test      run tests (unit tests and example tests)"
	@echo "  coverage  run coverage on tests *"
	@echo "  doc       generate documentation *"
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
	dart format lib test examples

#----------------------------------------------------------------
# Testing

test: test-unit test-example

test-unit:
	dart run test

test-example:
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
	dart doc

doc-open: doc
	open doc/api/index.html

#----------------------------------------------------------------

clean:
	@rm -rf "example/output" coverage doc

#EOF
