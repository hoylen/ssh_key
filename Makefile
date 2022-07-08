# Makefile

DIST_DIR=dist

.PHONY: test clean help dartfmt dartdoc

help:
	@echo "Make targets:"
	@echo "  format  reformat code"
	@echo "  doc     generate Dart documentation"
	@echo "  test    run unit tests and example tests"
	@echo "  clean   delete generated files"

# ssh-keygen -t rsa -b 2048 -f rsa2048
# ssh-keygen -t rsa -b 4096 -f rsa4096
# ssh-keygen  -e -m rfc4716 -f rsa2048.pub > rsa2048.rfc4716
# ssh-keygen  -e -m pkcs8 -f rsa2048.pub > rsa2048.pkcs8
# ssh-keygen  -e -m pem -f rsa2048.pub > rsa2048.pem

#----------------------------------------------------------------
# Development targets

format:
	@dart format lib test examples

#----------------------------------------------------------------
# Documentation

# Dart source code documentation

dartdoc: doc

doc:
	@dart doc --output-dir "${DIST_DIR}/doc/code" `pwd`
	@echo "View Dart documentation by opening: ${DIST_DIR}/doc/code/index.html"

#----------------------------------------------------------------
# Testing

test:
	@dart run test
	@echo
	@example/tests-run.sh all

clean:
	@rm -rf "${DIST_DIR}"
	@rm -rf "example/output"
